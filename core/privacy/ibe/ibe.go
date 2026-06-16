// Copyright 2024 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// Package ibe implements threshold identity-based encryption (Boneh-Franklin) over
// the bn256 pairing curve, with the keyper committee as the private-key generator
// and the epoch as the identity. It gives the encrypted mempool a cryptographic
// per-epoch decryption trigger: a transaction encrypted for epoch E is
// undecryptable until a threshold of keypers release that epoch's key, and the
// released key for one epoch is useless for any other.
//
// This is the property the threshold-ElGamal scheme could not provide (its
// decryption shares do not bind to an epoch, so a keyper could only gate release
// operationally). Here the epoch key SK_E = s·H(E) simply does not exist until the
// committee produces it, so early decryption is cryptographically impossible.
//
// Scheme (master secret s held by the committee via DKG; mpk = s·G2):
//
//	identity      Q_E = HashToG1(epoch)              (RFC 9380, unknown discrete log)
//	epoch key     SK_E = s·Q_E ∈ G1                  (released by the committee)
//	per-keyper    σ_i = s_i·Q_E ∈ G1                 (combined via Lagrange to SK_E)
//	encrypt       U = r·G2 ; key = KDF(e(Q_E, mpk)^r)
//	decrypt       key = KDF(e(SK_E, U))              (= e(Q_E, G2)^{r·s})
//
// The committee shares (s_i) and verification keys (V_i = s_i·G2) are exactly those
// produced by core/privacy/keyper's DKG, so the same committee backs this scheme.
package ibe

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/ethereum/go-ethereum/core/privacy/threshold"
	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
)

// ibeDST is the domain-separation tag for hashing epochs to G1 (RFC 9380).
var ibeDST = []byte("ETHEREUM-PRIVACY-KEYPER-IBE-BN254-EPOCH-V1")

var order = bn256.Order

var (
	errParams    = errors.New("ibe: invalid parameters")
	errTooFew    = errors.New("ibe: not enough epoch-key shares")
	errDuplicate = errors.New("ibe: duplicate share index")
	errMalformed = errors.New("ibe: malformed ciphertext")
	errDecrypt   = errors.New("ibe: decryption failed")
)

// MasterPublicKey is the committee key mpk = s·G2 that transactions are encrypted
// to (together with an epoch).
type MasterPublicKey struct {
	Point *bn256.G2
}

// EpochKeyShare is one keyper's contribution to an epoch key: σ_i = s_i·Q_E.
type EpochKeyShare struct {
	Index uint32
	Sigma *bn256.G1
}

// EpochKey is the combined committee key SK_E = s·Q_E that decrypts every
// transaction encrypted for epoch E.
type EpochKey struct {
	Epoch uint64
	SK    *bn256.G1
}

// Ciphertext is an IBE-encrypted message bound to an epoch (hybrid with AES-GCM).
type Ciphertext struct {
	Epoch   uint64
	U       *bn256.G2 // r·G2
	Nonce   []byte
	Payload []byte
}

func g2Generator() *bn256.G2 { return new(bn256.G2).ScalarBaseMult(big.NewInt(1)) }

// hashEpochToG1 maps an epoch to a G1 point with unknown discrete log, using
// gnark-crypto's RFC 9380 hash-to-curve on the same curve as bn256, then converting
// the affine point into a bn256 G1. A known-discrete-log hash would let anyone
// derive the epoch key, so a real hash-to-curve is mandatory here.
func hashEpochToG1(epoch uint64) (*bn256.G1, error) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], epoch)
	p, err := bn254.HashToG1(buf[:], ibeDST)
	if err != nil {
		return nil, err
	}
	var x, y big.Int
	p.X.BigInt(&x)
	p.Y.BigInt(&y)
	var raw [64]byte
	x.FillBytes(raw[:32])
	y.FillBytes(raw[32:])
	g := new(bn256.G1)
	if _, err := g.Unmarshal(raw[:]); err != nil {
		return nil, fmt.Errorf("ibe: hash-to-curve conversion failed: %w", err)
	}
	return g, nil
}

// DeriveMasterPublicKey reconstructs mpk = s·G2 from any t committee verification
// keys (V_i = s_i·G2) by Lagrange interpolation at zero. It lets a committee
// publish the IBE encryption key from the same DKG output that backs decryption.
func DeriveMasterPublicKey(vks []*threshold.VerificationKey, t int) (*MasterPublicKey, error) {
	if t < 1 || len(vks) < t {
		return nil, errParams
	}
	use := vks[:t]
	indices := make([]*big.Int, t)
	for i, vk := range use {
		if vk == nil || vk.Point == nil || vk.Index == 0 {
			return nil, errParams
		}
		indices[i] = new(big.Int).SetUint64(uint64(vk.Index))
	}
	acc := new(bn256.G2).ScalarBaseMult(big.NewInt(0))
	for i, vk := range use {
		lambda := lagrangeAtZero(indices, i)
		acc.Add(acc, new(bn256.G2).ScalarMult(vk.Point, lambda))
	}
	return &MasterPublicKey{Point: acc}, nil
}

// EpochShare computes a keyper's epoch-key share σ_i = s_i·Q_E. A keyper releases
// this only for epochs whose decryption trigger has fired.
func EpochShare(ks *threshold.KeyShare, epoch uint64) (*EpochKeyShare, error) {
	qe, err := hashEpochToG1(epoch)
	if err != nil {
		return nil, err
	}
	return &EpochKeyShare{Index: ks.Index, Sigma: new(bn256.G1).ScalarMult(qe, ks.Secret)}, nil
}

// VerifyEpochShare checks σ_i against the keyper's verification key via
// e(σ_i, G2) == e(Q_E, V_i), so a malformed or dishonest share is detected.
func VerifyEpochShare(vk *threshold.VerificationKey, epoch uint64, share *EpochKeyShare) bool {
	if vk == nil || share == nil || vk.Index != share.Index || share.Sigma == nil || vk.Point == nil {
		return false
	}
	qe, err := hashEpochToG1(epoch)
	if err != nil {
		return false
	}
	// e(σ_i, G2) · e(-Q_E, V_i) == 1
	negQE := new(bn256.G1).Neg(qe)
	return bn256.PairingCheck([]*bn256.G1{share.Sigma, negQE}, []*bn256.G2{g2Generator(), vk.Point})
}

// CombineEpochKey reconstructs SK_E = s·Q_E from at least t valid epoch-key shares
// (Lagrange at zero). Callers should VerifyEpochShare each share first.
func CombineEpochKey(t int, epoch uint64, shares []*EpochKeyShare) (*EpochKey, error) {
	if t < 1 {
		return nil, errParams
	}
	if len(shares) < t {
		return nil, errTooFew
	}
	use := shares[:t]
	indices := make([]*big.Int, t)
	seen := make(map[uint32]struct{}, t)
	for i, s := range use {
		if s == nil || s.Sigma == nil || s.Index == 0 {
			return nil, errMalformed
		}
		if _, dup := seen[s.Index]; dup {
			return nil, errDuplicate
		}
		seen[s.Index] = struct{}{}
		indices[i] = new(big.Int).SetUint64(uint64(s.Index))
	}
	sk := new(bn256.G1).ScalarBaseMult(big.NewInt(0))
	for i, s := range use {
		lambda := lagrangeAtZero(indices, i)
		sk.Add(sk, new(bn256.G1).ScalarMult(s.Sigma, lambda))
	}
	return &EpochKey{Epoch: epoch, SK: sk}, nil
}

// Encrypt IBE-encrypts msg to the committee key for the given epoch.
func Encrypt(mpk *MasterPublicKey, epoch uint64, msg []byte, r io.Reader) (*Ciphertext, error) {
	if mpk == nil || mpk.Point == nil {
		return nil, errParams
	}
	qe, err := hashEpochToG1(epoch)
	if err != nil {
		return nil, err
	}
	k, err := randScalar(r)
	if err != nil {
		return nil, err
	}
	u := new(bn256.G2).ScalarBaseMult(k)
	shared := new(bn256.GT).ScalarMult(bn256.Pair(qe, mpk.Point), k) // e(Q_E, mpk)^r
	key := kdf(shared)

	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(r, nonce); err != nil {
		return nil, err
	}
	payload := gcm.Seal(nil, nonce, msg, aad(epoch, u))
	return &Ciphertext{Epoch: epoch, U: u, Nonce: nonce, Payload: payload}, nil
}

// Decrypt recovers the plaintext of a ciphertext using the epoch key for its epoch.
func Decrypt(sk *EpochKey, ct *Ciphertext) ([]byte, error) {
	if sk == nil || sk.SK == nil || ct == nil || ct.U == nil {
		return nil, errMalformed
	}
	if sk.Epoch != ct.Epoch {
		return nil, fmt.Errorf("%w: epoch key for %d cannot decrypt epoch %d", errDecrypt, sk.Epoch, ct.Epoch)
	}
	shared := bn256.Pair(sk.SK, ct.U) // e(s·Q_E, r·G2) = e(Q_E, mpk)^r
	key := kdf(shared)
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(ct.Nonce) != gcm.NonceSize() {
		return nil, errMalformed
	}
	msg, err := gcm.Open(nil, ct.Nonce, ct.Payload, aad(ct.Epoch, ct.U))
	if err != nil {
		return nil, errDecrypt
	}
	return msg, nil
}

// aad binds the epoch and ephemeral to the AES-GCM authentication.
func aad(epoch uint64, u *bn256.G2) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], epoch)
	return append(buf[:], u.Marshal()...)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func kdf(shared *bn256.GT) []byte {
	h := sha256.Sum256(shared.Marshal())
	return h[:]
}

func lagrangeAtZero(indices []*big.Int, i int) *big.Int {
	num := big.NewInt(1)
	den := big.NewInt(1)
	xi := indices[i]
	for j, xj := range indices {
		if j == i {
			continue
		}
		num.Mul(num, xj)
		num.Mod(num, order)
		diff := new(big.Int).Sub(xj, xi)
		diff.Mod(diff, order)
		den.Mul(den, diff)
		den.Mod(den, order)
	}
	den.ModInverse(den, order)
	num.Mul(num, den)
	num.Mod(num, order)
	return num
}

func randScalar(r io.Reader) (*big.Int, error) {
	for {
		k, err := rand.Int(r, order)
		if err != nil {
			return nil, err
		}
		if k.Sign() != 0 {
			return k, nil
		}
	}
}

// g2Size is the marshalled size of a bn256 G2 point.
var g2Size = len(g2Generator().Marshal())

// Marshal serializes a ciphertext as:
//
//	epoch(8) | U(g2Size) | nonceLen(1) | nonce | payload
func (ct *Ciphertext) Marshal() ([]byte, error) {
	if ct == nil || ct.U == nil {
		return nil, errMalformed
	}
	if len(ct.Nonce) > 255 {
		return nil, errMalformed
	}
	u := ct.U.Marshal()
	out := make([]byte, 8, 8+len(u)+1+len(ct.Nonce)+len(ct.Payload))
	binary.BigEndian.PutUint64(out[:8], ct.Epoch)
	out = append(out, u...)
	out = append(out, byte(len(ct.Nonce)))
	out = append(out, ct.Nonce...)
	out = append(out, ct.Payload...)
	return out, nil
}

// UnmarshalCiphertext parses the encoding produced by Ciphertext.Marshal.
func UnmarshalCiphertext(b []byte) (*Ciphertext, error) {
	if len(b) < 8+g2Size+1 {
		return nil, errMalformed
	}
	epoch := binary.BigEndian.Uint64(b[:8])
	u := new(bn256.G2)
	if _, err := u.Unmarshal(b[8 : 8+g2Size]); err != nil {
		return nil, fmt.Errorf("%w: %v", errMalformed, err)
	}
	rest := b[8+g2Size:]
	nonceLen := int(rest[0])
	rest = rest[1:]
	if len(rest) < nonceLen {
		return nil, errMalformed
	}
	nonce := append([]byte(nil), rest[:nonceLen]...)
	payload := append([]byte(nil), rest[nonceLen:]...)
	return &Ciphertext{Epoch: epoch, U: u, Nonce: nonce, Payload: payload}, nil
}

// Marshal serializes an epoch-key share as index(4) | Sigma(64).
func (s *EpochKeyShare) Marshal() ([]byte, error) {
	if s == nil || s.Sigma == nil {
		return nil, errMalformed
	}
	out := make([]byte, 4, 4+64)
	binary.BigEndian.PutUint32(out, s.Index)
	return append(out, s.Sigma.Marshal()...), nil
}

// UnmarshalEpochKeyShare parses the encoding produced by EpochKeyShare.Marshal.
func UnmarshalEpochKeyShare(b []byte) (*EpochKeyShare, error) {
	if len(b) < 4 {
		return nil, errMalformed
	}
	idx := binary.BigEndian.Uint32(b[:4])
	sigma := new(bn256.G1)
	if _, err := sigma.Unmarshal(b[4:]); err != nil {
		return nil, fmt.Errorf("%w: %v", errMalformed, err)
	}
	return &EpochKeyShare{Index: idx, Sigma: sigma}, nil
}

// Marshal serializes the master public key (G2 point).
func (mpk *MasterPublicKey) Marshal() ([]byte, error) {
	if mpk == nil || mpk.Point == nil {
		return nil, errParams
	}
	return mpk.Point.Marshal(), nil
}

// UnmarshalMasterPublicKey parses a master public key.
func UnmarshalMasterPublicKey(b []byte) (*MasterPublicKey, error) {
	p := new(bn256.G2)
	if _, err := p.Unmarshal(b); err != nil {
		return nil, fmt.Errorf("%w: %v", errParams, err)
	}
	return &MasterPublicKey{Point: p}, nil
}
