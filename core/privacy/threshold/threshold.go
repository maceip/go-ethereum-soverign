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

// Package threshold implements the threshold-encryption primitive used by the
// fork's encrypted mempool. It is the cryptographic foundation for a Shutter-style
// encrypted mempool: users encrypt a transaction to a committee public key; the
// transaction propagates and waits encrypted; and only when it is selected for a
// block does a threshold of committee members release decryption shares that the
// proposer combines to recover the plaintext. Transactions that are never selected
// stay encrypted, so their contents remain private — the property
// batched-threshold-encryption research (USENIX Security 2024/2025) calls privacy
// for non-included transactions.
//
// This file is the verifiable threshold cryptosystem only. It is deliberately
// transport- and consensus-agnostic so it can be tested in isolation; the
// committee transport (keyper network) and block-building decryption/inclusion are
// implemented elsewhere in the encrypted-mempool work.
//
// Scheme. A hybrid threshold KEM/DEM over the bn256 pairing curve already used by
// this fork:
//
//   - Setup splits a master secret s (Shamir, threshold t of n) into committee
//     shares s_i. The encryption public key is P = s·G1; each member publishes a
//     verification key V_i = s_i·G2.
//   - Encrypt picks r, sets C1 = r·G1, derives the shared secret S = r·P = r·s·G1,
//     and uses KDF(S) as an AES-256-GCM key over the payload.
//   - Each member's decryption share is D_i = s_i·C1, verifiable with the pairing
//     check e(D_i, G2) == e(C1, V_i) so a malformed share (decryption-share abuse)
//     is detectable — the accountability hook the roadmap requires.
//   - Combine reconstructs S = s·C1 = Σ λ_i·D_i over any t valid shares (Lagrange
//     at 0) and AES-GCM-decrypts.
//
// SECURITY POSTURE. DealerSetup is a trusted-dealer (devnet) key generation: the
// dealer learns the master secret and must discard it. A production deployment
// requires a distributed key generation (DKG) so no single party ever holds s.
// Like the shielded-pool trusted setup in this fork, DealerSetup must never be
// used to protect value on a real network. This is enforced by labelling, not by
// code, exactly as the shielded setup is.
package threshold

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

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
)

// order is the prime order of the bn256 groups; all scalars live in Z_order.
var order = bn256.Order

var (
	errBadParams     = errors.New("threshold: invalid (t,n) parameters")
	errTooFewShares  = errors.New("threshold: not enough decryption shares")
	errDuplicate     = errors.New("threshold: duplicate share index")
	errShareIndex    = errors.New("threshold: share index out of range")
	errMalformed     = errors.New("threshold: malformed ciphertext")
	errDecryptFailed = errors.New("threshold: decryption failed (bad shares or ciphertext)")
)

// PublicKey is the committee's aggregate encryption key, P = s·G1.
type PublicKey struct {
	P *bn256.G1
}

// KeyShare is a single committee member's secret Shamir share of the master key.
// It is secret material and must never be serialized into untrusted storage.
type KeyShare struct {
	Index  uint32   // Shamir x-coordinate, in [1,n]
	Secret *big.Int // s_i = f(Index)
}

// VerificationKey is the public commitment V_i = s_i·G2 to a member's share,
// used to verify that member's decryption shares.
type VerificationKey struct {
	Index uint32
	Point *bn256.G2
}

// Ciphertext is a hybrid threshold-encrypted message: a KEM component C1 plus an
// AES-256-GCM-encrypted payload.
type Ciphertext struct {
	C1      *bn256.G1
	Nonce   []byte
	Payload []byte
}

// DecryptionShare is one committee member's contribution toward decrypting a
// specific ciphertext: D_i = s_i·C1.
type DecryptionShare struct {
	Index uint32
	D     *bn256.G1
}

// g2Generator returns the canonical G2 generator.
func g2Generator() *bn256.G2 {
	return new(bn256.G2).ScalarBaseMult(big.NewInt(1))
}

// randScalar samples a uniform non-zero scalar in [1, order).
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

// DealerSetup performs trusted-dealer key generation for an (t,n) committee: it
// samples the master secret, Shamir-splits it, and returns the committee public
// key, the n secret shares, and the n public verification keys.
//
// This is a DEVNET-ONLY trusted setup: the dealer (this function) sees the master
// secret. Production requires a DKG. See the package documentation.
func DealerSetup(t, n int, r io.Reader) (*PublicKey, []*KeyShare, []*VerificationKey, error) {
	if t < 1 || n < 1 || t > n {
		return nil, nil, nil, errBadParams
	}
	// Sample polynomial coefficients a_0..a_{t-1}; a_0 is the master secret.
	coeffs := make([]*big.Int, t)
	for i := range coeffs {
		c, err := randScalar(r)
		if err != nil {
			return nil, nil, nil, err
		}
		coeffs[i] = c
	}
	pub := &PublicKey{P: new(bn256.G1).ScalarBaseMult(coeffs[0])}

	g2 := g2Generator()
	shares := make([]*KeyShare, n)
	vks := make([]*VerificationKey, n)
	for i := 1; i <= n; i++ {
		si := evalPolynomial(coeffs, big.NewInt(int64(i)))
		shares[i-1] = &KeyShare{Index: uint32(i), Secret: si}
		vks[i-1] = &VerificationKey{Index: uint32(i), Point: new(bn256.G2).ScalarMult(g2, si)}
	}
	return pub, shares, vks, nil
}

// evalPolynomial evaluates f(x) = Σ coeffs[j]·x^j mod order (Horner).
func evalPolynomial(coeffs []*big.Int, x *big.Int) *big.Int {
	acc := new(big.Int)
	for j := len(coeffs) - 1; j >= 0; j-- {
		acc.Mul(acc, x)
		acc.Add(acc, coeffs[j])
		acc.Mod(acc, order)
	}
	return acc
}

// Encrypt threshold-encrypts msg to the committee public key.
func Encrypt(pk *PublicKey, msg []byte, r io.Reader) (*Ciphertext, error) {
	if pk == nil || pk.P == nil {
		return nil, errBadParams
	}
	k, err := randScalar(r)
	if err != nil {
		return nil, err
	}
	c1 := new(bn256.G1).ScalarBaseMult(k)
	shared := new(bn256.G1).ScalarMult(pk.P, k) // r·P = r·s·G1
	key := kdf(shared)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(r, nonce); err != nil {
		return nil, err
	}
	payload := gcm.Seal(nil, nonce, msg, c1.Marshal())
	return &Ciphertext{C1: c1, Nonce: nonce, Payload: payload}, nil
}

// Decrypt produces this member's decryption share for the given ciphertext.
func (ks *KeyShare) Decrypt(ct *Ciphertext) *DecryptionShare {
	return &DecryptionShare{
		Index: ks.Index,
		D:     new(bn256.G1).ScalarMult(ct.C1, ks.Secret),
	}
}

// VerifyShare checks that share is a well-formed decryption share for ct from the
// member identified by vk, using the pairing relation e(D, G2) == e(C1, V). A
// failing check indicates a malformed or dishonest share.
func VerifyShare(vk *VerificationKey, ct *Ciphertext, share *DecryptionShare) bool {
	if vk == nil || ct == nil || share == nil || vk.Index != share.Index {
		return false
	}
	if share.D == nil || ct.C1 == nil || vk.Point == nil {
		return false
	}
	// e(D, G2) == e(C1, V)  <=>  e(D, G2) · e(-C1, V) == 1
	negC1 := new(bn256.G1).Neg(ct.C1)
	return bn256.PairingCheck([]*bn256.G1{share.D, negC1}, []*bn256.G2{g2Generator(), vk.Point})
}

// Combine reconstructs the plaintext from at least t decryption shares. The shares
// must have distinct, valid indices; callers should VerifyShare each share against
// the corresponding verification key before combining so that a bad share is
// attributed to its member rather than surfacing only as a decryption failure.
func Combine(t int, ct *Ciphertext, shares []*DecryptionShare) ([]byte, error) {
	if ct == nil || ct.C1 == nil {
		return nil, errMalformed
	}
	if t < 1 {
		return nil, errBadParams
	}
	if len(shares) < t {
		return nil, errTooFewShares
	}
	// Use the first t shares; ensure distinct indices.
	use := shares[:t]
	seen := make(map[uint32]struct{}, t)
	indices := make([]*big.Int, t)
	for i, s := range use {
		if s == nil || s.D == nil {
			return nil, errMalformed
		}
		if s.Index == 0 {
			return nil, errShareIndex
		}
		if _, dup := seen[s.Index]; dup {
			return nil, errDuplicate
		}
		seen[s.Index] = struct{}{}
		indices[i] = new(big.Int).SetUint64(uint64(s.Index))
	}

	// shared = Σ λ_i · D_i = s·C1.
	shared := new(bn256.G1).ScalarBaseMult(big.NewInt(0)) // identity
	for i, s := range use {
		lambda := lagrangeAtZero(indices, i)
		term := new(bn256.G1).ScalarMult(s.D, lambda)
		shared.Add(shared, term)
	}

	key := kdf(shared)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ct.Nonce) != gcm.NonceSize() {
		return nil, errMalformed
	}
	msg, err := gcm.Open(nil, ct.Nonce, ct.Payload, ct.C1.Marshal())
	if err != nil {
		return nil, errDecryptFailed
	}
	return msg, nil
}

// lagrangeAtZero returns the Lagrange basis coefficient λ_i evaluated at x=0 for
// the interpolation points indices, modulo order.
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

// kdf derives a 32-byte AES key from a shared group element.
func kdf(shared *bn256.G1) []byte {
	h := sha256.Sum256(shared.Marshal())
	return h[:]
}

// Marshal serializes a ciphertext to a self-describing byte slice:
//
//	C1 (64 bytes) | nonceLen (1 byte) | nonce | payload
func (ct *Ciphertext) Marshal() ([]byte, error) {
	if ct == nil || ct.C1 == nil {
		return nil, errMalformed
	}
	if len(ct.Nonce) > 255 {
		return nil, errMalformed
	}
	c1 := ct.C1.Marshal() // 64 bytes
	out := make([]byte, 0, len(c1)+1+len(ct.Nonce)+len(ct.Payload))
	out = append(out, c1...)
	out = append(out, byte(len(ct.Nonce)))
	out = append(out, ct.Nonce...)
	out = append(out, ct.Payload...)
	return out, nil
}

// UnmarshalCiphertext parses the encoding produced by Ciphertext.Marshal.
func UnmarshalCiphertext(b []byte) (*Ciphertext, error) {
	const c1Len = 64
	if len(b) < c1Len+1 {
		return nil, errMalformed
	}
	c1 := new(bn256.G1)
	if _, err := c1.Unmarshal(b[:c1Len]); err != nil {
		return nil, fmt.Errorf("%w: %v", errMalformed, err)
	}
	nonceLen := int(b[c1Len])
	rest := b[c1Len+1:]
	if len(rest) < nonceLen {
		return nil, errMalformed
	}
	nonce := append([]byte(nil), rest[:nonceLen]...)
	payload := append([]byte(nil), rest[nonceLen:]...)
	return &Ciphertext{C1: c1, Nonce: nonce, Payload: payload}, nil
}

// Marshal serializes the committee public key (64-byte G1 point).
func (pk *PublicKey) Marshal() ([]byte, error) {
	if pk == nil || pk.P == nil {
		return nil, errBadParams
	}
	return pk.P.Marshal(), nil
}

// UnmarshalPublicKey parses a committee public key.
func UnmarshalPublicKey(b []byte) (*PublicKey, error) {
	p := new(bn256.G1)
	if _, err := p.Unmarshal(b); err != nil {
		return nil, fmt.Errorf("%w: %v", errBadParams, err)
	}
	return &PublicKey{P: p}, nil
}

// Marshal serializes a decryption share as index(4) || G1(64).
func (s *DecryptionShare) Marshal() ([]byte, error) {
	if s == nil || s.D == nil {
		return nil, errMalformed
	}
	out := make([]byte, 4, 4+64)
	binary.BigEndian.PutUint32(out, s.Index)
	return append(out, s.D.Marshal()...), nil
}

// UnmarshalDecryptionShare parses the encoding produced by DecryptionShare.Marshal.
func UnmarshalDecryptionShare(b []byte) (*DecryptionShare, error) {
	if len(b) < 4 {
		return nil, errMalformed
	}
	idx := binary.BigEndian.Uint32(b[:4])
	d := new(bn256.G1)
	if _, err := d.Unmarshal(b[4:]); err != nil {
		return nil, fmt.Errorf("%w: %v", errMalformed, err)
	}
	return &DecryptionShare{Index: idx, D: d}, nil
}

// Marshal serializes a verification key as index(4) || G2.
func (v *VerificationKey) Marshal() ([]byte, error) {
	if v == nil || v.Point == nil {
		return nil, errMalformed
	}
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, v.Index)
	return append(out, v.Point.Marshal()...), nil
}

// UnmarshalVerificationKey parses the encoding produced by VerificationKey.Marshal.
func UnmarshalVerificationKey(b []byte) (*VerificationKey, error) {
	if len(b) < 4 {
		return nil, errMalformed
	}
	idx := binary.BigEndian.Uint32(b[:4])
	p := new(bn256.G2)
	if _, err := p.Unmarshal(b[4:]); err != nil {
		return nil, fmt.Errorf("%w: %v", errMalformed, err)
	}
	return &VerificationKey{Index: idx, Point: p}, nil
}
