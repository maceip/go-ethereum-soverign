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

package privacy

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// Roadmap reference: Phase 1 — "Implement native stealth addresses (building beyond
// EIP-5564) to generate one-time recipient addresses, disrupting blockchain
// analysis".
//
// This implements the secp256k1 stealth-address scheme of EIP-5564. A recipient
// publishes a stealth meta-address consisting of two public keys: a spending key
// P_spend and a viewing key P_view. To pay them, a sender:
//
//  1. samples an ephemeral keypair (r, R = r*G),
//  2. computes the shared secret s_h = keccak(r * P_view) (ECDH),
//  3. derives the one-time stealth public key P_stealth = P_spend + s_h*G,
//  4. publishes R (the ephemeral pubkey) and a one-byte "view tag" so the
//     recipient can cheaply scan for payments.
//
// The recipient recovers the same shared secret with its viewing private key
// (s_h = keccak(v * R)) and, when it wants to spend, computes the stealth private
// key p_stealth = p_spend + s_h (mod n). Only the holder of the spending key can
// spend, while the viewing key alone is enough to detect incoming payments — this
// separation is what enables watch-only / auditor views.

// ErrInvalidStealthKey is returned when a public key cannot be parsed onto the
// secp256k1 curve.
var ErrInvalidStealthKey = errors.New("privacy: invalid stealth key")

// StealthMetaAddress is the recipient's published stealth meta-address: the
// spending and viewing public keys.
type StealthMetaAddress struct {
	Spend *ecdsa.PublicKey
	View  *ecdsa.PublicKey
}

// StealthPayment is the public output a sender produces for a single stealth
// payment. StealthAddress is the one-time address that should receive funds,
// EphemeralPubKey must be published on-chain (e.g. via an announcer event) so the
// recipient can recover the payment, and ViewTag is a one-byte hint that lets the
// recipient skip ~255/256 of non-matching announcements during scanning.
type StealthPayment struct {
	StealthAddress  common.Address
	StealthPubKey   *ecdsa.PublicKey
	EphemeralPubKey *ecdsa.PublicKey
	ViewTag         byte
}

// GenerateStealthAddress produces a fresh one-time stealth payment for the given
// meta-address using a randomly sampled ephemeral key. It is the operation a
// sender performs.
func GenerateStealthAddress(meta StealthMetaAddress) (*StealthPayment, error) {
	ephemeral, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return generateStealthAddress(meta, ephemeral)
}

// generateStealthAddress is the deterministic core of GenerateStealthAddress,
// split out so tests can supply a fixed ephemeral key.
func generateStealthAddress(meta StealthMetaAddress, ephemeral *ecdsa.PrivateKey) (*StealthPayment, error) {
	if !onCurve(meta.Spend) || !onCurve(meta.View) {
		return nil, ErrInvalidStealthKey
	}
	// ECDH against the viewing key: shared = ephemeral_priv * P_view.
	shared := sharedSecret(ephemeral.D.Bytes(), meta.View)
	sh := keccak(shared)

	// P_stealth = P_spend + keccak(shared)*G
	stealthPub, err := addScalarBase(meta.Spend, sh)
	if err != nil {
		return nil, err
	}
	return &StealthPayment{
		StealthAddress:  crypto.PubkeyToAddress(*stealthPub),
		StealthPubKey:   stealthPub,
		EphemeralPubKey: &ephemeral.PublicKey,
		ViewTag:         sh[0],
	}, nil
}

// CheckStealthAddress reports whether a published (ephemeralPub, viewTag) pair is
// a payment addressed to the holder of viewKey/spendPub, and if so returns the
// derived stealth address. This is the cheap scanning operation a recipient runs
// against every announcement using only its viewing private key.
func CheckStealthAddress(viewKey *ecdsa.PrivateKey, spendPub, ephemeralPub *ecdsa.PublicKey, viewTag byte) (common.Address, bool, error) {
	if !onCurve(ephemeralPub) || !onCurve(spendPub) {
		return common.Address{}, false, ErrInvalidStealthKey
	}
	// Recompute the shared secret from the recipient side: shared = view_priv * R.
	shared := sharedSecret(viewKey.D.Bytes(), ephemeralPub)
	sh := keccak(shared)

	// View-tag fast path: reject non-matching announcements without an EC add.
	if sh[0] != viewTag {
		return common.Address{}, false, nil
	}
	stealthPub, err := addScalarBase(spendPub, sh)
	if err != nil {
		return common.Address{}, false, err
	}
	return crypto.PubkeyToAddress(*stealthPub), true, nil
}

// ComputeStealthKey derives the private key controlling a stealth address. It
// requires both the spending and viewing private keys and the published ephemeral
// public key. Only the holder of the spending key can run this and therefore only
// they can spend the funds.
func ComputeStealthKey(spendKey, viewKey *ecdsa.PrivateKey, ephemeralPub *ecdsa.PublicKey) (*ecdsa.PrivateKey, error) {
	if !onCurve(ephemeralPub) {
		return nil, ErrInvalidStealthKey
	}
	shared := sharedSecret(viewKey.D.Bytes(), ephemeralPub)
	sh := keccak(shared)

	// p_stealth = p_spend + keccak(shared)  (mod n)
	n := crypto.S256().Params().N
	d := new(big.Int).Add(spendKey.D, new(big.Int).SetBytes(sh))
	d.Mod(d, n)
	if d.Sign() == 0 {
		return nil, ErrInvalidStealthKey
	}
	return crypto.ToECDSA(common.LeftPadBytes(d.Bytes(), 32))
}

// sharedSecret computes the X coordinate of priv*pub on secp256k1, the standard
// ECDH shared secret.
func sharedSecret(priv []byte, pub *ecdsa.PublicKey) []byte {
	x, _ := crypto.S256().ScalarMult(pub.X, pub.Y, priv)
	return common.LeftPadBytes(x.Bytes(), 32)
}

// addScalarBase returns pub + scalar*G as a public key.
func addScalarBase(pub *ecdsa.PublicKey, scalar []byte) (*ecdsa.PublicKey, error) {
	curve := crypto.S256()
	sx, sy := curve.ScalarBaseMult(scalar)
	x, y := curve.Add(pub.X, pub.Y, sx, sy)
	if x.Sign() == 0 && y.Sign() == 0 {
		return nil, ErrInvalidStealthKey
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

func onCurve(pub *ecdsa.PublicKey) bool {
	return pub != nil && pub.X != nil && pub.Y != nil && crypto.S256().IsOnCurve(pub.X, pub.Y)
}
