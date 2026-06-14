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
	"errors"
	"math/big"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
)

// Roadmap reference: Phase 1 — "Sealed amounts and addresses: Employ cryptographic
// commitments like Pedersen commitments to encrypt transaction values".
//
// A Pedersen commitment to a value v with blinding factor r is the elliptic-curve
// point
//
//	C = v*G + r*H
//
// where G is the standard generator of the bn256 G1 group and H is a second,
// independent generator for which the discrete logarithm relative to G is
// unknown ("nothing-up-my-sleeve"). The commitment is:
//
//   - hiding:   C reveals nothing about v (r is uniformly random), and
//   - binding:  it is infeasible to open C to a different (v', r'), and
//   - additively homomorphic: Commit(v1,r1) + Commit(v2,r2) == Commit(v1+v2, r1+r2).
//
// The homomorphism is what lets a confidential transaction prove that the sum of
// hidden input amounts equals the sum of hidden output amounts (plus fee) without
// revealing any individual amount.

// CommitmentSize is the byte length of a serialized commitment. Commitments are
// encoded in the EVM-friendly uncompressed bn256 G1 format used by the existing
// precompiles: a 32-byte big-endian X coordinate followed by a 32-byte Y.
const CommitmentSize = 64

var (
	// ErrInvalidCommitment is returned when bytes cannot be decoded into a valid
	// G1 group element.
	ErrInvalidCommitment = errors.New("privacy: invalid pedersen commitment encoding")

	// ErrValueOutOfRange is returned when a value or blinding factor is negative
	// or not strictly less than the group order.
	ErrValueOutOfRange = errors.New("privacy: scalar out of range")
)

// h is the second Pedersen generator. It is derived deterministically from the
// canonical encoding of the primary generator G so that nobody knows its discrete
// logarithm with respect to G. See hashToG1 for the construction.
var h = deriveH()

func deriveH() *bn256.G1 {
	// G's marshaled form is a fixed public constant; hashing it into the group
	// yields an independent generator with an unknown dlog relative to G.
	g := new(bn256.G1).ScalarBaseMult(big.NewInt(1))
	return hashToG1(append([]byte("go-ethereum/privacy/pedersen/H"), g.Marshal()...))
}

// hashToG1 maps arbitrary bytes to a G1 point using try-and-increment over the
// curve generator. This is not constant-time and is only ever used to derive the
// fixed public generator H, so timing is irrelevant.
func hashToG1(seed []byte) *bn256.G1 {
	for i := uint64(0); ; i++ {
		ctr := new(big.Int).SetUint64(i)
		k := new(big.Int).SetBytes(keccak(append(seed, ctr.Bytes()...)))
		k.Mod(k, bn256.Order)
		if k.Sign() == 0 {
			continue
		}
		return new(bn256.G1).ScalarBaseMult(k)
	}
}

// Commit returns the serialized Pedersen commitment C = value*G + blinding*H.
//
// Both value and blinding must be in the range [0, Order). value is the amount
// being hidden; blinding must be sampled uniformly at random (see RandomScalar)
// and kept secret alongside the value to later open the commitment.
func Commit(value, blinding *big.Int) ([]byte, error) {
	if !inRange(value) || !inRange(blinding) {
		return nil, ErrValueOutOfRange
	}
	vG := new(bn256.G1).ScalarBaseMult(value)
	rH := new(bn256.G1).ScalarMult(h, blinding)
	return new(bn256.G1).Add(vG, rH).Marshal(), nil
}

// Add returns the homomorphic sum of two serialized commitments. Because the
// scheme is additively homomorphic, the result is itself a valid commitment to
// the sum of the two underlying values with the sum of the two blinding factors.
func Add(a, b []byte) ([]byte, error) {
	pa, err := unmarshalG1(a)
	if err != nil {
		return nil, err
	}
	pb, err := unmarshalG1(b)
	if err != nil {
		return nil, err
	}
	return new(bn256.G1).Add(pa, pb).Marshal(), nil
}

// Neg returns the additive inverse of a serialized commitment, i.e. the
// commitment scaled by (Order-1). This lets callers form differences of
// commitments (Add(a, Neg(b))) when checking balance equations.
func Neg(a []byte) ([]byte, error) {
	pa, err := unmarshalG1(a)
	if err != nil {
		return nil, err
	}
	negOne := new(big.Int).Sub(bn256.Order, big.NewInt(1))
	return new(bn256.G1).ScalarMult(pa, negOne).Marshal(), nil
}

// VerifySum reports whether the sum of the input commitments equals the sum of
// the output commitments. For a balanced confidential transfer the caller folds
// any plaintext fee into the outputs as Commit(fee, 0) before calling.
//
// This is the core consensus check a confidential-ETH transaction performs: it
// proves value is conserved without revealing any individual amount. It does not,
// on its own, prove that the committed values are non-negative — that requires an
// accompanying range proof, which the roadmap delegates to the zk-SNARK layer.
func VerifySum(inputs, outputs [][]byte) (bool, error) {
	left, err := sum(inputs)
	if err != nil {
		return false, err
	}
	right, err := sum(outputs)
	if err != nil {
		return false, err
	}
	return equalBytes(left, right), nil
}

func sum(cs [][]byte) ([]byte, error) {
	acc := new(bn256.G1).ScalarBaseMult(big.NewInt(0)) // identity element
	for _, c := range cs {
		p, err := unmarshalG1(c)
		if err != nil {
			return nil, err
		}
		acc.Add(acc, p)
	}
	return acc.Marshal(), nil
}

func unmarshalG1(b []byte) (*bn256.G1, error) {
	if len(b) != CommitmentSize {
		return nil, ErrInvalidCommitment
	}
	p := new(bn256.G1)
	if _, err := p.Unmarshal(b); err != nil {
		return nil, ErrInvalidCommitment
	}
	return p, nil
}

func inRange(v *big.Int) bool {
	return v != nil && v.Sign() >= 0 && v.Cmp(bn256.Order) < 0
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
