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

// Package circuit defines the production shielded-transfer zero-knowledge circuit
// for Privacy Phase 1 of the Ethereum Privacy roadmap, together with the native
// (out-of-circuit) hashing, note and Merkle-tree helpers a wallet/prover needs.
//
// The circuit proves, in zero knowledge, that a 2-input/2-output shielded transfer
// is valid:
//
//   - each (non-dummy) input note is a leaf of the commitment tree under the
//     public Anchor (Merkle membership),
//   - each input's nullifier is correctly derived from the owner's spending key
//     and the note, and equals the publicly revealed nullifier (double-spend
//     prevention + ownership),
//   - each output note commitment is well-formed and equals the publicly revealed
//     commitment, and
//   - value is conserved: Σ(input values) == Σ(output values) + valueBalance, with
//     all amounts range-checked to prevent field-wraparound forgery.
//
// All hashing uses MiMC over the BN254 scalar field, which is efficient inside a
// SNARK (Keccak would cost orders of magnitude more constraints). The native
// helpers here MUST compute byte-for-byte the same values as the in-circuit
// gadgets, otherwise honestly-built proofs would fail to verify; this invariant is
// covered by tests.
package circuit

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/ethereum/go-ethereum/common"
)

const (
	// NumInputs and NumOutputs fix the circuit arity. A 2-in/2-output "JoinSplit"
	// shape (as used by Zcash Sapling) supports merge/split of notes; unused slots
	// are filled with dummy notes.
	NumInputs  = 2
	NumOutputs = 2

	// MerkleDepth is the depth of the note-commitment tree. It must match the depth
	// used by the consensus shielded pool. A depth of 32 supports 2^32 notes.
	MerkleDepth = 32

	// ValueBits bounds note values and the value balance to 128 bits. This is the
	// soundness-critical range check that prevents proving "negative" values via
	// field wraparound. 128 bits comfortably exceeds the wei supply (< 2^90).
	ValueBits = 128
)

// toField interprets a 32-byte hash as a BN254 scalar (reducing mod the field
// order, which is a no-op for canonical values produced by fromField).
func toField(h common.Hash) fr.Element {
	var e fr.Element
	e.SetBytes(h[:])
	return e
}

// fromField serializes a scalar to its canonical 32-byte big-endian form.
func fromField(e fr.Element) common.Hash {
	return common.BytesToHash(e.Marshal())
}

// hashElements computes MiMC over the given field elements (the native
// counterpart of the in-circuit MiMC gadget).
func hashElements(elems ...fr.Element) common.Hash {
	h := mimc.NewMiMC()
	for _, e := range elems {
		// e.Marshal returns a canonical 32-byte (BlockSize) big-endian encoding.
		if _, err := h.Write(e.Marshal()); err != nil {
			panic("circuit: mimc write failed: " + err.Error()) // unreachable for canonical elements
		}
	}
	var out common.Hash
	copy(out[:], h.Sum(nil))
	return out
}

// HashTwo is the Merkle node hash: MiMC(left, right). It is exported so the
// consensus pool uses exactly the same construction as the circuit.
func HashTwo(left, right common.Hash) common.Hash {
	return hashElements(toField(left), toField(right))
}

// valueField converts an unsigned amount to a field element.
func valueField(v *big.Int) fr.Element {
	var e fr.Element
	e.SetBigInt(v)
	return e
}

// DeriveApk derives the public address key from a spending key: apk = MiMC(ask).
func DeriveApk(ask common.Hash) common.Hash {
	return hashElements(toField(ask))
}

// NoteCommitment computes a note commitment: cm = MiMC(value, apk, rho).
func NoteCommitment(value *big.Int, apk, rho common.Hash) common.Hash {
	return hashElements(valueField(value), toField(apk), toField(rho))
}

// Nullifier computes a note's nullifier: nf = MiMC(ask, cm), binding it to the
// full note commitment so that distinct notes always have distinct nullifiers
// (even if they happen to share an ask). Only the holder of the spending key can
// produce it, and it is unlinkable to the commitment without that key.
func Nullifier(ask, commitment common.Hash) common.Hash {
	return hashElements(toField(ask), toField(commitment))
}

// EmptySubtreeRoots returns the root of an empty subtree at each level 0..depth,
// where level 0 is the empty leaf (zero) and level i+1 = HashTwo(z_i, z_i). The
// consensus pool uses these for padding so its roots match the circuit/tree.
func EmptySubtreeRoots(depth uint) []common.Hash {
	zeros := make([]common.Hash, depth+1)
	for i := uint(0); i < depth; i++ {
		zeros[i+1] = HashTwo(zeros[i], zeros[i])
	}
	return zeros
}

// PublicInputs assembles the circuit's public witness vector from a shielded
// transaction's public fields, in the exact order the circuit declares them:
//
//	[Anchor, Nullifiers[0..NumInputs-1], OutCommitments[0..NumOutputs-1],
//	 ValueMag, ValueNeg]
//
// It errors if the nullifier/commitment counts do not match the circuit arity.
// ValueNeg is 1 for a shield (valueBalance < 0) and 0 otherwise; ValueMag is the
// magnitude.
func PublicInputs(anchor common.Hash, nullifiers, commitments []common.Hash, valueBalance *big.Int) ([]*big.Int, error) {
	if len(nullifiers) != NumInputs || len(commitments) != NumOutputs {
		return nil, ErrArity
	}
	vec := make([]*big.Int, 0, 1+NumInputs+NumOutputs+2)
	a := toField(anchor)
	vec = append(vec, a.BigInt(new(big.Int)))
	for _, nf := range nullifiers {
		e := toField(nf)
		vec = append(vec, e.BigInt(new(big.Int)))
	}
	for _, cm := range commitments {
		e := toField(cm)
		vec = append(vec, e.BigInt(new(big.Int)))
	}
	if valueBalance == nil {
		valueBalance = new(big.Int)
	}
	mag := new(big.Int).Abs(valueBalance)
	neg := big.NewInt(0)
	if valueBalance.Sign() < 0 {
		neg.SetInt64(1)
	}
	vec = append(vec, mag, neg)
	return vec, nil
}
