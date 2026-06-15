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

package circuit

import (
	"errors"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/rangecheck"
)

// ErrArity is returned when a shielded transaction's nullifier/commitment counts
// do not match the circuit's fixed arity.
var ErrArity = errors.New("circuit: nullifier/commitment count does not match circuit arity")

// InputNote is the secret witness for one spent note.
type InputNote struct {
	Value frontend.Variable // note value (range-checked)
	Ask   frontend.Variable // owner spending key
	Rho   frontend.Variable // note randomness

	// IsDummy is 1 for an unused input slot. Dummy inputs must have Value 0 and
	// skip the Merkle membership check (their nullifier is still revealed).
	IsDummy frontend.Variable

	// PathElements/PathIndices are the Merkle authentication path of the note's
	// commitment to the Anchor. PathIndices[d] is the bit (0/1) telling whether the
	// current node is the left or right child at level d.
	PathElements [MerkleDepth]frontend.Variable
	PathIndices  [MerkleDepth]frontend.Variable
}

// OutputNote is the secret witness for one created note.
type OutputNote struct {
	Value frontend.Variable
	Apk   frontend.Variable // recipient address key (apk = MiMC(recipient ask))
	Rho   frontend.Variable
}

// Transfer is the 2-in/2-out shielded-transfer circuit. Public inputs are
// declared first and in the order consumed by circuit.PublicInputs.
type Transfer struct {
	// --- public inputs ---
	Anchor         frontend.Variable             `gnark:",public"`
	Nullifiers     [NumInputs]frontend.Variable  `gnark:",public"`
	OutCommitments [NumOutputs]frontend.Variable `gnark:",public"`
	ValueMag       frontend.Variable             `gnark:",public"`
	ValueNeg       frontend.Variable             `gnark:",public"`

	// --- secret witness ---
	In  [NumInputs]InputNote
	Out [NumOutputs]OutputNote
}

// hash is a one-shot MiMC over the given inputs, matching native hashElements.
func hashCircuit(api frontend.API, inputs ...frontend.Variable) (frontend.Variable, error) {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return nil, err
	}
	h.Write(inputs...)
	return h.Sum(), nil
}

// merkleRoot folds a leaf up to the root using its authentication path. It must
// mirror the native Tree/pool folding exactly.
func merkleRoot(api frontend.API, leaf frontend.Variable, path, index [MerkleDepth]frontend.Variable) (frontend.Variable, error) {
	cur := leaf
	for d := 0; d < MerkleDepth; d++ {
		api.AssertIsBoolean(index[d])
		// index[d]==1 => cur is the right child, sibling on the left.
		left := api.Select(index[d], path[d], cur)
		right := api.Select(index[d], cur, path[d])
		var err error
		if cur, err = hashCircuit(api, left, right); err != nil {
			return nil, err
		}
	}
	return cur, nil
}

// Define implements the shielded-transfer constraints.
func (c *Transfer) Define(api frontend.API) error {
	rc := rangecheck.New(api)

	sumIn := frontend.Variable(0)
	for i := 0; i < NumInputs; i++ {
		in := c.In[i]
		api.AssertIsBoolean(in.IsDummy)

		// Range-check the value and force dummy inputs to value 0.
		rc.Check(in.Value, ValueBits)
		api.AssertIsEqual(api.Mul(in.IsDummy, in.Value), 0)

		// apk = MiMC(ask); cm = MiMC(value, apk, rho).
		apk, err := hashCircuit(api, in.Ask)
		if err != nil {
			return err
		}
		cm, err := hashCircuit(api, in.Value, apk, in.Rho)
		if err != nil {
			return err
		}

		// Membership: for real inputs the recomputed root must equal the Anchor.
		// For dummy inputs the check is bypassed.
		root, err := merkleRoot(api, cm, in.PathElements, in.PathIndices)
		if err != nil {
			return err
		}
		api.AssertIsEqual(api.Select(in.IsDummy, c.Anchor, root), c.Anchor)

		// Nullifier: nf = MiMC(ask, rho), bound to the publicly revealed value.
		nf, err := hashCircuit(api, in.Ask, in.Rho)
		if err != nil {
			return err
		}
		api.AssertIsEqual(nf, c.Nullifiers[i])

		sumIn = api.Add(sumIn, in.Value)
	}

	sumOut := frontend.Variable(0)
	for j := 0; j < NumOutputs; j++ {
		out := c.Out[j]
		rc.Check(out.Value, ValueBits)

		cm, err := hashCircuit(api, out.Value, out.Apk, out.Rho)
		if err != nil {
			return err
		}
		api.AssertIsEqual(cm, c.OutCommitments[j])

		sumOut = api.Add(sumOut, out.Value)
	}

	// Value conservation. ValueNeg selects the direction of the transparent flow:
	//   shield   (ValueNeg==1): sumIn + ValueMag == sumOut   (ETH enters the pool)
	//   unshield (ValueNeg==0): sumIn == sumOut + ValueMag   (ETH leaves the pool)
	api.AssertIsBoolean(c.ValueNeg)
	rc.Check(c.ValueMag, ValueBits)
	lhs := api.Add(sumIn, api.Mul(c.ValueNeg, c.ValueMag))
	rhs := api.Add(sumOut, api.Mul(api.Sub(1, c.ValueNeg), c.ValueMag))
	api.AssertIsEqual(lhs, rhs)

	return nil
}
