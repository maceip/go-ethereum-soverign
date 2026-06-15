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
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/privacy/zk"
)

// randField returns a random canonical field element as a 32-byte hash.
func randField() common.Hash {
	var e fr.Element
	e.SetRandom()
	return fromField(e)
}

func hv(h common.Hash) frontend.Variable { return new(big.Int).SetBytes(h[:]) }

func setPath(dst *[MerkleDepth]frontend.Variable, src [MerkleDepth]common.Hash) {
	for i := range src {
		dst[i] = hv(src[i])
	}
}

func setBits(dst *[MerkleDepth]frontend.Variable, src [MerkleDepth]uint8) {
	for i := range src {
		dst[i] = src[i]
	}
}

// dummyInput builds a dummy input note (value 0) with a random nullifier and an
// all-zero membership path (which is bypassed because IsDummy=1).
func dummyInput() (InputNote, common.Hash) {
	ask, rho := randField(), randField()
	cm := NoteCommitment(big.NewInt(0), DeriveApk(ask), rho)
	nf := Nullifier(ask, cm)
	in := InputNote{
		Value:   big.NewInt(0),
		Ask:     hv(ask),
		Rho:     hv(rho),
		IsDummy: 1,
	}
	for i := 0; i < MerkleDepth; i++ {
		in.PathElements[i] = big.NewInt(0)
		in.PathIndices[i] = 0
	}
	return in, nf
}

// dummyOutput builds a dummy output note (value 0) and returns its commitment.
func dummyOutput() (OutputNote, common.Hash) {
	ask, rho := randField(), randField()
	apk := DeriveApk(ask)
	cm := NoteCommitment(big.NewInt(0), apk, rho)
	return OutputNote{Value: big.NewInt(0), Apk: hv(apk), Rho: hv(rho)}, cm
}

// outputNote builds a real output note of the given value.
func outputNote(value *big.Int) (OutputNote, common.Hash, common.Hash) {
	ask, rho := randField(), randField()
	apk := DeriveApk(ask)
	cm := NoteCommitment(value, apk, rho)
	return OutputNote{Value: value, Apk: hv(apk), Rho: hv(rho)}, cm, ask
}

// buildShield constructs a valid shield assignment: two dummy inputs, one real
// output of `value` and one dummy output, with valueBalance = -value (shield).
func buildShield(t *testing.T, value *big.Int) *Transfer {
	t.Helper()
	var c Transfer
	c.Anchor = hv(EmptySubtreeRoots(MerkleDepth)[MerkleDepth]) // empty-tree root
	for i := 0; i < NumInputs; i++ {
		in, nf := dummyInput()
		c.In[i] = in
		c.Nullifiers[i] = hv(nf)
	}
	out0, cm0, _ := outputNote(value)
	out1, cm1 := dummyOutput()
	c.Out[0], c.Out[1] = out0, out1
	c.OutCommitments[0] = hv(cm0)
	c.OutCommitments[1] = hv(cm1)
	c.ValueMag = value
	c.ValueNeg = 1 // shield
	return &c
}

// TestCircuitValidShield checks a well-formed shield satisfies the constraints.
func TestCircuitValidShield(t *testing.T) {
	c := buildShield(t, big.NewInt(1000))
	if err := test.IsSolved(&Transfer{}, c, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("valid shield not solved: %v", err)
	}
}

// TestCircuitRejectsValueInflation checks that creating more value than is shielded
// is unprovable (the balance constraint fails).
func TestCircuitRejectsValueInflation(t *testing.T) {
	c := buildShield(t, big.NewInt(1000))
	// Tamper: claim only 999 entered the pool while minting a 1000-value output.
	c.ValueMag = big.NewInt(999)
	if err := test.IsSolved(&Transfer{}, c, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("value-inflating transfer was accepted by the circuit")
	}
}

// TestCircuitRejectsForgedNullifier checks that a nullifier not derived from the
// input's (ask, rho) is unprovable.
func TestCircuitRejectsForgedNullifier(t *testing.T) {
	c := buildShield(t, big.NewInt(1000))
	c.Nullifiers[0] = hv(randField()) // arbitrary, not MiMC(ask, rho)
	if err := test.IsSolved(&Transfer{}, c, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("forged nullifier was accepted by the circuit")
	}
}

// TestCircuitRejectsForgedOutputCommitment checks an output commitment that does
// not open to the claimed note is unprovable.
func TestCircuitRejectsForgedOutputCommitment(t *testing.T) {
	c := buildShield(t, big.NewInt(1000))
	c.OutCommitments[0] = hv(randField())
	if err := test.IsSolved(&Transfer{}, c, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("forged output commitment was accepted by the circuit")
	}
}

// TestCircuitRejectsNonMemberSpend checks that spending a note absent from the tree
// (real input with a bogus membership path) is unprovable.
func TestCircuitRejectsNonMemberSpend(t *testing.T) {
	value := big.NewInt(1000)
	var c Transfer

	// One real input whose commitment is NOT in the tree under Anchor.
	ask, rho := randField(), randField()
	apk := DeriveApk(ask)
	cm := NoteCommitment(value, apk, rho)
	in := InputNote{Value: value, Ask: hv(ask), Rho: hv(rho), IsDummy: 0}
	for i := 0; i < MerkleDepth; i++ {
		in.PathElements[i] = big.NewInt(0) // bogus path
		in.PathIndices[i] = 0
	}
	c.In[0] = in
	c.Nullifiers[0] = hv(Nullifier(ask, cm))

	din, dnf := dummyInput()
	c.In[1] = din
	c.Nullifiers[1] = hv(dnf)

	c.Anchor = hv(randField()) // arbitrary root the spend can't match
	out0, cm0, _ := outputNote(value)
	out1, cm1 := dummyOutput()
	c.Out[0], c.Out[1] = out0, out1
	c.OutCommitments[0] = hv(cm0)
	c.OutCommitments[1] = hv(cm1)
	c.ValueMag = big.NewInt(0)
	c.ValueNeg = 0

	if err := test.IsSolved(&Transfer{}, &c, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("spend of a non-member note was accepted by the circuit")
	}
}

// TestProveVerifyShield runs the full (devnet) setup → prove → verify path and
// checks the public-witness ordering matches circuit.PublicInputs.
func TestProveVerifyShield(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping trusted-setup/proving in -short mode")
	}
	vk, err := DevnetSetup()
	if err != nil {
		t.Fatalf("DevnetSetup: %v", err)
	}

	value := big.NewInt(1000)
	c := buildShield(t, value)
	proof, err := Prove(c)
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	// Reconstruct the public inputs the way consensus would, from the public
	// fields, and verify.
	nfs := []common.Hash{hashFromVar(t, c.Nullifiers[0]), hashFromVar(t, c.Nullifiers[1])}
	cms := []common.Hash{hashFromVar(t, c.OutCommitments[0]), hashFromVar(t, c.OutCommitments[1])}
	anchor := hashFromVar(t, c.Anchor)
	vb := new(big.Int).Neg(value) // shield

	inputs, err := PublicInputs(anchor, nfs, cms, vb)
	if err != nil {
		t.Fatalf("PublicInputs: %v", err)
	}
	witnessBytes, err := zk.PublicWitnessBytes(inputs)
	if err != nil {
		t.Fatalf("PublicWitnessBytes: %v", err)
	}
	ok, err := zk.VerifyPlonkBN254(vk, proof, witnessBytes)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatal("valid shield proof failed to verify")
	}

	// Sanity: verifying against a different anchor must fail (binding).
	inputs[0] = new(big.Int).SetBytes(randField().Bytes())
	witnessBytes, _ = zk.PublicWitnessBytes(inputs)
	if ok, _ := zk.VerifyPlonkBN254(vk, proof, witnessBytes); ok {
		t.Fatal("proof verified against tampered public inputs")
	}
}

// hashFromVar extracts the common.Hash from a frontend.Variable that was assigned
// a *big.Int in these tests.
func hashFromVar(t *testing.T, v frontend.Variable) common.Hash {
	t.Helper()
	b, ok := v.(*big.Int)
	if !ok {
		t.Fatalf("variable is not *big.Int: %T", v)
	}
	return common.BytesToHash(b.Bytes())
}
