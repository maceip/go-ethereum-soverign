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

package vm

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/privacy"
)

// padScalar left-pads a big.Int to a 32-byte big-endian slice.
func padScalar(v *big.Int) []byte {
	return common.LeftPadBytes(v.Bytes(), 32)
}

// TestPedersenCommitPrecompile checks the precompile output matches the privacy
// package and that the commitment is homomorphic via the PEDERSEN_ADD precompile.
func TestPedersenCommitPrecompile(t *testing.T) {
	commit := &pedersenCommit{}
	add := &pedersenAdd{}

	// C1 = Commit(100, 7), C2 = Commit(50, 9).
	in1 := append(padScalar(big.NewInt(100)), padScalar(big.NewInt(7))...)
	in2 := append(padScalar(big.NewInt(50)), padScalar(big.NewInt(9))...)

	c1, err := commit.Run(in1)
	if err != nil {
		t.Fatalf("commit C1: %v", err)
	}
	c2, err := commit.Run(in2)
	if err != nil {
		t.Fatalf("commit C2: %v", err)
	}

	// Cross-check against the library directly.
	wantC1, _ := privacy.Commit(big.NewInt(100), big.NewInt(7))
	if !bytes.Equal(c1, wantC1) {
		t.Fatal("precompile commitment != library commitment")
	}

	// PEDERSEN_ADD(C1, C2) must equal Commit(150, 16).
	sum, err := add.Run(append(append([]byte{}, c1...), c2...))
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	wantSum, _ := privacy.Commit(big.NewInt(150), big.NewInt(16))
	if !bytes.Equal(sum, wantSum) {
		t.Fatal("homomorphic add via precompile mismatch")
	}
}

func TestPedersenCommitPrecompileBadInput(t *testing.T) {
	commit := &pedersenCommit{}
	if _, err := commit.Run(make([]byte, 63)); err != errPrivacyBadInput {
		t.Fatalf("short input: got %v, want errPrivacyBadInput", err)
	}
	add := &pedersenAdd{}
	if _, err := add.Run(make([]byte, 100)); err != errPrivacyBadInput {
		t.Fatalf("short add input: got %v, want errPrivacyBadInput", err)
	}
}

// TestPrivacyPrecompilesRegistered ensures the precompiles are live in the Osaka
// fork at the documented addresses.
func TestPrivacyPrecompilesRegistered(t *testing.T) {
	set := PrecompiledContractsOsaka
	for _, addr := range []byte{0x12, 0x13, 0x14} {
		if _, ok := set[common.BytesToAddress([]byte{addr})]; !ok {
			t.Fatalf("privacy precompile not registered at 0x%x in Osaka set", addr)
		}
	}
}

// plonkTestCircuit proves knowledge of X such that X*X == Y, with Y public.
type plonkTestCircuit struct {
	X frontend.Variable `gnark:",secret"`
	Y frontend.Variable `gnark:",public"`
}

func (c *plonkTestCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.Y, api.Mul(c.X, c.X))
	return nil
}

// buildPlonkInput produces a length-prefixed (vk, proof, publicWitness) blob in
// the format the PLONK_VERIFY precompile consumes, proving 7*7 == 49.
func buildPlonkInput(t *testing.T) []byte {
	t.Helper()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &plonkTestCircuit{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	if err != nil {
		t.Fatalf("srs: %v", err)
	}
	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	full, err := frontend.NewWitness(&plonkTestCircuit{X: 7, Y: 49}, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	proof, err := plonk.Prove(ccs, pk, full)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	pub, err := full.Public()
	if err != nil {
		t.Fatalf("public: %v", err)
	}

	// Serialize each component with a 4-byte big-endian length prefix.
	enc := func(buf *bytes.Buffer) []byte {
		b := buf.Bytes()
		out := make([]byte, 4+len(b))
		out[0] = byte(len(b) >> 24)
		out[1] = byte(len(b) >> 16)
		out[2] = byte(len(b) >> 8)
		out[3] = byte(len(b))
		copy(out[4:], b)
		return out
	}
	var vkBuf, proofBuf, witBuf bytes.Buffer
	if _, err := vk.WriteTo(&vkBuf); err != nil {
		t.Fatalf("vk encode: %v", err)
	}
	if _, err := proof.WriteTo(&proofBuf); err != nil {
		t.Fatalf("proof encode: %v", err)
	}
	if _, err := pub.WriteTo(&witBuf); err != nil {
		t.Fatalf("witness encode: %v", err)
	}
	var out []byte
	out = append(out, enc(&vkBuf)...)
	out = append(out, enc(&proofBuf)...)
	out = append(out, enc(&witBuf)...)
	return out
}

// TestPlonkVerifyPrecompile checks a real PlonK proof verifies through the
// PLONK_VERIFY (0x14) precompile and returns the canonical truthy 32-byte word.
func TestPlonkVerifyPrecompile(t *testing.T) {
	input := buildPlonkInput(t)
	p := &plonkVerify{}

	if g := p.RequiredGas(input); g == 0 {
		t.Fatal("RequiredGas returned 0")
	}
	out, err := p.Run(input)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !bytes.Equal(out, true32Byte) {
		t.Fatalf("valid proof did not return true word: %x", out)
	}
}

// TestPlonkVerifyPrecompileMalformed checks malformed input is surfaced as an
// error (treated as an invalid transaction) rather than silently passing.
func TestPlonkVerifyPrecompileMalformed(t *testing.T) {
	p := &plonkVerify{}
	if _, err := p.Run([]byte{0x00, 0x00, 0x00, 0x05, 0x01}); err == nil {
		t.Fatal("malformed input did not error")
	}
}
