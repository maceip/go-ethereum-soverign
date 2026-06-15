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

package zk

import (
	"bytes"
	"io"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
)

// cubicCircuit proves knowledge of a secret X such that X^3 + X + 5 == Y, where Y
// is a public input. It is a minimal stand-in for a real confidential-transfer
// circuit and lets the test exercise the full prove/verify path.
type cubicCircuit struct {
	X frontend.Variable `gnark:",secret"`
	Y frontend.Variable `gnark:",public"`
}

func (c *cubicCircuit) Define(api frontend.API) error {
	x3 := api.Mul(c.X, c.X, c.X)
	api.AssertIsEqual(c.Y, api.Add(x3, c.X, 5))
	return nil
}

// encodeComponent serializes a gnark object and length-prefixes it the way
// DecodeVerifierInput expects.
func encodeComponent(t *testing.T, w io.WriterTo) []byte {
	t.Helper()
	var buf bytes.Buffer
	if _, err := w.WriteTo(&buf); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	out := make([]byte, 4+buf.Len())
	out[0] = byte(buf.Len() >> 24)
	out[1] = byte(buf.Len() >> 16)
	out[2] = byte(buf.Len() >> 8)
	out[3] = byte(buf.Len())
	copy(out[4:], buf.Bytes())
	return out
}

// setupProof compiles the cubic circuit, runs an (unsafe, test-only) trusted
// setup, and produces a proof for X=3 (=> Y=35). It returns the encoded verifier
// blob plus the raw vk/proof/witness bytes.
func setupProof(t *testing.T) (encoded, vkBytes, proofBytes, witBytes []byte) {
	t.Helper()

	var circuit cubicCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
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

	assignment := &cubicCircuit{X: 3, Y: 35}
	fullWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	proof, err := plonk.Prove(ccs, pk, fullWitness)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	publicWitness, err := fullWitness.Public()
	if err != nil {
		t.Fatalf("public witness: %v", err)
	}

	vkEnc := encodeComponent(t, vk)
	proofEnc := encodeComponent(t, proof)
	witEnc := encodeComponent(t, publicWitness)

	encoded = append(append(append([]byte{}, vkEnc...), proofEnc...), witEnc...)
	return encoded, vkEnc[4:], proofEnc[4:], witEnc[4:]
}

// TestVerifyValidProof checks a correctly generated PlonK proof verifies.
func TestVerifyValidProof(t *testing.T) {
	encoded, vk, proof, wit := setupProof(t)

	ok, err := VerifyPlonkBN254(vk, proof, wit)
	if err != nil {
		t.Fatalf("VerifyPlonkBN254: %v", err)
	}
	if !ok {
		t.Fatal("valid proof rejected")
	}

	// And through the single-blob convenience wrapper.
	ok, err = VerifyEncoded(encoded)
	if err != nil {
		t.Fatalf("VerifyEncoded: %v", err)
	}
	if !ok {
		t.Fatal("valid proof rejected via VerifyEncoded")
	}
}

// TestVerifyWrongPublicInput checks the proof is rejected (cleanly, no error) when
// the public input does not match the statement the proof was generated for.
func TestVerifyWrongPublicInput(t *testing.T) {
	_, vk, proof, _ := setupProof(t)

	// Build a public witness for Y=36, which the proof does not satisfy.
	wrong := &cubicCircuit{Y: 36}
	w, err := frontend.NewWitness(wrong, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	var buf bytes.Buffer
	if _, err := w.WriteTo(&buf); err != nil {
		t.Fatalf("serialize: %v", err)
	}

	ok, err := VerifyPlonkBN254(vk, proof, buf.Bytes())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("proof accepted against wrong public input")
	}
}

// TestVerifyTamperedProof checks a corrupted proof is rejected.
func TestVerifyTamperedProof(t *testing.T) {
	_, vk, proof, wit := setupProof(t)
	tampered := append([]byte{}, proof...)
	tampered[len(tampered)/2] ^= 0xff

	ok, err := VerifyPlonkBN254(vk, tampered, wit)
	// Corruption may surface either as a decode error or a clean rejection; both
	// are acceptable, but it must never verify as true.
	if ok {
		t.Fatalf("tampered proof accepted (err=%v)", err)
	}
}

// TestDecodeVerifierInput checks the length-prefixed framing round-trips and
// rejects malformed blobs.
func TestDecodeVerifierInput(t *testing.T) {
	encoded, wantVK, wantProof, wantWit := setupProof(t)

	vk, proof, wit, err := DecodeVerifierInput(encoded)
	if err != nil {
		t.Fatalf("DecodeVerifierInput: %v", err)
	}
	if !bytes.Equal(vk, wantVK) || !bytes.Equal(proof, wantProof) || !bytes.Equal(wit, wantWit) {
		t.Fatal("decoded components do not match originals")
	}

	if _, _, _, err := DecodeVerifierInput([]byte{0x00, 0x00}); err != ErrMalformedProofInput {
		t.Fatalf("short input: got %v, want ErrMalformedProofInput", err)
	}
	// Length prefix claims more bytes than present.
	if _, _, _, err := DecodeVerifierInput([]byte{0x00, 0x00, 0x00, 0xff, 0x01}); err != ErrMalformedProofInput {
		t.Fatalf("overlong prefix: got %v, want ErrMalformedProofInput", err)
	}
}

// witnessReaderSanity guards the assumption that an empty witness reader errors
// rather than panicking, since the precompile relies on decode errors.
func TestVerifyRejectsGarbage(t *testing.T) {
	if _, err := VerifyPlonkBN254([]byte{0x01, 0x02}, []byte{0x03}, []byte{0x04}); err != ErrDecode {
		t.Fatalf("garbage input: got %v, want ErrDecode", err)
	}
	// Ensure witness.New is usable (smoke test of the gnark version).
	if _, err := witness.New(ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("witness.New: %v", err)
	}
}
