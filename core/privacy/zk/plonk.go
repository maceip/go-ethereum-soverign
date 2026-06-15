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

// Package zk provides zero-knowledge proof verification used by the Ethereum
// privacy roadmap (Phase 1 confidential transactions, Phase 3 privacy
// precompiles). It currently wraps gnark's PlonK verifier over the BN254 curve.
//
// PlonK is chosen over Groth16 because it uses a universal, updatable trusted
// setup (a single SRS shared by every circuit) rather than a fresh per-circuit
// ceremony, which is the property the roadmap calls for when standardising
// privacy primitives across many applications (Roadmap Phase 2: "modern zk-SNARK
// constructions (e.g., PlonK, Halo2)"). The verifier is deliberately isolated in
// this package so the heavyweight proving dependency boundary stays contained and
// the EVM precompile layer can call a small, stable surface.
package zk

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
)

var (
	// ErrMalformedProofInput is returned when the length-prefixed verifier input
	// cannot be parsed into its (verifying key, proof, public witness) parts.
	ErrMalformedProofInput = errors.New("zk: malformed proof verifier input")

	// ErrDecode is returned when one of the components fails to deserialize into a
	// valid gnark object.
	ErrDecode = errors.New("zk: failed to decode proof component")
)

// maxComponent bounds each length-prefixed component to a sane size, protecting
// the verifier from absurd allocations driven by malicious calldata. A PlonK
// verifying key/proof for realistic privacy circuits is well under this bound.
const maxComponent = 1 << 20 // 1 MiB

// DecodeVerifierInput splits the precompile/verifier input into its three
// length-prefixed components. The wire format is:
//
//	vkLen (4-byte big-endian) || vk
//	proofLen (4-byte big-endian) || proof
//	witnessLen (4-byte big-endian) || publicWitness
//
// Each component is the native gnark binary serialization (io.WriterTo output) of
// the respective object. The public witness contains only the public inputs.
func DecodeVerifierInput(input []byte) (vk, proof, publicWitness []byte, err error) {
	next := func(buf []byte) (component, rest []byte, ok bool) {
		if len(buf) < 4 {
			return nil, nil, false
		}
		n := binary.BigEndian.Uint32(buf[:4])
		if n > maxComponent || uint64(len(buf)-4) < uint64(n) {
			return nil, nil, false
		}
		return buf[4 : 4+n], buf[4+n:], true
	}

	var ok bool
	if vk, input, ok = next(input); !ok {
		return nil, nil, nil, ErrMalformedProofInput
	}
	if proof, input, ok = next(input); !ok {
		return nil, nil, nil, ErrMalformedProofInput
	}
	if publicWitness, input, ok = next(input); !ok {
		return nil, nil, nil, ErrMalformedProofInput
	}
	if len(input) != 0 {
		return nil, nil, nil, ErrMalformedProofInput
	}
	return vk, proof, publicWitness, nil
}

// VerifyPlonkBN254 verifies a PlonK proof over BN254 against the supplied
// verifying key and public witness, all in gnark binary encoding.
//
// It distinguishes two failure modes the way a precompile needs them:
//   - a decoding error (malformed input) is returned as a non-nil error so the
//     caller can treat it as an invalid transaction, and
//   - a well-formed proof that simply does not satisfy the statement returns
//     (false, nil), i.e. a clean "proof rejected" without aborting execution.
func VerifyPlonkBN254(vkBytes, proofBytes, publicWitnessBytes []byte) (bool, error) {
	vk := plonk.NewVerifyingKey(ecc.BN254)
	if _, err := vk.ReadFrom(bytes.NewReader(vkBytes)); err != nil {
		return false, ErrDecode
	}
	proof := plonk.NewProof(ecc.BN254)
	if _, err := proof.ReadFrom(bytes.NewReader(proofBytes)); err != nil {
		return false, ErrDecode
	}
	pubWitness, err := witness.New(ecc.BN254.ScalarField())
	if err != nil {
		return false, ErrDecode
	}
	if _, err := pubWitness.ReadFrom(bytes.NewReader(publicWitnessBytes)); err != nil {
		return false, ErrDecode
	}
	if err := plonk.Verify(proof, vk, pubWitness); err != nil {
		// Valid encoding, but the proof does not satisfy the statement.
		return false, nil
	}
	return true, nil
}

// VerifyEncoded is a convenience wrapper that decodes a single length-prefixed
// input blob and verifies it.
func VerifyEncoded(input []byte) (bool, error) {
	vk, proof, pubWitness, err := DecodeVerifierInput(input)
	if err != nil {
		return false, err
	}
	return VerifyPlonkBN254(vk, proof, pubWitness)
}

// PublicWitnessBytes builds a BN254 public witness from the given field values and
// returns its gnark binary serialization. This lets consensus code reconstruct the
// exact public inputs a proof must satisfy (e.g. a digest binding a shielded
// transaction's contents) and verify the proof against them, without holding a
// circuit definition.
func PublicWitnessBytes(values []*big.Int) ([]byte, error) {
	w, err := witness.New(ecc.BN254.ScalarField())
	if err != nil {
		return nil, err
	}
	ch := make(chan any, len(values))
	for _, v := range values {
		ch <- v
	}
	close(ch)
	if err := w.Fill(len(values), 0, ch); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if _, err := w.WriteTo(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
