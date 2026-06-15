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

package pool

import (
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/privacy/zk"
	"github.com/ethereum/go-ethereum/crypto"
)

// This file implements the consensus verification of a shielded transaction's
// zero-knowledge proof. The shielded-transfer circuit proves, against a recent
// commitment-tree root, that spent notes exist and are correctly nullified, that
// the new commitments are well-formed, and that value is conserved. All of those
// public statements are bound into a single field element — the "public digest" —
// derived deterministically from the transaction's public fields. Consensus
// recomputes that digest from the transaction it is validating and verifies the
// PlonK proof against it, so a proof can only validate for the exact (anchor,
// nullifiers, commitments, valueBalance) tuple it was generated for.
//
// The verifying key of the canonical circuit is installed into the pool's system
// account storage (e.g. at genesis), so it is part of consensus state and can be
// rotated through governance without a client release.

var (
	// ErrNoVerifyingKey is returned when no shielded-transfer verifying key has
	// been installed in the pool state.
	ErrNoVerifyingKey = errors.New("pool: no shielded verifying key installed")

	// ErrInvalidProof is returned when a shielded transaction's proof fails to
	// verify against the recomputed public digest.
	ErrInvalidProof = errors.New("pool: invalid shielded proof")
)

var (
	slotVKLen      = crypto.Keccak256Hash([]byte("privacy/pool/vk/len"))
	prefixVKChunk  = []byte("privacy/pool/vk/chunk")
	bn254ScalarMod = ecc.BN254.ScalarField()
)

// InstallVerifyingKey stores the shielded-transfer PlonK verifying key in the
// pool's system-account storage. It is intended to be called from genesis
// initialisation (or a governance-gated path), not from ordinary transactions.
func (p *Pool) InstallVerifyingKey(vk []byte) {
	writeBlob(p.be, slotVKLen, prefixVKChunk, vk)
}

// VerifyingKey returns the installed verifying key, or nil if none is set.
func (p *Pool) VerifyingKey() []byte {
	return readBlob(p.be, slotVKLen, prefixVKChunk)
}

// PublicDigest deterministically binds a shielded transaction's public fields into
// a single BN254 scalar. Both the prover (off-chain) and the verifier (consensus)
// must compute it identically, so it is the canonical definition of the circuit's
// public input.
func PublicDigest(anchor common.Hash, nullifiers, commitments []common.Hash, valueBalance *big.Int) *big.Int {
	var preimage []byte
	preimage = append(preimage, []byte("privacy/pool/publicDigest")...)
	preimage = append(preimage, anchor[:]...)

	var count [8]byte
	binary.BigEndian.PutUint64(count[:], uint64(len(nullifiers)))
	preimage = append(preimage, count[:]...)
	for _, n := range nullifiers {
		preimage = append(preimage, n[:]...)
	}
	binary.BigEndian.PutUint64(count[:], uint64(len(commitments)))
	preimage = append(preimage, count[:]...)
	for _, c := range commitments {
		preimage = append(preimage, c[:]...)
	}
	// Encode the signed value balance as a sign byte followed by the magnitude, so
	// shield/unshield/transfer produce distinct digests. Use a copy for the
	// magnitude so the caller's value is never mutated.
	vb := valueBalance
	if vb == nil {
		vb = new(big.Int)
	}
	preimage = append(preimage, byte(vb.Sign()&0xff))
	preimage = append(preimage, new(big.Int).Abs(vb).Bytes()...)

	d := new(big.Int).SetBytes(crypto.Keccak256(preimage))
	return d.Mod(d, bn254ScalarMod)
}

// VerifyProof verifies a shielded transaction's proof against the installed
// verifying key and the public digest of the supplied fields. It returns nil iff
// the proof is valid.
func (p *Pool) VerifyProof(anchor common.Hash, nullifiers, commitments []common.Hash, valueBalance *big.Int, proof []byte) error {
	vk := p.VerifyingKey()
	if len(vk) == 0 {
		return ErrNoVerifyingKey
	}
	digest := PublicDigest(anchor, nullifiers, commitments, valueBalance)
	witnessBytes, err := zk.PublicWitnessBytes([]*big.Int{digest})
	if err != nil {
		return ErrInvalidProof
	}
	ok, err := zk.VerifyPlonkBN254(vk, proof, witnessBytes)
	if err != nil || !ok {
		return ErrInvalidProof
	}
	return nil
}

// --- chunked blob storage ------------------------------------------------------

// writeBlob stores an arbitrary-length byte slice across consecutive storage
// slots: lenSlot holds the byte length, and the data is split into 32-byte chunks
// keyed by chunkPrefix.
func writeBlob(be Backend, lenSlot common.Hash, chunkPrefix []byte, data []byte) {
	var lenWord common.Hash
	binary.BigEndian.PutUint64(lenWord[24:], uint64(len(data)))
	be.SetState(SystemAddress, lenSlot, lenWord)

	for i := 0; i*32 < len(data); i++ {
		var chunk common.Hash
		end := (i + 1) * 32
		if end > len(data) {
			end = len(data)
		}
		copy(chunk[:], data[i*32:end])
		be.SetState(SystemAddress, indexedSlot(chunkPrefix, uint64(i)), chunk)
	}
}

// readBlob reverses writeBlob.
func readBlob(be Backend, lenSlot common.Hash, chunkPrefix []byte) []byte {
	lenWord := be.GetState(SystemAddress, lenSlot)
	n := binary.BigEndian.Uint64(lenWord[24:])
	if n == 0 {
		return nil
	}
	out := make([]byte, n)
	for i := 0; uint64(i*32) < n; i++ {
		chunk := be.GetState(SystemAddress, indexedSlot(chunkPrefix, uint64(i)))
		copy(out[i*32:], chunk[:])
	}
	return out
}
