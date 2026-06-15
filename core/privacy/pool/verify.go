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

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/privacy/circuit"
	"github.com/ethereum/go-ethereum/core/privacy/zk"
	"github.com/ethereum/go-ethereum/crypto"
)

// This file implements the consensus verification of a shielded transaction's
// zero-knowledge proof. The shielded-transfer circuit (see core/privacy/circuit)
// proves, against a recent commitment-tree root, that spent notes exist and are
// correctly nullified, that the new commitments are well-formed, and that value is
// conserved. Its public inputs are exactly the transaction's public fields —
// anchor, nullifiers, output commitments and the (signed) value balance — so
// consensus rebuilds that public witness from the transaction it is validating and
// verifies the PlonK proof against it. A proof therefore only validates for the
// precise transaction it was generated for.
//
// The verifying key of the canonical circuit is installed into the pool's system
// account storage (e.g. at genesis), so it is part of consensus state and can be
// rotated through governance without a client release.

var (
	// ErrNoVerifyingKey is returned when no shielded-transfer verifying key has
	// been installed in the pool state.
	ErrNoVerifyingKey = errors.New("pool: no shielded verifying key installed")

	// ErrInvalidProof is returned when a shielded transaction's proof fails to
	// verify against its public inputs.
	ErrInvalidProof = errors.New("pool: invalid shielded proof")
)

var (
	slotVKLen     = crypto.Keccak256Hash([]byte("privacy/pool/vk/len"))
	prefixVKChunk = []byte("privacy/pool/vk/chunk")
)

// InstallVerifyingKey stores the shielded-transfer PlonK verifying key in the
// pool's system-account storage. It is intended to be called from genesis
// initialisation (or a governance-gated path), not from ordinary transactions.
//
// SECURITY: the verifying key must come from a real trusted-setup ceremony for any
// value-bearing network. The devnet key produced by circuit.DevnetSetup uses an
// in-process (insecure) SRS and must never be installed on such a network.
func (p *Pool) InstallVerifyingKey(vk []byte) {
	writeBlob(p.be, slotVKLen, prefixVKChunk, vk)
}

// VerifyingKey returns the installed verifying key, or nil if none is set.
func (p *Pool) VerifyingKey() []byte {
	return readBlob(p.be, slotVKLen, prefixVKChunk)
}

// VerifyProof verifies a shielded transaction's proof against the installed
// verifying key and the transaction's public fields. It returns nil iff the proof
// is valid for exactly those fields.
func (p *Pool) VerifyProof(anchor common.Hash, nullifiers, commitments []common.Hash, valueBalance *big.Int, proof []byte) error {
	vk := p.VerifyingKey()
	if len(vk) == 0 {
		return ErrNoVerifyingKey
	}
	inputs, err := circuit.PublicInputs(anchor, nullifiers, commitments, valueBalance)
	if err != nil {
		return ErrInvalidProof
	}
	witnessBytes, err := zk.PublicWitnessBytes(inputs)
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
