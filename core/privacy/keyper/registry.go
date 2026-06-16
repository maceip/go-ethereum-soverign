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

// Package keyper implements the on-chain keyper registry for the fork's encrypted
// mempool (threshold-encryption based; shape.md): the consensus-readable record of
// who the decryption committee (the "keypers") are, their threshold, and the
// committee ("eon") public key that users encrypt to.
//
// The registry is plain account storage at a reserved registry address, laid out
// so an ordinary Solidity registry contract can write it and the execution client
// can read it directly from state:
//
//	slot 0  : threshold t                       (uint256)
//	slot 1  : keypers.length n                  (uint256; `address[] keypers` at slot 1)
//	slot 2  : eonKey bytes [0:32]               (first half of the 64-byte G1 point)
//	slot 3  : eonKey bytes [32:64]              (second half)
//	keypers[i] : slot keccak256(uint256(1)) + i (right-aligned address)
//
// This package owns the layout and the read path, plus a genesis populator so a
// devnet can install a committee. The keyper *network* (distributed key generation
// for the eon key, and per-epoch decryption-key release) is a separate service;
// this package deliberately does not implement DKG or key release, and the eon key
// it serves is only as trustworthy as whatever produced it. On a production network
// the registry must be populated by a real keyper-run registration/DKG flow, never
// by a trusted dealer.
package keyper

import (
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/privacy/threshold"
	"github.com/ethereum/go-ethereum/crypto"
)

// Storage slot assignments in the registry account.
const (
	slotThreshold   = 0
	slotKeypersLen  = 1
	slotEonKeyWord0 = 2
	slotEonKeyWord1 = 3
)

var (
	// ErrNoEonKey is returned when the registry holds no committee public key.
	ErrNoEonKey = errors.New("keyper: no eon key set in registry")
	// ErrInvalidRegistry is returned when registry contents are malformed.
	ErrInvalidRegistry = errors.New("keyper: invalid registry contents")
)

// StateReader is the subset of the state interface the registry reads. *state.StateDB
// satisfies it.
type StateReader interface {
	GetState(addr common.Address, key common.Hash) common.Hash
}

// Registry reads the keyper committee record from the account at Addr.
type Registry struct {
	Addr common.Address
}

// NewRegistry returns a registry reader for the given registry account address.
func NewRegistry(addr common.Address) *Registry {
	return &Registry{Addr: addr}
}

// Threshold returns the decryption threshold t recorded in the registry.
func (r *Registry) Threshold(s StateReader) int {
	return int(slotUint(s, r.Addr, slotThreshold))
}

// Keypers returns the ordered list of committee member addresses.
func (r *Registry) Keypers(s StateReader) []common.Address {
	n := slotUint(s, r.Addr, slotKeypersLen)
	if n == 0 {
		return nil
	}
	base := arrayBaseSlot(slotKeypersLen)
	out := make([]common.Address, 0, n)
	for i := uint64(0); i < n; i++ {
		slot := new(big.Int).Add(base, new(big.Int).SetUint64(i))
		word := s.GetState(r.Addr, common.BigToHash(slot))
		out = append(out, common.BytesToAddress(word.Bytes()))
	}
	return out
}

// EonKey returns the committee (eon) public key users encrypt to.
func (r *Registry) EonKey(s StateReader) (*threshold.PublicKey, error) {
	w0 := s.GetState(r.Addr, common.BigToHash(big.NewInt(slotEonKeyWord0)))
	w1 := s.GetState(r.Addr, common.BigToHash(big.NewInt(slotEonKeyWord1)))
	if w0 == (common.Hash{}) && w1 == (common.Hash{}) {
		return nil, ErrNoEonKey
	}
	raw := make([]byte, 0, 64)
	raw = append(raw, w0.Bytes()...)
	raw = append(raw, w1.Bytes()...)
	pk, err := threshold.UnmarshalPublicKey(raw)
	if err != nil {
		return nil, ErrInvalidRegistry
	}
	return pk, nil
}

// Configured reports whether the registry holds a usable committee: a positive
// threshold no larger than the keyper count, and an eon key.
func (r *Registry) Configured(s StateReader) bool {
	t := r.Threshold(s)
	keypers := r.Keypers(s)
	if t < 1 || t > len(keypers) {
		return false
	}
	if _, err := r.EonKey(s); err != nil {
		return false
	}
	return true
}

// BuildRegistryStorage returns the account storage that encodes the given
// committee, for installing a registry at genesis (devnet) or for tests. It
// produces exactly the layout that Registry reads and that a Solidity registry
// contract would write.
func BuildRegistryStorage(t int, eonKey *threshold.PublicKey, keypers []common.Address) (map[common.Hash]common.Hash, error) {
	if t < 1 || t > len(keypers) {
		return nil, ErrInvalidRegistry
	}
	raw, err := eonKey.Marshal()
	if err != nil {
		return nil, err
	}
	if len(raw) != 64 {
		return nil, ErrInvalidRegistry
	}
	storage := map[common.Hash]common.Hash{
		common.BigToHash(big.NewInt(slotThreshold)):   common.BigToHash(big.NewInt(int64(t))),
		common.BigToHash(big.NewInt(slotKeypersLen)):  common.BigToHash(big.NewInt(int64(len(keypers)))),
		common.BigToHash(big.NewInt(slotEonKeyWord0)): common.BytesToHash(raw[:32]),
		common.BigToHash(big.NewInt(slotEonKeyWord1)): common.BytesToHash(raw[32:64]),
	}
	base := arrayBaseSlot(slotKeypersLen)
	for i, addr := range keypers {
		slot := new(big.Int).Add(base, new(big.Int).SetUint64(uint64(i)))
		storage[common.BigToHash(slot)] = common.BytesToHash(addr.Bytes())
	}
	return storage, nil
}

// slotUint reads a storage slot as a uint64.
func slotUint(s StateReader, addr common.Address, slot int64) uint64 {
	return s.GetState(addr, common.BigToHash(big.NewInt(slot))).Big().Uint64()
}

// arrayBaseSlot returns the base storage slot for the elements of a Solidity
// dynamic array declared at the given slot: keccak256(uint256(slot)).
func arrayBaseSlot(slot uint64) *big.Int {
	h := crypto.Keccak256(common.BigToHash(new(big.Int).SetUint64(slot)).Bytes())
	return new(big.Int).SetBytes(h)
}
