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

package keyper

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/privacy/threshold"
)

type mapState struct {
	addr    common.Address
	storage map[common.Hash]common.Hash
}

func (m *mapState) GetState(addr common.Address, key common.Hash) common.Hash {
	if addr != m.addr {
		return common.Hash{}
	}
	return m.storage[key]
}

var registryAddr = common.HexToAddress("0x00000000000000000000000000000000000a11ce")

func TestRegistryServesUsableCommitteeConfig(t *testing.T) {
	const thresholdSize, members = 3, 5
	eon, shares, _, err := threshold.DealerSetup(thresholdSize, members, rand.Reader)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	keypers := []common.Address{
		common.HexToAddress("0x1111111111111111111111111111111111111111"),
		common.HexToAddress("0x2222222222222222222222222222222222222222"),
		common.HexToAddress("0x3333333333333333333333333333333333333333"),
		common.HexToAddress("0x4444444444444444444444444444444444444444"),
		common.HexToAddress("0x5555555555555555555555555555555555555555"),
	}
	storage, err := BuildRegistryStorage(thresholdSize, eon, keypers)
	if err != nil {
		t.Fatalf("build storage: %v", err)
	}
	reg := NewRegistry(registryAddr)
	st := &mapState{addr: registryAddr, storage: storage}

	if !reg.Configured(st) {
		t.Fatal("registry should report configured")
	}
	if got := reg.Threshold(st); got != thresholdSize {
		t.Fatalf("threshold = %d, want %d", got, thresholdSize)
	}
	gotKeypers := reg.Keypers(st)
	if len(gotKeypers) != len(keypers) {
		t.Fatalf("keyper count = %d, want %d", len(gotKeypers), len(keypers))
	}
	for i := range keypers {
		if gotKeypers[i] != keypers[i] {
			t.Fatalf("keyper[%d] = %s, want %s", i, gotKeypers[i], keypers[i])
		}
	}
	pk, err := reg.EonKey(st)
	if err != nil {
		t.Fatalf("eon key: %v", err)
	}
	plaintext := []byte("hello committee")
	ct, err := threshold.Encrypt(pk, plaintext, rand.Reader)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	got, err := threshold.Combine(thresholdSize, ct, []*threshold.DecryptionShare{
		shares[0].Decrypt(ct),
		shares[1].Decrypt(ct),
		shares[2].Decrypt(ct),
	})
	if err != nil {
		t.Fatalf("combine: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("recovered %q, want %q", got, plaintext)
	}

	empty := &mapState{addr: registryAddr, storage: map[common.Hash]common.Hash{}}
	if reg.Configured(empty) {
		t.Fatal("empty registry reported configured")
	}
	if _, err := reg.EonKey(empty); err != ErrNoEonKey {
		t.Fatalf("empty registry eon key err = %v, want %v", err, ErrNoEonKey)
	}
	if _, err := BuildRegistryStorage(0, eon, keypers); err == nil {
		t.Fatal("accepted zero threshold")
	}
	if _, err := BuildRegistryStorage(len(keypers)+1, eon, keypers); err == nil {
		t.Fatal("accepted threshold greater than keyper count")
	}
}
