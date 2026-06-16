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
	"crypto/rand"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/privacy/threshold"
)

// mapState is an in-memory StateReader for a single account.
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

func TestRegistryRoundTrip(t *testing.T) {
	const tt, n = 3, 5
	eon, _, _, err := threshold.DealerSetup(tt, n, rand.Reader)
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

	storage, err := BuildRegistryStorage(tt, eon, keypers)
	if err != nil {
		t.Fatalf("build storage: %v", err)
	}
	st := &mapState{addr: registryAddr, storage: storage}
	reg := NewRegistry(registryAddr)

	if got := reg.Threshold(st); got != tt {
		t.Fatalf("threshold = %d, want %d", got, tt)
	}
	gotKeypers := reg.Keypers(st)
	if len(gotKeypers) != len(keypers) {
		t.Fatalf("keyper count = %d, want %d", len(gotKeypers), len(keypers))
	}
	for i := range keypers {
		if gotKeypers[i] != keypers[i] {
			t.Fatalf("keyper[%d] = %s, want %s", i, gotKeypers[i].Hex(), keypers[i].Hex())
		}
	}
	gotEon, err := reg.EonKey(st)
	if err != nil {
		t.Fatalf("eon key: %v", err)
	}
	// The eon key read from the registry must encrypt to the same committee: a
	// ciphertext made with it decrypts with the committee's shares.
	want, _ := eon.Marshal()
	got, _ := gotEon.Marshal()
	if string(want) != string(got) {
		t.Fatal("eon key round-trip mismatch")
	}
	if !reg.Configured(st) {
		t.Fatal("registry should report configured")
	}
}

// TestRegistryEonKeyUsable checks the registry-served eon key actually works for
// threshold encryption end to end.
func TestRegistryEonKeyUsable(t *testing.T) {
	const tt, n = 2, 3
	eon, shares, _, err := threshold.DealerSetup(tt, n, rand.Reader)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	keypers := []common.Address{
		common.HexToAddress("0xaa"), common.HexToAddress("0xbb"), common.HexToAddress("0xcc"),
	}
	storage, err := BuildRegistryStorage(tt, eon, keypers)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	st := &mapState{addr: registryAddr, storage: storage}
	reg := NewRegistry(registryAddr)

	pk, err := reg.EonKey(st)
	if err != nil {
		t.Fatalf("eon: %v", err)
	}
	ct, err := threshold.Encrypt(pk, []byte("hello committee"), rand.Reader)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	msg, err := threshold.Combine(tt, ct, []*threshold.DecryptionShare{
		shares[0].Decrypt(ct), shares[1].Decrypt(ct),
	})
	if err != nil {
		t.Fatalf("combine: %v", err)
	}
	if string(msg) != "hello committee" {
		t.Fatalf("got %q", msg)
	}
}

func TestRegistryUnconfigured(t *testing.T) {
	st := &mapState{addr: registryAddr, storage: map[common.Hash]common.Hash{}}
	reg := NewRegistry(registryAddr)
	if reg.Configured(st) {
		t.Fatal("empty registry should not be configured")
	}
	if _, err := reg.EonKey(st); err != ErrNoEonKey {
		t.Fatalf("eon key on empty registry: err = %v, want %v", err, ErrNoEonKey)
	}
}

func TestBuildRegistryBadParams(t *testing.T) {
	eon, _, _, _ := threshold.DealerSetup(2, 3, rand.Reader)
	if _, err := BuildRegistryStorage(0, eon, []common.Address{{1}}); err == nil {
		t.Fatal("t=0 accepted")
	}
	if _, err := BuildRegistryStorage(3, eon, []common.Address{{1}}); err == nil {
		t.Fatal("t>n accepted")
	}
}
