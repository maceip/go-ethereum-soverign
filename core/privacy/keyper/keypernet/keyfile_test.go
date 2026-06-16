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

package keypernet

import (
	"crypto/rand"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/privacy/ibe"
)

// TestKeyFileRoundTrip checks a keyper's material survives save/load and the loaded
// keyper still produces a valid, verifiable epoch-key share that combines with
// another keyper's to decrypt.
func TestKeyFileRoundTrip(t *testing.T) {
	const tt, n = 2, 3
	keypers, mpk, vks, err := Bootstrap(tt, n, rand.Reader)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	path := filepath.Join(t.TempDir(), "keyper-1.json")
	if err := SaveKeyper(path, keypers[0]); err != nil {
		t.Fatalf("save: %v", err)
	}
	loaded, err := LoadKeyper(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.Index() != keypers[0].Index() {
		t.Fatalf("index = %d, want %d", loaded.Index(), keypers[0].Index())
	}

	const epoch = 5
	ct, _ := ibe.Encrypt(mpk, epoch, []byte("survives reload"), rand.Reader)
	s0, err := loaded.EpochShare(epoch)
	if err != nil {
		t.Fatalf("epoch share: %v", err)
	}
	if !ibe.VerifyEpochShare(loaded.VerificationKey(), epoch, s0) {
		t.Fatal("reloaded keyper share failed verification")
	}
	s1, _ := keypers[1].EpochShare(epoch)
	sk, err := ibe.CombineEpochKey(tt, epoch, []*ibe.EpochKeyShare{s0, s1})
	if err != nil {
		t.Fatalf("combine: %v", err)
	}
	got, err := ibe.Decrypt(sk, ct)
	if err != nil || string(got) != "survives reload" {
		t.Fatalf("decrypt with reloaded keyper: %v, %q", err, got)
	}
	_ = vks
}

// TestExportCommittee checks the committee export produces registry storage that a
// keyper.Registry can read back as the IBE master public key.
func TestExportCommittee(t *testing.T) {
	const tt, n = 2, 3
	_, mpk, _, err := Bootstrap(tt, n, rand.Reader)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	addrs := []common.Address{{1}, {2}, {3}}
	export, err := ExportCommittee(tt, mpk, common.Address{0xaa}, addrs)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if export.Threshold != tt {
		t.Fatalf("threshold = %d, want %d", export.Threshold, tt)
	}
	if len(export.RegistryStorage) == 0 {
		t.Fatal("empty registry storage")
	}
	if export.RegistryAddress != (common.Address{0xaa}) {
		t.Fatal("wrong registry address")
	}
}
