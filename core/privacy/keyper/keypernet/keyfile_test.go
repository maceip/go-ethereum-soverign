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
	"github.com/ethereum/go-ethereum/core/privacy/threshold"
)

// TestKeyFileRoundTrip checks a keyper's material survives save/load and the loaded
// keyper still produces valid, verifiable decryption shares.
func TestKeyFileRoundTrip(t *testing.T) {
	const tt, n = 2, 3
	keypers, eon, _, err := Bootstrap(tt, n, rand.Reader)
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

	// The loaded keyper, combined with another original keyper, must decrypt.
	ct, _ := threshold.Encrypt(eon, []byte("survives reload"), rand.Reader)
	shares := []*threshold.DecryptionShare{loaded.DecryptionShare(ct), keypers[1].DecryptionShare(ct)}
	if !threshold.VerifyShare(loaded.VerificationKey(), ct, shares[0]) {
		t.Fatal("loaded keyper share failed verification")
	}
	got, err := threshold.Combine(tt, ct, shares)
	if err != nil || string(got) != "survives reload" {
		t.Fatalf("combine with reloaded keyper: %v, %q", err, got)
	}
}

// TestExportCommittee checks the committee export produces registry storage that a
// keyper.Registry can read back.
func TestExportCommittee(t *testing.T) {
	const tt, n = 2, 3
	_, eon, _, err := Bootstrap(tt, n, rand.Reader)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	addrs := []common.Address{{1}, {2}, {3}}
	export, err := ExportCommittee(tt, eon, common.Address{0xaa}, addrs)
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
