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

package encmempool

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/ethereum/go-ethereum/core/privacy/threshold"
)

func TestEnvelopePoolStoresOnlyOpaqueBoundedCiphertext(t *testing.T) {
	if _, err := NewEnvelope(nil); err != ErrEmptyEnvelope {
		t.Fatalf("empty envelope err = %v, want %v", err, ErrEmptyEnvelope)
	}
	if _, err := NewEnvelope(make([]byte, MaxEnvelopeSize+1)); err != ErrEnvelopeTooLarge {
		t.Fatalf("oversize envelope err = %v, want %v", err, ErrEnvelopeTooLarge)
	}

	const thresholdSize, members = 3, 5
	pk, shares, _, err := threshold.DealerSetup(thresholdSize, members, rand.Reader)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	plaintext := []byte("inner transaction RLP that must not be exposed by the pool")
	ct, err := threshold.Encrypt(pk, plaintext, rand.Reader)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	blob, err := ct.Marshal()
	if err != nil {
		t.Fatalf("marshal ciphertext: %v", err)
	}
	env, err := NewEnvelope(blob)
	if err != nil {
		t.Fatalf("envelope: %v", err)
	}

	pool := NewPool(2)
	if !pool.Add(env) {
		t.Fatal("fresh envelope was not accepted")
	}
	if pool.Add(env) {
		t.Fatal("duplicate envelope was accepted")
	}
	got := pool.Get(env.ID())
	if got == nil {
		t.Fatal("stored envelope missing")
	}
	if bytes.Contains(got.Ciphertext, plaintext) {
		t.Fatal("pool exposed plaintext bytes")
	}
	parsed, err := threshold.UnmarshalCiphertext(got.Ciphertext)
	if err != nil {
		t.Fatalf("stored envelope is not a threshold ciphertext: %v", err)
	}
	if _, err := threshold.Combine(thresholdSize, parsed, []*threshold.DecryptionShare{
		shares[0].Decrypt(parsed),
		shares[1].Decrypt(parsed),
	}); err == nil {
		t.Fatal("stored ciphertext decrypted with fewer than threshold shares")
	}
	recovered, err := threshold.Combine(thresholdSize, parsed, []*threshold.DecryptionShare{
		shares[0].Decrypt(parsed),
		shares[1].Decrypt(parsed),
		shares[2].Decrypt(parsed),
	})
	if err != nil {
		t.Fatalf("threshold combine: %v", err)
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("recovered %q, want %q", recovered, plaintext)
	}

	e2, _ := NewEnvelope([]byte("ciphertext-2"))
	e3, _ := NewEnvelope([]byte("ciphertext-3"))
	pool.Add(e2)
	pool.Add(e3)
	if pool.Len() != 2 {
		t.Fatalf("pool len = %d, want 2", pool.Len())
	}
	if pool.Has(env.ID()) {
		t.Fatal("oldest envelope was not evicted")
	}
	pool.Remove(e2.ID())
	if pool.Has(e2.ID()) {
		t.Fatal("removed envelope still present")
	}
}
