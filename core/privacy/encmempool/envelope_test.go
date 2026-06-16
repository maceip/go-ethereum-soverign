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

func TestEnvelopeValidation(t *testing.T) {
	if _, err := NewEnvelope(nil); err != ErrEmptyEnvelope {
		t.Fatalf("empty envelope: err = %v, want %v", err, ErrEmptyEnvelope)
	}
	if _, err := NewEnvelope(make([]byte, MaxEnvelopeSize+1)); err != ErrEnvelopeTooLarge {
		t.Fatalf("oversize envelope: err = %v, want %v", err, ErrEnvelopeTooLarge)
	}
	if _, err := NewEnvelope([]byte{0x01}); err != nil {
		t.Fatalf("valid envelope rejected: %v", err)
	}
}

func TestPoolDedupAndEviction(t *testing.T) {
	p := NewPool(2)
	e1, _ := NewEnvelope([]byte("ct-1"))
	e2, _ := NewEnvelope([]byte("ct-2"))
	e3, _ := NewEnvelope([]byte("ct-3"))

	if !p.Add(e1) {
		t.Fatal("first add should be new")
	}
	if p.Add(e1) {
		t.Fatal("duplicate add should be rejected")
	}
	if !p.Has(e1.ID()) {
		t.Fatal("pool should contain e1")
	}

	p.Add(e2)
	p.Add(e3) // exceeds cap of 2 -> evicts oldest (e1)
	if p.Len() != 2 {
		t.Fatalf("pool len = %d, want 2", p.Len())
	}
	if p.Has(e1.ID()) {
		t.Fatal("oldest envelope should have been evicted")
	}
	if !p.Has(e2.ID()) || !p.Has(e3.ID()) {
		t.Fatal("newer envelopes should be retained")
	}

	p.Remove(e2.ID())
	if p.Has(e2.ID()) {
		t.Fatal("removed envelope still present")
	}
}

// TestNonIncludedStaysEncrypted is the core privacy property of the encrypted
// mempool: a buffered envelope that is never selected for inclusion exposes only
// ciphertext. Its plaintext is unrecoverable from the pool alone and requires a
// threshold of committee decryption shares.
func TestNonIncludedStaysEncrypted(t *testing.T) {
	const tt, n = 3, 5
	pk, shares, _, err := threshold.DealerSetup(tt, n, rand.Reader)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	plaintext := []byte("inner transaction RLP that must stay private until inclusion")
	ct, err := threshold.Encrypt(pk, plaintext, rand.Reader)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	blob, err := ct.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	env, err := NewEnvelope(blob)
	if err != nil {
		t.Fatalf("envelope: %v", err)
	}

	pool := NewPool(16)
	pool.Add(env)

	// What the pool exposes for a never-included envelope is exactly the
	// ciphertext, which must not contain the plaintext.
	got := pool.Get(env.ID())
	if got == nil {
		t.Fatal("envelope missing from pool")
	}
	if bytes.Contains(got.Ciphertext, plaintext) {
		t.Fatal("plaintext leaked into the buffered ciphertext")
	}

	// The plaintext is recoverable only with a threshold of committee shares.
	parsed, err := threshold.UnmarshalCiphertext(got.Ciphertext)
	if err != nil {
		t.Fatalf("unmarshal ciphertext: %v", err)
	}
	dshares := []*threshold.DecryptionShare{
		shares[0].Decrypt(parsed),
		shares[1].Decrypt(parsed),
		shares[2].Decrypt(parsed),
	}
	recovered, err := threshold.Combine(tt, parsed, dshares)
	if err != nil {
		t.Fatalf("combine: %v", err)
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("recovered %q, want %q", recovered, plaintext)
	}
}
