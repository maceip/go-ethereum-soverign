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

// Package encmempool implements the encrypted-mempool buffer and envelope for the
// fork's Phase 1 encrypted-mempool work (shape.md: threshold-encryption based).
//
// A user threshold-encrypts an inner transaction to the committee key (see
// core/privacy/threshold), wraps the ciphertext in an Envelope, and gossips the
// envelope. Nodes buffer the still-encrypted envelopes in a Pool. The plaintext is
// recovered only at inclusion time, when a threshold of committee members release
// decryption shares (Stage 3). Until then — and forever, for transactions that are
// never selected — only the opaque ciphertext is stored and propagated, giving the
// "privacy for non-included transactions" property that batched-threshold-
// encryption research targets.
//
// This package is the Stage-2 buffer/envelope: it deliberately holds and moves
// only ciphertext and never attempts decryption, so the privacy property is
// structural. Decryption and block inclusion are Stage 3.
package encmempool

import (
	"errors"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// MaxEnvelopeSize bounds the size of an encrypted envelope's ciphertext, so a peer
// cannot exhaust memory by gossiping oversized blobs.
const MaxEnvelopeSize = 128 * 1024

var (
	// ErrEnvelopeTooLarge is returned for ciphertext exceeding MaxEnvelopeSize.
	ErrEnvelopeTooLarge = errors.New("encmempool: envelope too large")
	// ErrEmptyEnvelope is returned for an envelope with no ciphertext.
	ErrEmptyEnvelope = errors.New("encmempool: empty envelope")
)

// Envelope is a threshold-encrypted transaction awaiting inclusion. It carries
// only the opaque ciphertext; the plaintext inner transaction is never stored.
type Envelope struct {
	Ciphertext []byte    // threshold.Ciphertext marshalling; opaque to the mempool
	received   time.Time // local receipt time, for ordering/eviction
}

// NewEnvelope wraps a marshalled threshold ciphertext. It validates size but never
// inspects the contents.
func NewEnvelope(ciphertext []byte) (*Envelope, error) {
	if len(ciphertext) == 0 {
		return nil, ErrEmptyEnvelope
	}
	if len(ciphertext) > MaxEnvelopeSize {
		return nil, ErrEnvelopeTooLarge
	}
	cp := make([]byte, len(ciphertext))
	copy(cp, ciphertext)
	return &Envelope{Ciphertext: cp, received: time.Now()}, nil
}

// ID is the content hash of the ciphertext, used to identify and deduplicate
// envelopes on the wire and in the buffer.
func (e *Envelope) ID() common.Hash {
	return crypto.Keccak256Hash(e.Ciphertext)
}

// ReceivedAt reports when the envelope was buffered locally.
func (e *Envelope) ReceivedAt() time.Time { return e.received }

// Pool is a bounded, concurrency-safe buffer of pending encrypted envelopes. It
// evicts the oldest envelopes when full. It stores only ciphertext and offers no
// way to decrypt — decryption is the committee's job at inclusion time.
type Pool struct {
	mu    sync.RWMutex
	max   int
	envs  map[common.Hash]*Envelope
	order []common.Hash // FIFO insertion order for eviction
}

// NewPool creates an encrypted-mempool buffer holding at most max envelopes.
func NewPool(max int) *Pool {
	if max < 1 {
		max = 1
	}
	return &Pool{max: max, envs: make(map[common.Hash]*Envelope)}
}

// Add buffers an envelope. It returns true if the envelope was newly added, and
// false if it was already present (deduplicated by content id).
func (p *Pool) Add(e *Envelope) bool {
	id := e.ID()
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.envs[id]; ok {
		return false
	}
	p.envs[id] = e
	p.order = append(p.order, id)
	for len(p.envs) > p.max && len(p.order) > 0 {
		oldest := p.order[0]
		p.order = p.order[1:]
		delete(p.envs, oldest)
	}
	return true
}

// Has reports whether an envelope with the given id is buffered.
func (p *Pool) Has(id common.Hash) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	_, ok := p.envs[id]
	return ok
}

// Get returns the buffered envelope with the given id, or nil.
func (p *Pool) Get(id common.Hash) *Envelope {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.envs[id]
}

// Pending returns the buffered envelopes in insertion order.
func (p *Pool) Pending() []*Envelope {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]*Envelope, 0, len(p.order))
	for _, id := range p.order {
		if e, ok := p.envs[id]; ok {
			out = append(out, e)
		}
	}
	return out
}

// Remove drops an envelope (e.g. once it has been decrypted and included).
func (p *Pool) Remove(id common.Hash) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.envs, id)
}

// Len returns the number of buffered envelopes.
func (p *Pool) Len() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.envs)
}
