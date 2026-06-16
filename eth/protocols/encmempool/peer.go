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
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p"
)

const (
	// maxQueuedEnvelopeBatches bounds the per-peer send queue.
	maxQueuedEnvelopeBatches = 128
	// maxKnownEnvelopes bounds the per-peer set of envelopes known to have been
	// sent to or received from the peer (loop/duplicate suppression).
	maxKnownEnvelopes = 8192
)

// Peer is a connection to a remote node speaking the `enc` protocol.
type Peer struct {
	*p2p.Peer
	rw      p2p.MsgReadWriter
	version uint
	logger  log.Logger

	queue chan [][]byte
	term  chan struct{}

	knownMu sync.Mutex
	known   map[common.Hash]struct{} // envelope ids known to this peer
}

// NewPeer wraps a p2p connection and starts the envelope broadcaster.
func NewPeer(version uint, p *p2p.Peer, rw p2p.MsgReadWriter) *Peer {
	peer := &Peer{
		Peer:    p,
		rw:      rw,
		version: version,
		logger:  log.New("peer", p.ID()),
		queue:   make(chan [][]byte, maxQueuedEnvelopeBatches),
		term:    make(chan struct{}),
		known:   make(map[common.Hash]struct{}),
	}
	go peer.broadcastLoop()
	return peer
}

// Version returns the negotiated protocol version.
func (p *Peer) Version() uint { return p.version }

// Log returns the peer's contextual logger.
func (p *Peer) Log() log.Logger { return p.logger }

// Close stops the broadcaster. It must be called exactly once at teardown.
func (p *Peer) Close() { close(p.term) }

// MarkKnown records that the peer is known to have the given envelope id, so it is
// not sent there again.
func (p *Peer) MarkKnown(id common.Hash) {
	p.knownMu.Lock()
	defer p.knownMu.Unlock()
	if len(p.known) >= maxKnownEnvelopes {
		// Evict an arbitrary entry to bound memory.
		for k := range p.known {
			delete(p.known, k)
			break
		}
	}
	p.known[id] = struct{}{}
}

// Knows reports whether the envelope id is already known to this peer.
func (p *Peer) Knows(id common.Hash) bool {
	p.knownMu.Lock()
	defer p.knownMu.Unlock()
	_, ok := p.known[id]
	return ok
}

// broadcastLoop drains queued envelope batches to the remote peer.
func (p *Peer) broadcastLoop() {
	for {
		select {
		case batch := <-p.queue:
			if err := p2p.Send(p.rw, EnvelopesMsg, EnvelopesPacket(batch)); err != nil {
				p.logger.Debug("Failed to send envelopes", "count", len(batch), "err", err)
				return
			}
		case <-p.term:
			return
		}
	}
}

// SendEnvelopes queues a batch of envelope ciphertexts for delivery. It never
// blocks: if the queue is full the batch is dropped (the sender's pool retains the
// envelopes and they will re-propagate on the next gossip round).
func (p *Peer) SendEnvelopes(batch [][]byte) {
	select {
	case p.queue <- batch:
	case <-p.term:
	default:
		p.logger.Debug("Dropping envelope batch, queue full", "count", len(batch))
	}
}
