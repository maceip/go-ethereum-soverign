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

package dandelion

import (
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p"
)

// maxQueuedStemTxs is the number of stem-transaction batches buffered for a peer
// before further batches are dropped (the embargo failsafe will then diffuse them).
const maxQueuedStemTxs = 128

// Peer is a collection of relevant information we have about a `dle` peer.
type Peer struct {
	*p2p.Peer                           // The embedded P2P package peer
	rw        p2p.MsgReadWriter         // Input/output streams for the `dle` protocol
	version   uint                      // Negotiated `dle` protocol version
	logger    log.Logger                // Contextual logger with the peer id injected
	queue     chan []*types.Transaction // Queue of stem-transaction batches to send
	term      chan struct{}             // Termination channel to stop the broadcaster
}

// NewPeer creates a wrapper for a network connection and negotiated protocol
// version, and starts the peer's stem-transaction broadcaster.
func NewPeer(version uint, p *p2p.Peer, rw p2p.MsgReadWriter) *Peer {
	peer := &Peer{
		Peer:    p,
		rw:      rw,
		version: version,
		logger:  log.New("peer", p.ID()),
		queue:   make(chan []*types.Transaction, maxQueuedStemTxs),
		term:    make(chan struct{}),
	}
	go peer.broadcastLoop()
	return peer
}

// Version retrieves the peer's negotiated `dle` protocol version.
func (p *Peer) Version() uint { return p.version }

// Log overrides the P2P logger with the higher-level one containing only the id.
func (p *Peer) Log() log.Logger { return p.logger }

// Close signals the broadcaster to stop. It must be called exactly once when the
// peer is torn down.
func (p *Peer) Close() { close(p.term) }

// broadcastLoop drains queued stem-transaction batches and writes them to the
// remote peer, exiting on send error or termination.
func (p *Peer) broadcastLoop() {
	for {
		select {
		case txs := <-p.queue:
			if err := p2p.Send(p.rw, StemTransactionsMsg, StemTransactionsPacket(txs)); err != nil {
				p.logger.Debug("Failed to send stem transactions", "count", len(txs), "err", err)
				return
			}
			p.logger.Trace("Relayed stem transactions", "count", len(txs))
		case <-p.term:
			return
		}
	}
}

// SendStemTransactions queues a batch of stem-phase transactions for relay to this
// peer. It never blocks: if the peer's queue is full the batch is dropped, and the
// stemming node's embargo failsafe will diffuse the transactions instead.
func (p *Peer) SendStemTransactions(txs []*types.Transaction) {
	select {
	case p.queue <- txs:
	case <-p.term:
	default:
		p.logger.Debug("Dropping stem transactions, queue full", "count", len(txs))
	}
}
