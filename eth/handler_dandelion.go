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

package eth

import (
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/p2p/dandelion"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

// This file wires the Dandelion++ router (p2p/dandelion) into the live eth
// transaction-propagation path. Dandelion++ is a Phase 1 ("Early MEV Protection
// & Network Privacy") requirement of the fork's privacy roadmap: it obscures the
// network origin of locally-submitted transactions so a well-connected adversary
// observing announcement timings cannot localise the originating node.
//
// The high-level flow is:
//
//   - Locally-originated transactions (RPC/wallet submissions, see markLocalTx)
//     are recorded in localOrigins. When the txpool emits them through the normal
//     NewTxsEvent path, stemTransactions consults the router: it either relays the
//     full transaction to a single per-epoch successor peer (stem phase) or hands
//     it back for ordinary diffusion (fluff phase).
//   - Transactions received from peers are not in localOrigins, so they always
//     diffuse normally. Receiving a transaction (or its announcement) via gossip
//     is treated as a "fluff sighting" and cancels any embargo this node holds for
//     that hash (markFluffed).
//   - A background loop (dandelionLoop) diffuses transactions whose embargo timer
//     elapses without a fluff sighting, providing the Dandelion++ black-hole
//     failsafe, and keeps the router's eligible-peer set in sync.
//
// Dandelion++ is feature-gated (handler.dandelion is nil when disabled) and
// tunable without any consensus change.

// Dandelion++ propagation metrics.
var (
	dandelionStemMeter         = metrics.NewRegisteredMeter("eth/dandelion/stem", nil)
	dandelionFluffMeter        = metrics.NewRegisteredMeter("eth/dandelion/fluff", nil)
	dandelionEmbargoMeter      = metrics.NewRegisteredMeter("eth/dandelion/embargo", nil)
	dandelionPeerFallbackMeter = metrics.NewRegisteredMeter("eth/dandelion/peerfallback", nil)
)

const (
	// dandelionOriginTTL bounds how long a locally-submitted transaction hash is
	// remembered as local-origin while it waits to surface through the txpool's
	// NewTxsEvent feed. Entries are consumed on first broadcast; this TTL only
	// reclaims hashes for transactions the pool rejected or never accepted.
	dandelionOriginTTL = 5 * time.Minute

	// dandelionOriginMax caps the number of outstanding local-origin hashes so a
	// flood of rejected submissions cannot grow the tracker without bound.
	dandelionOriginMax = 8192
)

// originTracker remembers the hashes of transactions that originated on this node
// so the broadcast path can decide whether a transaction should enter the stem
// phase. It is safe for concurrent use, and bounds its memory with both a TTL and
// a hard size cap.
type originTracker struct {
	mu      sync.Mutex
	clock   func() time.Time
	ttl     time.Duration
	max     int
	entries map[common.Hash]time.Time
	order   []common.Hash // insertion order, for FIFO eviction over the cap
}

func newOriginTracker() *originTracker {
	return &originTracker{
		clock:   time.Now,
		ttl:     dandelionOriginTTL,
		max:     dandelionOriginMax,
		entries: make(map[common.Hash]time.Time),
	}
}

// mark records a hash as locally originated.
func (t *originTracker) mark(hash common.Hash) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.gc(t.clock())
	if _, ok := t.entries[hash]; ok {
		return
	}
	t.entries[hash] = t.clock().Add(t.ttl)
	t.order = append(t.order, hash)

	// Enforce the hard cap by evicting the oldest still-live entries.
	for len(t.entries) > t.max && len(t.order) > 0 {
		oldest := t.order[0]
		t.order = t.order[1:]
		delete(t.entries, oldest)
	}
}

// consume reports whether the hash was locally originated, removing it so that a
// transaction stems only on its first broadcast (re-broadcasts diffuse normally).
func (t *originTracker) consume(hash common.Hash) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	deadline, ok := t.entries[hash]
	if !ok {
		return false
	}
	delete(t.entries, hash)
	return !t.clock().After(deadline)
}

// gc drops expired entries. The caller must hold t.mu.
func (t *originTracker) gc(now time.Time) {
	if len(t.order) == 0 {
		return
	}
	kept := t.order[:0]
	for _, hash := range t.order {
		deadline, ok := t.entries[hash]
		if !ok {
			continue // already consumed
		}
		if now.After(deadline) {
			delete(t.entries, hash)
			continue
		}
		kept = append(kept, hash)
	}
	t.order = kept
}

// markLocalTx records that a transaction originated on this node (e.g. via an RPC
// submission). It is a no-op when Dandelion++ is disabled.
func (h *handler) markLocalTx(hash common.Hash) {
	if h.localOrigins == nil {
		return
	}
	h.localOrigins.mark(hash)
}

// consumeLocalOrigin reports whether the transaction originated locally, consuming
// the record. It returns false when Dandelion++ is disabled.
func (h *handler) consumeLocalOrigin(hash common.Hash) bool {
	if h.localOrigins == nil {
		return false
	}
	return h.localOrigins.consume(hash)
}

// markFluffed records that the given transactions have been seen propagating via
// normal diffusion, cancelling any local embargo failsafe for them. It is a no-op
// when Dandelion++ is disabled.
func (h *handler) markFluffed(hashes ...common.Hash) {
	if h.dandelion == nil {
		return
	}
	for _, hash := range hashes {
		h.dandelion.MarkFluffed(hash)
	}
}

// updateDandelionPeers refreshes the router's set of eligible stem successors from
// the live peer set. It is invoked on peer connect/disconnect and periodically
// from the embargo loop, so successor selection always ranges over reachable peers.
func (h *handler) updateDandelionPeers() {
	if h.dandelion == nil {
		return
	}
	peers := h.peers.all()
	ids := make([]enode.ID, 0, len(peers))
	for _, p := range peers {
		ids = append(ids, p.Node().ID())
	}
	h.dandelion.SetPeers(ids)
}

// stemTransactions applies Dandelion++ routing to a batch of transactions about to
// be broadcast. Locally-originated, diffusible transactions that route into the
// stem phase are relayed to a single successor peer here; every other transaction
// (remote, blob, oversized, or routed into the fluff phase) is returned for the
// caller to diffuse normally.
func (h *handler) stemTransactions(txs types.Transactions) types.Transactions {
	// Keep the eligible-peer view fresh so a successor is chosen from live peers.
	h.updateDandelionPeers()

	diffuse := make(types.Transactions, 0, len(txs))
	for _, tx := range txs {
		// Only locally-originated, normally-diffusible transactions are eligible
		// for stem routing. Blob and oversized transactions are announce-only on
		// the wire, and remote transactions must keep diffusing to stay live.
		if tx.Type() == types.BlobTxType || tx.Size() > txMaxBroadcastSize || !h.consumeLocalOrigin(tx.Hash()) {
			diffuse = append(diffuse, tx)
			continue
		}
		hash := tx.Hash()
		action := h.dandelion.Route(hash)
		if action.Phase == dandelion.PhaseFluff {
			dandelionFluffMeter.Mark(1)
			diffuse = append(diffuse, tx)
			continue
		}
		// Stem phase: relay the full transaction to the single epoch successor.
		peer := h.peers.peerByNode(action.Relay)
		if peer == nil {
			// The chosen successor has gone away. Cancel the embargo we just armed
			// and fall back to diffusion so the transaction is never black-holed.
			dandelionPeerFallbackMeter.Mark(1)
			h.dandelion.MarkFluffed(hash)
			diffuse = append(diffuse, tx)
			continue
		}
		if peer.KnownTransaction(hash) {
			// The successor already has the transaction, so it is already
			// propagating. Leave the embargo armed as a failsafe and do not diffuse
			// from here, preserving origin privacy.
			dandelionStemMeter.Mark(1)
			continue
		}
		peer.AsyncSendTransactions([]common.Hash{hash})
		dandelionStemMeter.Mark(1)
	}
	return diffuse
}

// dandelionLoop diffuses transactions whose embargo timer has elapsed without a
// fluff sighting (the Dandelion++ black-hole failsafe) and keeps the router's
// eligible-peer set in sync. It runs until the handler shuts down.
func (h *handler) dandelionLoop() {
	defer h.wg.Done()

	interval := h.dandelionCfg.EmbargoBase / 2
	if interval < 50*time.Millisecond {
		interval = 50 * time.Millisecond
	}
	if interval > 2*time.Second {
		interval = 2 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			h.updateDandelionPeers()

			expired := h.dandelion.ExpiredEmbargoes()
			if len(expired) == 0 {
				continue
			}
			// Resolve the still-pending transactions and diffuse them normally.
			txs := make(types.Transactions, 0, len(expired))
			for _, hash := range expired {
				if tx := h.txpool.Get(hash); tx != nil {
					txs = append(txs, tx)
				}
			}
			if len(txs) > 0 {
				dandelionEmbargoMeter.Mark(int64(len(txs)))
				log.Debug("Diffusing embargoed transactions", "count", len(txs))
				h.diffuseTransactions(txs)
			}
		case <-h.quitSync:
			return
		}
	}
}
