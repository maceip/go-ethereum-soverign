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
	dleproto "github.com/ethereum/go-ethereum/eth/protocols/dandelion"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/p2p/dandelion"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

// This file wires the Dandelion++ router (p2p/dandelion) and the `dle` stem
// sub-protocol (eth/protocols/dandelion) into the live eth transaction path.
// Dandelion++ is a Phase 1 ("Early MEV Protection & Network Privacy") requirement
// of the fork's privacy roadmap: it obscures the network origin of locally-
// submitted transactions.
//
// Flow:
//
//   - Locally-originated transactions (RPC/wallet submissions, see markLocalTx)
//     are recorded in localOrigins. When the txpool emits them, stemTransactions
//     routes them as the originator: the originator never diffuses by chance — it
//     relays the full transaction to a stem successor over the `dle` protocol, or
//     diffuses only when no stem successor exists. Local-origin status persists
//     until a fluff sighting, so re-broadcasts keep stemming rather than leaking
//     the origin.
//   - A transaction received over `dle` arrived in the stem phase. relayStem
//     routes it as a relay: it either continues the stem to its own successor (and
//     arms its own embargo) or transitions it to fluff by admitting it to the
//     local pool, which diffuses it via ordinary eth gossip.
//   - Receiving a transaction (or announcement) via ordinary eth gossip is a fluff
//     sighting: it cancels the embargo, releases any held copy, and stops the
//     origin from re-stemming (markFluffed).
//   - A background loop (dandelionLoop) is the black-hole failsafe: it diffuses
//     stemmed transactions whose embargo elapses without a fluff sighting, and
//     keeps the router's eligible-successor set in sync with the live `dle` peers.
//
// Dandelion++ is feature-gated (handler.dandelion is nil when disabled) and
// tunable without any consensus change.

// Dandelion++ propagation metrics.
var (
	dandelionStemMeter         = metrics.NewRegisteredMeter("eth/dandelion/stem", nil)
	dandelionRelayMeter        = metrics.NewRegisteredMeter("eth/dandelion/relay", nil)
	dandelionFluffMeter        = metrics.NewRegisteredMeter("eth/dandelion/fluff", nil)
	dandelionEmbargoMeter      = metrics.NewRegisteredMeter("eth/dandelion/embargo", nil)
	dandelionPeerFallbackMeter = metrics.NewRegisteredMeter("eth/dandelion/peerfallback", nil)
)

const (
	// dandelionOriginTTL bounds how long a locally-submitted transaction hash is
	// remembered as local-origin. While remembered, every (re-)broadcast of the
	// transaction is stemmed rather than diffused; the entry is cleared earlier on
	// a fluff sighting. The TTL is the safety net against unbounded growth and
	// against transactions that are dropped before they are ever included.
	dandelionOriginTTL = 10 * time.Minute

	// dandelionOriginMax caps the number of outstanding local-origin hashes.
	dandelionOriginMax = 16384

	// dandelionHoldMax caps the number of relay-held stem transactions awaiting a
	// fluff sighting or embargo expiry.
	dandelionHoldMax = 16384
)

// originTracker remembers the hashes of transactions that originated on this node
// so the broadcast path can keep routing them through the stem phase. Unlike a
// consume-once set, an entry persists until it is explicitly cleared (on a fluff
// sighting) or its TTL elapses, so repeated broadcasts of the same local
// transaction never fall back to diffusing it from the origin. It is safe for
// concurrent use and bounds its memory with both a TTL and a hard size cap.
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

// mark records (or refreshes) a hash as locally originated.
func (t *originTracker) mark(hash common.Hash) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.gc(t.clock())
	if _, ok := t.entries[hash]; ok {
		t.entries[hash] = t.clock().Add(t.ttl) // refresh TTL on re-submission
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

// isLocal reports whether the hash is currently a live local-origin entry without
// removing it, so repeated broadcasts of the same transaction keep stemming.
func (t *originTracker) isLocal(hash common.Hash) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	deadline, ok := t.entries[hash]
	if !ok {
		return false
	}
	if t.clock().After(deadline) {
		delete(t.entries, hash)
		return false
	}
	return true
}

// clear forgets a local-origin hash (e.g. once it has been seen fluffing).
func (t *originTracker) clear(hash common.Hash) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.entries, hash)
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
			continue // already cleared
		}
		if now.After(deadline) {
			delete(t.entries, hash)
			continue
		}
		kept = append(kept, hash)
	}
	t.order = kept
}

// stemHoldSet holds the full transactions that this node is relaying in the stem
// phase but has not admitted to its local pool. They are kept so the embargo
// failsafe can diffuse them if the stem turns out to be a black hole. It is safe
// for concurrent use and bounded by a hard size cap.
type stemHoldSet struct {
	mu    sync.Mutex
	max   int
	txs   map[common.Hash]*types.Transaction
	order []common.Hash
}

func newStemHoldSet() *stemHoldSet {
	return &stemHoldSet{max: dandelionHoldMax, txs: make(map[common.Hash]*types.Transaction)}
}

func (s *stemHoldSet) add(tx *types.Transaction) {
	s.mu.Lock()
	defer s.mu.Unlock()

	hash := tx.Hash()
	if _, ok := s.txs[hash]; ok {
		return
	}
	s.txs[hash] = tx
	s.order = append(s.order, hash)
	for len(s.txs) > s.max && len(s.order) > 0 {
		oldest := s.order[0]
		s.order = s.order[1:]
		delete(s.txs, oldest)
	}
}

func (s *stemHoldSet) get(hash common.Hash) *types.Transaction {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.txs[hash]
}

func (s *stemHoldSet) remove(hash common.Hash) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.txs, hash)
}

// markLocalTx records that a transaction originated on this node (e.g. via an RPC
// submission). It is a no-op when Dandelion++ is disabled.
func (h *handler) markLocalTx(hash common.Hash) {
	if h.localOrigins == nil {
		return
	}
	h.localOrigins.mark(hash)
}

// isLocalTx reports whether the transaction originated locally. It returns false
// when Dandelion++ is disabled.
func (h *handler) isLocalTx(hash common.Hash) bool {
	if h.localOrigins == nil {
		return false
	}
	return h.localOrigins.isLocal(hash)
}

// withholdFromSync reports whether a transaction must be withheld from initial
// mempool syncing to a freshly-connected peer because it is a locally-originated
// transaction still in the Dandelion++ stem phase. Announcing it would reveal this
// node as its origin; once it is seen fluffing it is announced normally.
func (h *handler) withholdFromSync(hash common.Hash) bool {
	return h.dandelion != nil && h.isLocalTx(hash)
}

// markFluffed records that the given transactions have been seen propagating via
// normal diffusion: it cancels any local embargo failsafe, releases any held copy,
// and stops the origin from re-stemming them. No-op when Dandelion++ is disabled.
func (h *handler) markFluffed(hashes ...common.Hash) {
	if h.dandelion == nil {
		return
	}
	for _, hash := range hashes {
		h.dandelion.MarkFluffed(hash)
		h.stemHold.remove(hash)
		h.localOrigins.clear(hash)
	}
}

// dandelionPeer returns the connected `dle` peer with the given node id, or nil.
func (h *handler) dandelionPeer(id enode.ID) *dleproto.Peer {
	h.dandelionPeerLock.RLock()
	defer h.dandelionPeerLock.RUnlock()
	if info := h.dandelionPeers[id]; info != nil {
		return info.peer
	}
	return nil
}

// registerDandelionPeer records a `dle` peer together with the connection metadata
// used to harden stem-successor selection against eclipse / connection-reset
// attacks, then refreshes the eligible-successor set.
func (h *handler) registerDandelionPeer(peer *dleproto.Peer) {
	info := &dlePeerInfo{
		peer:        peer,
		connectedAt: time.Now(),
		inbound:     peer.Inbound(),
	}
	if node := peer.Node(); node != nil {
		info.ip = node.IP()
	}
	h.dandelionPeerLock.Lock()
	h.dandelionPeers[peer.ID()] = info
	h.dandelionPeerLock.Unlock()
	h.updateDandelionPeers()
}

// unregisterDandelionPeer removes a `dle` peer, records the disconnection for
// connection-reset / eclipse detection, and refreshes the eligible-successor set.
func (h *handler) unregisterDandelionPeer(id enode.ID) {
	h.dandelionPeerLock.Lock()
	_, existed := h.dandelionPeers[id]
	delete(h.dandelionPeers, id)
	h.dandelionPeerLock.Unlock()
	if existed {
		h.recordDandelionChurn()
	}
	h.updateDandelionPeers()
}

// updateDandelionPeers refreshes the router's set of eligible stem successors from
// the live `dle` peers, applying eclipse/connection-reset hardening (stability
// gating, subnet diversity, outbound preference). Only peers that speak the stem
// sub-protocol can continue a stem. Invoked on `dle` peer connect/disconnect and
// from the embargo loop.
func (h *handler) updateDandelionPeers() {
	if h.dandelion == nil {
		return
	}
	h.dandelionPeerLock.RLock()
	infos := make([]*dlePeerInfo, 0, len(h.dandelionPeers))
	for _, info := range h.dandelionPeers {
		infos = append(infos, info)
	}
	h.dandelionPeerLock.RUnlock()

	h.dandelion.SetPeers(eligibleStemPeers(infos, time.Now(), h.dandelionCfg.StemPeerMinAge))
}

// stemTransactions applies Dandelion++ origin routing to a batch of transactions
// about to be broadcast. Locally-originated, diffusible transactions are routed as
// the originator: they are relayed to a stem successor over the `dle` protocol and
// dropped from the diffusion set, or returned for ordinary diffusion when no stem
// successor is available. Every other transaction is returned unchanged.
func (h *handler) stemTransactions(txs types.Transactions) types.Transactions {
	h.updateDandelionPeers()

	diffuse := make(types.Transactions, 0, len(txs))
	for _, tx := range txs {
		hash := tx.Hash()
		// Only locally-originated, normally-diffusible transactions are eligible
		// for stem routing. Blob and oversized transactions are announce-only on
		// the wire, and remote transactions must keep diffusing to stay live.
		if tx.Type() == types.BlobTxType || tx.Size() > txMaxBroadcastSize || !h.isLocalTx(hash) {
			diffuse = append(diffuse, tx)
			continue
		}
		// The originator never applies the fluff coin (Route originator=true), so a
		// local transaction is never diffused from the source by chance.
		action := h.dandelion.Route(hash, true, enode.ID{})
		if action.Phase == dandelion.PhaseFluff {
			dandelionFluffMeter.Mark(1)
			diffuse = append(diffuse, tx)
			continue
		}
		peer := h.dandelionPeer(action.Relay)
		if peer == nil {
			// The chosen successor has gone away. Cancel the embargo we just armed
			// and fall back to diffusion so the transaction is never black-holed.
			dandelionPeerFallbackMeter.Mark(1)
			h.dandelion.MarkFluffed(hash)
			diffuse = append(diffuse, tx)
			continue
		}
		peer.SendStemTransactions([]*types.Transaction{tx})
		dandelionStemMeter.Mark(1)
	}
	return diffuse
}

// relayStemTransactions handles transactions that arrived from peer `from` in the
// stem phase over the `dle` protocol. Each transaction is routed as a relay: it
// either continues the stem to this node's own successor (held locally so the
// embargo failsafe can recover a black hole) or transitions to fluff by being
// admitted to the local pool, which diffuses it via ordinary eth gossip.
func (h *handler) relayStemTransactions(from enode.ID, txs []*types.Transaction) error {
	if h.dandelion == nil {
		return nil
	}
	h.updateDandelionPeers()

	var fluff types.Transactions
	for _, tx := range txs {
		hash := tx.Hash()
		// If we already hold the transaction in our pool it is (or is about to be)
		// diffusing; there is nothing left to stem.
		if h.txpool.Has(hash) {
			continue
		}
		// Route as a relay, excluding the sender so we never forward straight back.
		action := h.dandelion.Route(hash, false, from)
		if action.Phase == dandelion.PhaseStem {
			if peer := h.dandelionPeer(action.Relay); peer != nil {
				peer.SendStemTransactions([]*types.Transaction{tx})
				h.stemHold.add(tx)
				dandelionRelayMeter.Mark(1)
				continue
			}
		}
		// Fluff transition (or no safe successor): cancel any embargo armed by
		// Route, release any held copy, and diffuse by admitting the transaction to
		// the local pool.
		h.dandelion.MarkFluffed(hash)
		h.stemHold.remove(hash)
		fluff = append(fluff, tx)
		dandelionFluffMeter.Mark(1)
	}
	if len(fluff) > 0 {
		h.txpool.Add(fluff, false)
	}
	return nil
}

// dandelionLoop diffuses transactions whose embargo timer has elapsed without a
// fluff sighting (the Dandelion++ black-hole failsafe) and keeps the router's
// eligible-successor set in sync. It runs until the handler shuts down.
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
			// Originator-held transactions are already in the pool and only need to
			// be diffused; relay-held transactions must be admitted to the pool,
			// which diffuses them through the normal broadcast path.
			var (
				diffuse types.Transactions
				admit   types.Transactions
			)
			for _, hash := range expired {
				if tx := h.txpool.Get(hash); tx != nil {
					diffuse = append(diffuse, tx)
				} else if tx := h.stemHold.get(hash); tx != nil {
					admit = append(admit, tx)
				}
				h.stemHold.remove(hash)
			}
			if n := len(diffuse) + len(admit); n > 0 {
				dandelionEmbargoMeter.Mark(int64(n))
				log.Debug("Diffusing embargoed transactions", "count", n)
			}
			if len(admit) > 0 {
				h.txpool.Add(admit, false)
			}
			if len(diffuse) > 0 {
				h.diffuseTransactions(diffuse)
			}
		case <-h.quitSync:
			return
		}
	}
}

// dandelionHandler implements the `dle` sub-protocol Backend on top of the eth
// handler. It is the satellite that delivers stem-phase transactions and keeps the
// stem-successor set populated.
type dandelionHandler handler

// RunPeer registers a `dle` peer for the duration of its connection.
func (h *dandelionHandler) RunPeer(peer *dleproto.Peer, hand dleproto.Handler) error {
	(*handler)(h).registerDandelionPeer(peer)
	defer (*handler)(h).unregisterDandelionPeer(peer.ID())
	return hand(peer)
}

// PeerInfo implements the `dle` Backend; the protocol exposes no extra peer info.
func (h *dandelionHandler) PeerInfo(id enode.ID) interface{} { return nil }

// HandleStemTransactions implements the `dle` Backend: it routes stem-phase
// transactions through the handler's Dandelion++ relay logic.
func (h *dandelionHandler) HandleStemTransactions(peer *dleproto.Peer, txs []*types.Transaction) error {
	return (*handler)(h).relayStemTransactions(peer.ID(), txs)
}
