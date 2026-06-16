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

// Package dandelion implements the Dandelion++ transaction-propagation routing
// logic called for by Phase 1 ("Early MEV Protection & Network Privacy") of the
// Ethereum Privacy roadmap:
//
//	"Network-level anonymity: Integrate or encourage protocols like Dandelion++ to
//	 obscure transaction origins at the peer-to-peer level, mitigating IP address
//	 tracing and censorship."
//
// Standard Ethereum transaction gossip broadcasts a new transaction to many peers
// immediately ("diffusion"). Because the originating node is the first to announce,
// a well-connected adversary observing announcement timings can localise the source
// IP and de-anonymise the sender. Dandelion++ defends against this by splitting
// propagation into two phases:
//
//   - Stem phase ("anonymity phase"): the transaction is forwarded along a single,
//     pseudo-random line of relays. Each node on the line forwards to a fixed
//     successor, so no node (other than the immediate predecessor) can tell whether
//     its sender originated the transaction or merely relayed it.
//   - Fluff phase ("spreading phase"): at a random point the line transitions to
//     ordinary diffusion and the transaction floods the network normally.
//
// The successor mapping is fixed per epoch (re-randomised periodically) to prevent
// an adversary from averaging over many independent routings to locate the source.
// An embargo timer provides a failsafe: if a node that stemmed a transaction never
// observes it return via fluff, it fluffs the transaction itself, defeating
// black-hole attacks.
//
// Two properties are essential to the anonymity guarantee and are enforced here:
//
//   - The originator never applies the stem/fluff coin at its own hop: a locally
//     originated transaction always enters the stem phase when a successor exists,
//     so it is never diffused directly from the source by random chance. Only relay
//     hops flip the coin.
//   - More than one successor is chosen per epoch (deterministically, as a function
//     of the local node, the epoch, and the eligible-peer set), so a single
//     malicious or failed successor cannot observe or black-hole all of a node's
//     stem traffic for the whole epoch.
//
// This package contains only the routing decision logic and is deliberately
// transport-agnostic: callers wire the Relay and Broadcast actions into their
// existing transaction send paths (in this fork, a dedicated `dle` sub-protocol
// carries the explicit stem signal so honest relays can continue the stem).
package dandelion

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"sort"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

// Phase identifies which propagation phase a transaction is in.
type Phase uint8

const (
	// PhaseStem means the transaction should be relayed to a single successor.
	PhaseStem Phase = iota
	// PhaseFluff means the transaction should be diffused (broadcast) to all peers.
	PhaseFluff
)

func (p Phase) String() string {
	if p == PhaseStem {
		return "stem"
	}
	return "fluff"
}

// Action is the routing decision the caller must carry out for a transaction.
type Action struct {
	Phase Phase
	// Relay is the chosen stem successor when Phase == PhaseStem. It is the zero
	// value otherwise.
	Relay enode.ID
}

// Config tunes the Dandelion++ state machine. The zero value is not valid; use
// DefaultConfig and override as needed.
type Config struct {
	// StemProbability is the per-relay probability of remaining in the stem phase
	// (i.e. 1-StemProbability is the chance of switching to fluff at each relay
	// hop). The reference Dandelion++ paper uses ~0.9. This applies only to relay
	// hops; the originator always stems when a successor is available.
	StemProbability float64

	// EpochDuration is how long a stem successor mapping remains fixed before being
	// re-randomised.
	EpochDuration time.Duration

	// EmbargoBase is the minimum time a stemmed transaction is held before the
	// failsafe fluffs it if it has not been seen returning via diffusion.
	EmbargoBase time.Duration

	// EmbargoJitter is an additional uniform-random delay added to EmbargoBase per
	// transaction so embargo expiries are not synchronised across the network.
	EmbargoJitter time.Duration

	// SuccessorCount is the number of stem successors selected per epoch. At least
	// two is recommended so a single malicious or failed successor cannot observe
	// or black-hole all of a node's stem traffic for the epoch. Values below one
	// are treated as one.
	SuccessorCount int

	// StemPeerMinAge is the minimum time a peer must have been connected before it
	// is eligible to be a stem successor. Newly-connected peers are excluded so an
	// adversary cannot inject itself into the stem path by repeated reconnection
	// (eclipse / connection-reset hardening). It is consumed by the integrating
	// handler when it builds the eligible-peer set, not by the Router core.
	StemPeerMinAge time.Duration
}

// DefaultConfig returns the recommended Dandelion++ parameters.
func DefaultConfig() Config {
	return Config{
		StemProbability: 0.9,
		EpochDuration:   10 * time.Minute,
		EmbargoBase:     10 * time.Second,
		EmbargoJitter:   10 * time.Second,
		SuccessorCount:  2,
		StemPeerMinAge:  30 * time.Second,
	}
}

// clock abstracts time so the embargo logic is deterministically testable.
type clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// randFloat returns a cryptographically-random float64 in [0,1). It is a package
// variable so tests can make routing decisions deterministic.
var randFloat = func() float64 {
	const precision = 1 << 53
	n, err := rand.Int(rand.Reader, big.NewInt(precision))
	if err != nil {
		// rand.Reader should never fail; fall back to always-stem which is the
		// privacy-preserving (conservative) choice.
		return 0
	}
	return float64(n.Int64()) / float64(precision)
}

// Router implements the Dandelion++ routing decisions for a single node. It is
// safe for concurrent use.
type Router struct {
	cfg   Config
	self  enode.ID // local node ID, used to seed deterministic successor selection
	clock clock

	mu         sync.Mutex
	peers      []enode.ID
	successors []enode.ID // fixed stem successors for the current epoch
	epoch      uint64     // monotonically increasing epoch counter
	epochEnd   time.Time

	// embargoes tracks stemmed transactions awaiting either a fluff sighting or
	// the failsafe timeout.
	embargoes map[common.Hash]time.Time
}

// New creates a Router with the given configuration for the local node self.
func New(cfg Config, self enode.ID) *Router {
	if cfg.SuccessorCount < 1 {
		cfg.SuccessorCount = 1
	}
	return &Router{
		cfg:       cfg,
		self:      self,
		clock:     realClock{},
		embargoes: make(map[common.Hash]time.Time),
	}
}

// SetPeers updates the set of peers eligible to be stem successors. It forces
// re-selection of the successors if any current successor is no longer present.
func (r *Router) SetPeers(peers []enode.ID) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.peers = append(r.peers[:0:0], peers...)
	if len(r.successors) > 0 && !subset(r.successors, r.peers) {
		r.successors = nil
	}
}

// Route returns the action to take for a transaction. originator must be true
// when the local node created the transaction (e.g. via local RPC submission) and
// false when it arrived from a peer in the stem phase. avoid is the peer the
// transaction arrived from; it is excluded from the successor candidates so a
// relay never forwards a transaction straight back to its sender. avoid is ignored
// for the originator (pass the zero value).
//
// The originator never applies the stem/fluff coin: when it has an eligible
// successor it always stems, so it is never revealed by diffusing the transaction
// from the source. Only relay hops flip the coin to decide whether to keep
// stemming or transition to fluff.
func (r *Router) Route(hash common.Hash, originator bool, avoid enode.ID) Action {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.maybeRotateEpoch()

	// No peers to stem through: fall back to diffusion so the transaction is not
	// stuck. This also covers the bootstrap case.
	if len(r.peers) == 0 {
		delete(r.embargoes, hash)
		return Action{Phase: PhaseFluff}
	}

	// Relays decide whether to continue stemming or switch to fluff for this hop.
	// The originator always stems (subject to having a successor) so it never
	// diffuses from the source by chance.
	if !originator && randFloat() >= r.cfg.StemProbability {
		delete(r.embargoes, hash) // we are fluffing; no embargo needed
		return Action{Phase: PhaseFluff}
	}

	r.ensureSuccessors()
	// Exclude the inbound peer from the candidates so a relay forwards onward, not
	// back to its sender.
	candidates := r.successors
	if !originator {
		candidates = filterOut(r.successors, avoid)
	}
	if len(candidates) == 0 {
		delete(r.embargoes, hash)
		return Action{Phase: PhaseFluff}
	}
	relay := candidates[randIndex(len(candidates))]

	// Arm the embargo failsafe for this stemmed transaction.
	if _, ok := r.embargoes[hash]; !ok {
		r.embargoes[hash] = r.clock.Now().Add(r.embargoDelay())
	}
	return Action{Phase: PhaseStem, Relay: relay}
}

// MarkFluffed records that a transaction has been observed in the fluff phase
// (e.g. received via normal diffusion), cancelling its embargo failsafe.
func (r *Router) MarkFluffed(hash common.Hash) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.embargoes, hash)
}

// ExpiredEmbargoes returns the hashes of stemmed transactions whose embargo timer
// has elapsed without a fluff sighting. The caller must diffuse these itself. The
// returned transactions are removed from the embargo set.
func (r *Router) ExpiredEmbargoes() []common.Hash {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.clock.Now()
	var expired []common.Hash
	for hash, deadline := range r.embargoes {
		if !now.Before(deadline) {
			expired = append(expired, hash)
			delete(r.embargoes, hash)
		}
	}
	return expired
}

// PendingEmbargoes returns the number of transactions currently held under an
// embargo timer. Exposed primarily for metrics and tests.
func (r *Router) PendingEmbargoes() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.embargoes)
}

// Successors returns a copy of the stem successors selected for the current
// epoch. Exposed primarily for tests and diagnostics.
func (r *Router) Successors() []enode.ID {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.maybeRotateEpoch()
	r.ensureSuccessors()
	return append([]enode.ID(nil), r.successors...)
}

// maybeRotateEpoch advances the epoch and clears the successor mapping when the
// epoch elapses. The caller must hold r.mu.
func (r *Router) maybeRotateEpoch() {
	now := r.clock.Now()
	if r.epochEnd.IsZero() || !now.Before(r.epochEnd) {
		r.epochEnd = now.Add(r.cfg.EpochDuration)
		r.epoch++
		r.successors = nil
	}
}

// ensureSuccessors (re-)selects the per-epoch stem successors when none are held
// or a previously chosen successor has left the peer set. The caller must hold
// r.mu. It deliberately does not re-select merely because a new (non-successor)
// peer connected, so the mapping stays stable within an epoch.
func (r *Router) ensureSuccessors() {
	if len(r.successors) > 0 && subset(r.successors, r.peers) {
		return
	}
	r.successors = r.selectSuccessors()
}

// selectSuccessors deterministically picks up to SuccessorCount stem successors as
// a pseudo-random function of (self, epoch, peer set): each peer is scored by
// keccak256(self || epoch || peerID) and the lowest-scoring peers are chosen. This
// is stable for a fixed peer set within an epoch, fresh each epoch, and
// independent of the order in which peers were supplied. The caller must hold r.mu.
func (r *Router) selectSuccessors() []enode.ID {
	n := r.cfg.SuccessorCount
	if n > len(r.peers) {
		n = len(r.peers)
	}
	if n <= 0 {
		return nil
	}
	var epochBuf [8]byte
	binary.BigEndian.PutUint64(epochBuf[:], r.epoch)

	type scored struct {
		id    enode.ID
		score []byte
	}
	scoredPeers := make([]scored, len(r.peers))
	for i, id := range r.peers {
		scoredPeers[i] = scored{id: id, score: crypto.Keccak256(r.self[:], epochBuf[:], id[:])}
	}
	sort.Slice(scoredPeers, func(i, j int) bool {
		return bytes.Compare(scoredPeers[i].score, scoredPeers[j].score) < 0
	})
	out := make([]enode.ID, n)
	for i := 0; i < n; i++ {
		out[i] = scoredPeers[i].id
	}
	return out
}

func (r *Router) embargoDelay() time.Duration {
	if r.cfg.EmbargoJitter <= 0 {
		return r.cfg.EmbargoBase
	}
	jitter := time.Duration(randIndex(int(r.cfg.EmbargoJitter)))
	return r.cfg.EmbargoBase + jitter
}

// randIndex returns a uniform random integer in [0,n) using crypto/rand.
func randIndex(n int) int {
	if n <= 0 {
		return 0
	}
	idx, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		// Deterministic fallback derived from the current time; only reached if the
		// system RNG is unavailable.
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(time.Now().UnixNano()))
		return int(binary.BigEndian.Uint64(b[:]) % uint64(n))
	}
	return int(idx.Int64())
}

func containsID(ids []enode.ID, target enode.ID) bool {
	for _, id := range ids {
		if id == target {
			return true
		}
	}
	return false
}

// subset reports whether every element of sub is present in super.
func subset(sub, super []enode.ID) bool {
	for _, s := range sub {
		if !containsID(super, s) {
			return false
		}
	}
	return true
}

// filterOut returns the elements of ids that are not equal to avoid. The zero
// avoid value (which is never a valid peer id) leaves ids unchanged.
func filterOut(ids []enode.ID, avoid enode.ID) []enode.ID {
	if (avoid == enode.ID{}) {
		return ids
	}
	out := make([]enode.ID, 0, len(ids))
	for _, id := range ids {
		if id != avoid {
			out = append(out, id)
		}
	}
	return out
}
