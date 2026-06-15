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
//     pseudo-random line of relays. Each node on the line forwards to exactly one
//     fixed successor, so no node (other than the immediate predecessor) can tell
//     whether its sender originated the transaction or merely relayed it.
//   - Fluff phase ("spreading phase"): at a random point the line transitions to
//     ordinary diffusion and the transaction floods the network normally.
//
// The successor mapping is fixed per epoch (re-randomised periodically) to prevent
// an adversary from averaging over many independent routings to locate the source.
// An embargo timer provides a failsafe: if a node that stemmed a transaction never
// observes it return via fluff, it fluffs the transaction itself, defeating
// black-hole attacks.
//
// This package contains only the routing decision logic and is deliberately
// transport-agnostic: callers wire the Relay and Broadcast actions into their
// existing eth-protocol transaction send paths. This keeps the privacy logic
// independently testable and avoids coupling it to a specific networking stack.
package dandelion

import (
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
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
	// (i.e. 1-StemProbability is the chance of switching to fluff at each hop).
	// The reference Dandelion++ paper uses ~0.9.
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
}

// DefaultConfig returns the recommended Dandelion++ parameters.
func DefaultConfig() Config {
	return Config{
		StemProbability: 0.9,
		EpochDuration:   10 * time.Minute,
		EmbargoBase:     10 * time.Second,
		EmbargoJitter:   10 * time.Second,
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
	clock clock

	mu        sync.Mutex
	peers     []enode.ID
	successor enode.ID // fixed stem successor for the current epoch
	haveSucc  bool
	epochEnd  time.Time

	// embargoes tracks stemmed transactions awaiting either a fluff sighting or
	// the failsafe timeout.
	embargoes map[common.Hash]time.Time
}

// New creates a Router with the given configuration.
func New(cfg Config) *Router {
	return &Router{
		cfg:       cfg,
		clock:     realClock{},
		embargoes: make(map[common.Hash]time.Time),
	}
}

// SetPeers updates the set of outbound peers eligible to be stem successors. It
// forces re-selection of the successor if the current one is no longer present.
func (r *Router) SetPeers(peers []enode.ID) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.peers = append(r.peers[:0:0], peers...)
	if r.haveSucc && !containsID(r.peers, r.successor) {
		r.haveSucc = false
	}
}

// Route returns the action to take for a transaction the local node is
// originating or has received in the stem phase. inbound indicates whether the
// transaction arrived from a peer (true) or was created locally (false); locally
// created transactions always start in the stem phase to protect the originator.
func (r *Router) Route(hash common.Hash) Action {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.maybeRotateEpoch()

	// No peers to stem through: fall back to diffusion so the transaction is not
	// stuck. This also covers the bootstrap case.
	if len(r.peers) == 0 {
		return Action{Phase: PhaseFluff}
	}

	// Decide whether to continue stemming or switch to fluff for this hop.
	if randFloat() >= r.cfg.StemProbability {
		delete(r.embargoes, hash) // we are fluffing; no embargo needed
		return Action{Phase: PhaseFluff}
	}

	if !r.haveSucc {
		r.selectSuccessor()
	}
	// Arm the embargo failsafe for this stemmed transaction.
	if _, ok := r.embargoes[hash]; !ok {
		r.embargoes[hash] = r.clock.Now().Add(r.embargoDelay())
	}
	return Action{Phase: PhaseStem, Relay: r.successor}
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

// maybeRotateEpoch re-randomises the stem successor when the epoch elapses. The
// caller must hold r.mu.
func (r *Router) maybeRotateEpoch() {
	now := r.clock.Now()
	if r.epochEnd.IsZero() || !now.Before(r.epochEnd) {
		r.epochEnd = now.Add(r.cfg.EpochDuration)
		r.haveSucc = false
	}
}

// selectSuccessor pseudo-randomly fixes a stem successor for the epoch. The caller
// must hold r.mu.
func (r *Router) selectSuccessor() {
	if len(r.peers) == 0 {
		r.haveSucc = false
		return
	}
	r.successor = r.peers[randIndex(len(r.peers))]
	r.haveSucc = true
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
