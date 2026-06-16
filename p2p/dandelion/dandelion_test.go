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
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

// fakeClock is a controllable clock for deterministic embargo testing.
type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func ids(n int) []enode.ID {
	out := make([]enode.ID, n)
	for i := range out {
		out[i][0] = byte(i + 1)
	}
	return out
}

func hash(b byte) common.Hash {
	var h common.Hash
	h[0] = b
	return h
}

var testSelf = enode.ID{0xaa}

// withRand temporarily overrides the package randFloat hook.
func withRand(v float64, fn func()) {
	orig := randFloat
	randFloat = func() float64 { return v }
	defer func() { randFloat = orig }()
	fn()
}

func newTestRouter(cfg Config) *Router { return New(cfg, testSelf) }

// TestRouteFluffsWithoutPeers ensures a node with no peers diffuses immediately
// rather than stalling, whether originating or relaying.
func TestRouteFluffsWithoutPeers(t *testing.T) {
	r := newTestRouter(DefaultConfig())
	if act := r.Route(hash(1), true, enode.ID{}); act.Phase != PhaseFluff {
		t.Fatalf("no peers (originator): phase = %s, want fluff", act.Phase)
	}
	if act := r.Route(hash(2), false, enode.ID{}); act.Phase != PhaseFluff {
		t.Fatalf("no peers (relay): phase = %s, want fluff", act.Phase)
	}
}

// TestOriginatorNeverFluffs is Correction 1: the originator must always enter the
// stem phase when it has an eligible successor, even on a roll that would make a
// relay fluff. This prevents the source from revealing itself by diffusing.
func TestOriginatorNeverFluffs(t *testing.T) {
	r := newTestRouter(DefaultConfig())
	r.SetPeers(ids(4))

	// A roll of 0.99 would fluff at a relay hop (>= 0.9), but the originator must
	// still stem.
	withRand(0.99, func() {
		for i := 0; i < 16; i++ {
			if act := r.Route(hash(byte(i+1)), true, enode.ID{}); act.Phase != PhaseStem {
				t.Fatalf("originator diffused on roll 0.99: phase = %s, want stem", act.Phase)
			}
		}
	})
	if r.PendingEmbargoes() == 0 {
		t.Fatal("originator stems did not arm an embargo")
	}
}

// TestRelayFluffsOnHighRoll checks the fluff transition fires at a relay hop when
// the random roll exceeds the stem probability.
func TestRelayFluffsOnHighRoll(t *testing.T) {
	r := newTestRouter(DefaultConfig())
	r.SetPeers(ids(4))
	withRand(0.95, func() { // >= 0.9 => fluff at a relay
		if act := r.Route(hash(1), false, enode.ID{}); act.Phase != PhaseFluff {
			t.Fatalf("phase = %s, want fluff", act.Phase)
		}
	})
	if r.PendingEmbargoes() != 0 {
		t.Fatal("fluffed transaction should not hold an embargo")
	}
}

// TestRouteStems checks that a stemmed transaction is relayed to one of the epoch
// successors, that the successor set is stable across calls within the epoch, and
// that an embargo is armed.
func TestRouteStems(t *testing.T) {
	r := newTestRouter(DefaultConfig())
	r.SetPeers(ids(8))

	withRand(0.0, func() { // 0 < StemProbability => always stem
		act := r.Route(hash(1), false, enode.ID{})
		if act.Phase != PhaseStem {
			t.Fatalf("phase = %s, want stem", act.Phase)
		}
		if (act.Relay == enode.ID{}) {
			t.Fatal("stem action has no relay successor")
		}
		succ := r.Successors()
		if !containsID(ids(8), act.Relay) {
			t.Fatal("successor not among peers")
		}
		// Every routed relay must come from the stable epoch successor set.
		for i := 0; i < 16; i++ {
			if got := r.Route(hash(byte(i+2)), false, enode.ID{}); got.Phase == PhaseStem && !containsID(succ, got.Relay) {
				t.Fatal("relayed outside the epoch successor set")
			}
		}
	})
	if r.PendingEmbargoes() == 0 {
		t.Fatal("stemmed transactions did not arm an embargo")
	}
}

// TestSuccessorCount is Correction 4: at least two successors are selected when
// enough peers exist.
func TestSuccessorCount(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SuccessorCount = 2
	r := newTestRouter(cfg)
	r.SetPeers(ids(8))

	succ := r.Successors()
	if len(succ) != 2 {
		t.Fatalf("selected %d successors, want 2", len(succ))
	}
	if succ[0] == succ[1] {
		t.Fatal("successors are not distinct")
	}
}

// TestSuccessorSelectionDeterministic is Correction 4: per-epoch selection is a
// stable, deterministic function of (self, epoch, peers) — two routers with the
// same identity and peer set pick the same successors, and selection is unaffected
// by the order peers are supplied.
func TestSuccessorSelectionDeterministic(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SuccessorCount = 3

	r1 := newTestRouter(cfg)
	r1.SetPeers(ids(10))

	r2 := newTestRouter(cfg)
	// Supply the same peers in reverse order.
	rev := ids(10)
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	r2.SetPeers(rev)

	s1, s2 := r1.Successors(), r2.Successors()
	if len(s1) != 3 || len(s2) != 3 {
		t.Fatalf("successor counts = %d, %d, want 3, 3", len(s1), len(s2))
	}
	for i := range s1 {
		if s1[i] != s2[i] {
			t.Fatalf("selection not order-independent: %v != %v", s1, s2)
		}
	}
}

// TestSuccessorsStableUnderUnrelatedChurn is Correction 4: connecting a new peer
// that is not a successor must not change the successor set within an epoch, while
// removing a chosen successor forces re-selection.
func TestSuccessorsStableUnderUnrelatedChurn(t *testing.T) {
	r := newTestRouter(DefaultConfig())
	r.SetPeers(ids(6))
	before := r.Successors()

	// Add an unrelated peer: successors must be unchanged.
	extra := append(ids(6), enode.ID{0x99})
	r.SetPeers(extra)
	after := r.Successors()
	if len(before) != len(after) {
		t.Fatalf("successor count changed on unrelated churn: %d -> %d", len(before), len(after))
	}
	for i := range before {
		if before[i] != after[i] {
			t.Fatalf("successor set changed on unrelated churn: %v -> %v", before, after)
		}
	}

	// Remove a chosen successor: re-selection must drop it.
	remaining := []enode.ID{}
	for _, id := range extra {
		if id != before[0] {
			remaining = append(remaining, id)
		}
	}
	r.SetPeers(remaining)
	for _, id := range r.Successors() {
		if id == before[0] {
			t.Fatal("kept a successor after it left the peer set")
		}
	}
}

// TestEmbargoExpiry checks the failsafe surfaces a stemmed transaction once its
// embargo elapses, and that it is reported only once.
func TestEmbargoExpiry(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	cfg := DefaultConfig()
	cfg.EmbargoBase = 5 * time.Second
	cfg.EmbargoJitter = 0
	r := newTestRouter(cfg)
	r.clock = clk
	r.SetPeers(ids(3))

	withRand(0.0, func() { r.Route(hash(1), false, enode.ID{}) })

	if got := r.ExpiredEmbargoes(); len(got) != 0 {
		t.Fatalf("embargo expired early: %v", got)
	}
	clk.advance(6 * time.Second)
	got := r.ExpiredEmbargoes()
	if len(got) != 1 || got[0] != hash(1) {
		t.Fatalf("expired = %v, want [hash(1)]", got)
	}
	// Once surfaced it must not be reported again.
	if got := r.ExpiredEmbargoes(); len(got) != 0 {
		t.Fatalf("embargo reported twice: %v", got)
	}
}

func TestMarkFluffedCancelsEmbargo(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	cfg := DefaultConfig()
	cfg.EmbargoBase = 5 * time.Second
	cfg.EmbargoJitter = 0
	r := newTestRouter(cfg)
	r.clock = clk
	r.SetPeers(ids(3))

	withRand(0.0, func() { r.Route(hash(1), false, enode.ID{}) })
	r.MarkFluffed(hash(1))
	clk.advance(time.Hour)
	if got := r.ExpiredEmbargoes(); len(got) != 0 {
		t.Fatalf("fluffed transaction still expired: %v", got)
	}
}

// TestEpochRotation checks that the stem successors are re-randomised when the
// epoch elapses (statistically, over a peer set large enough that a change is
// likely).
func TestEpochRotation(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	cfg := DefaultConfig()
	cfg.EpochDuration = time.Minute
	cfg.SuccessorCount = 1
	r := newTestRouter(cfg)
	r.clock = clk
	r.SetPeers(ids(64))

	first := r.Successors()[0]

	// Advance several epochs; at least one should pick a different successor out of
	// 64 peers.
	changed := false
	for i := 0; i < 8 && !changed; i++ {
		clk.advance(2 * time.Minute)
		if r.Successors()[0] != first {
			changed = true
		}
	}
	if !changed {
		t.Fatal("stem successor never rotated across epochs")
	}
}
