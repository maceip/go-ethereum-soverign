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

// withRand temporarily overrides the package randFloat hook.
func withRand(v float64, fn func()) {
	orig := randFloat
	randFloat = func() float64 { return v }
	defer func() { randFloat = orig }()
	fn()
}

// TestRouteFluffsWithoutPeers ensures a node with no peers diffuses immediately
// rather than stalling.
func TestRouteFluffsWithoutPeers(t *testing.T) {
	r := New(DefaultConfig())
	if act := r.Route(hash(1)); act.Phase != PhaseFluff {
		t.Fatalf("no peers: phase = %s, want fluff", act.Phase)
	}
}

// TestRouteStems checks that with a high stem roll the transaction is relayed to a
// single, fixed successor and an embargo is armed.
func TestRouteStems(t *testing.T) {
	r := New(DefaultConfig())
	r.SetPeers(ids(4))

	withRand(0.0, func() { // 0 < StemProbability => always stem
		act := r.Route(hash(1))
		if act.Phase != PhaseStem {
			t.Fatalf("phase = %s, want stem", act.Phase)
		}
		if (act.Relay == enode.ID{}) {
			t.Fatal("stem action has no relay successor")
		}
		// Successor must be one of our peers and stable across calls in the epoch.
		first := act.Relay
		if !containsID(ids(4), first) {
			t.Fatal("successor not among peers")
		}
		for i := 0; i < 5; i++ {
			if r.Route(hash(byte(i+2))).Relay != first {
				t.Fatal("successor changed within an epoch")
			}
		}
	})
	if r.PendingEmbargoes() == 0 {
		t.Fatal("stemmed transactions did not arm an embargo")
	}
}

// TestRouteFluffsOnHighRoll checks the fluff transition fires when the random roll
// exceeds the stem probability.
func TestRouteFluffsOnHighRoll(t *testing.T) {
	r := New(DefaultConfig())
	r.SetPeers(ids(4))
	withRand(0.95, func() { // >= 0.9 => fluff
		if act := r.Route(hash(1)); act.Phase != PhaseFluff {
			t.Fatalf("phase = %s, want fluff", act.Phase)
		}
	})
	if r.PendingEmbargoes() != 0 {
		t.Fatal("fluffed transaction should not hold an embargo")
	}
}

// TestEmbargoExpiry checks the failsafe surfaces a stemmed transaction once its
// embargo elapses, and that MarkFluffed cancels it.
func TestEmbargoExpiry(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	cfg := DefaultConfig()
	cfg.EmbargoBase = 5 * time.Second
	cfg.EmbargoJitter = 0
	r := New(cfg)
	r.clock = clk
	r.SetPeers(ids(3))

	withRand(0.0, func() { r.Route(hash(1)) })

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
	r := New(cfg)
	r.clock = clk
	r.SetPeers(ids(3))

	withRand(0.0, func() { r.Route(hash(1)) })
	r.MarkFluffed(hash(1))
	clk.advance(time.Hour)
	if got := r.ExpiredEmbargoes(); len(got) != 0 {
		t.Fatalf("fluffed transaction still expired: %v", got)
	}
}

// TestEpochRotation checks that the stem successor is re-randomised when the epoch
// elapses (statistically, over a peer set large enough that a change is likely).
func TestEpochRotation(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	cfg := DefaultConfig()
	cfg.EpochDuration = time.Minute
	r := New(cfg)
	r.clock = clk
	r.SetPeers(ids(64))

	var firstEpoch enode.ID
	withRand(0.0, func() { firstEpoch = r.Route(hash(1)).Relay })

	// Advance several epochs; at least one should pick a different successor out of
	// 64 peers (probability of all-identical is (1/64)^k).
	changed := false
	for i := 0; i < 8 && !changed; i++ {
		clk.advance(2 * time.Minute)
		withRand(0.0, func() {
			if r.Route(hash(byte(i+2))).Relay != firstEpoch {
				changed = true
			}
		})
	}
	if !changed {
		t.Fatal("stem successor never rotated across epochs")
	}
}

// TestSetPeersDropsStaleSuccessor checks that removing the current successor forces
// a fresh selection from the remaining peers.
func TestSetPeersDropsStaleSuccessor(t *testing.T) {
	r := New(DefaultConfig())
	r.SetPeers(ids(2))

	var succ enode.ID
	withRand(0.0, func() { succ = r.Route(hash(1)).Relay })

	// Replace the peer set with peers that exclude the chosen successor.
	remaining := []enode.ID{}
	for _, id := range ids(2) {
		if id != succ {
			remaining = append(remaining, id)
		}
	}
	r.SetPeers(remaining)
	withRand(0.0, func() {
		if got := r.Route(hash(2)).Relay; got == succ {
			t.Fatal("kept stale successor after it left the peer set")
		}
	})
}
