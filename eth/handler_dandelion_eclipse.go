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
	"net"
	"sync"
	"time"

	dleproto "github.com/ethereum/go-ethereum/eth/protocols/dandelion"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

// Eclipse / connection-reset hardening for Dandelion++ stem-successor selection.
//
// The 2025 NDSS work on eclipse attacks against Monero's peer-to-peer network
// shows that Dandelion++ can be weakened by attacking the surrounding connection
// manager rather than the relay algorithm: an adversary that can repeatedly reset
// a victim's connections, monopolize its outbound slots, or flood it with sybil
// peers on one host can bias which peers become stem successors and so localise
// transaction origins. This file hardens successor selection against that class:
//
//   - Stability gating: a peer must have been connected for at least a minimum age
//     before it is eligible to be a stem successor, so an attacker cannot inject
//     itself into the stem path by repeated disconnect/reconnect.
//   - Subnet diversity: at most one peer per /24 (IPv4) or /64 (IPv6) is kept as a
//     candidate, so a sybil cluster on one host or subnet cannot fill the stem
//     successor set.
//   - Outbound preference: locally-initiated (outbound) peers are preferred over
//     inbound ones, because an attacker cannot force us to dial it.
//   - Churn monitoring: the rate of stem-peer disconnections is tracked; abnormal
//     connection-reset pressure raises a metric and a rate-limited warning.

const (
	// dandelionChurnWindow is the sliding window over which stem-peer
	// disconnections are counted for connection-reset / eclipse detection.
	dandelionChurnWindow = time.Minute

	// dandelionChurnEclipseThreshold is the number of stem-peer disconnections
	// within dandelionChurnWindow above which connection-reset pressure is treated
	// as suspected eclipse activity.
	dandelionChurnEclipseThreshold = 8

	// dandelionEclipseLogInterval rate-limits the suspected-eclipse warning.
	dandelionEclipseLogInterval = 30 * time.Second
)

// Eclipse/connection-reset hardening metrics.
var (
	dandelionChurnMeter   = metrics.NewRegisteredMeter("eth/dandelion/churn", nil)
	dandelionEclipseMeter = metrics.NewRegisteredMeter("eth/dandelion/eclipse", nil)
)

// dlePeerInfo records connection metadata for a `dle` peer, used to harden
// stem-successor selection against eclipse / connection-reset attacks.
type dlePeerInfo struct {
	peer        *dleproto.Peer
	connectedAt time.Time
	ip          net.IP // remote IP, may be nil for in-process/test peers
	inbound     bool
}

// churnTracker records recent `dle` peer disconnections in a sliding window so the
// node can detect connection-reset / eclipse pressure.
type churnTracker struct {
	mu     sync.Mutex
	window time.Duration
	times  []time.Time
}

func newChurnTracker(window time.Duration) *churnTracker {
	return &churnTracker{window: window}
}

func (c *churnTracker) record(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.times = append(c.times, now)
	c.prune(now)
}

func (c *churnTracker) rate(now time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.prune(now)
	return len(c.times)
}

// prune drops timestamps older than the window. The caller must hold c.mu.
func (c *churnTracker) prune(now time.Time) {
	cutoff := now.Add(-c.window)
	i := 0
	for i < len(c.times) && c.times[i].Before(cutoff) {
		i++
	}
	c.times = c.times[i:]
}

// subnetKey returns a grouping key that collapses peers sharing an IPv4 /24 or
// IPv6 /64. Peers with no known IP (e.g. in-process test peers) are placed in
// their own group keyed by node id so they are never collapsed together.
func subnetKey(ip net.IP, id enode.ID) string {
	if ip == nil {
		return "id:" + id.String()
	}
	if v4 := ip.To4(); v4 != nil {
		return "v4:" + v4.Mask(net.CIDRMask(24, 32)).String()
	}
	return "v6:" + ip.Mask(net.CIDRMask(64, 128)).String()
}

// preferStemPeer reports whether a is a better stem successor than b: outbound
// connections beat inbound, then the longer-connected peer wins.
func preferStemPeer(a, b *dlePeerInfo) bool {
	if a.inbound != b.inbound {
		return !a.inbound
	}
	return a.connectedAt.Before(b.connectedAt)
}

// eligibleStemPeers returns the node ids eligible to be stem successors after
// eclipse/connection-reset hardening: peers younger than minAge are excluded
// (stability gating), at most one peer per subnet is kept (the preferred one by
// preferStemPeer), and outbound, longer-lived peers win ties.
func eligibleStemPeers(infos []*dlePeerInfo, now time.Time, minAge time.Duration) []enode.ID {
	best := make(map[string]*dlePeerInfo)
	for _, info := range infos {
		if minAge > 0 && now.Sub(info.connectedAt) < minAge {
			continue // too freshly connected to trust as a stem successor
		}
		key := subnetKey(info.ip, info.peer.ID())
		if cur, ok := best[key]; !ok || preferStemPeer(info, cur) {
			best[key] = info
		}
	}
	out := make([]enode.ID, 0, len(best))
	for _, info := range best {
		out = append(out, info.peer.ID())
	}
	return out
}

// recordDandelionChurn notes a stem-peer disconnection and raises suspected-eclipse
// observability when connection-reset pressure exceeds the threshold.
func (h *handler) recordDandelionChurn() {
	now := time.Now()
	h.churn.record(now)
	dandelionChurnMeter.Mark(1)
	if rate := h.churn.rate(now); rate >= dandelionChurnEclipseThreshold {
		dandelionEclipseMeter.Mark(1)
		h.logEclipseSuspicion(rate)
	}
}

// logEclipseSuspicion emits a rate-limited warning about suspected eclipse /
// connection-reset pressure on the stem path.
func (h *handler) logEclipseSuspicion(rate int) {
	now := time.Now().UnixNano()
	last := h.lastEclipseLog.Load()
	if now-last < int64(dandelionEclipseLogInterval) {
		return
	}
	if h.lastEclipseLog.CompareAndSwap(last, now) {
		log.Warn("Dandelion++ suspected eclipse / connection-reset pressure on stem path",
			"disconnects", rate, "window", dandelionChurnWindow)
	}
}
