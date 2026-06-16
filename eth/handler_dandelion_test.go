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
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth/ethconfig"
	dleproto "github.com/ethereum/go-ethereum/eth/protocols/dandelion"
	"github.com/ethereum/go-ethereum/eth/protocols/eth"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/dandelion"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/params"
)

// buildDandelionHandler builds a test handler with Dandelion++ network-origin
// privacy enabled and the given tuning parameters, over a mock transaction pool.
func buildDandelionHandler(t *testing.T, cfg dandelion.Config) *testHandler {
	t.Helper()
	db := rawdb.NewMemoryDatabase()
	gspec := &core.Genesis{
		Config: params.TestChainConfig,
		Alloc:  types.GenesisAlloc{testAddr: {Balance: big.NewInt(1000000)}},
	}
	chain, _ := core.NewBlockChain(db, gspec, ethash.NewFaker(), nil)
	pool := newTestTxPool()

	// In tests, peers are eligible as stem successors immediately (the production
	// stability gating is exercised directly in TestEligibleStemPeers).
	cfg.StemPeerMinAge = 0

	handler, err := newHandler(&handlerConfig{
		Database:         db,
		Chain:            chain,
		TxPool:           pool,
		Network:          1,
		Sync:             ethconfig.FullSync,
		BloomCache:       1,
		DandelionEnabled: true,
		Dandelion:        cfg,
	})
	if err != nil {
		t.Fatalf("failed to create dandelion handler: %v", err)
	}
	handler.Start(1000)
	handler.synced.Store(true)
	return &testHandler{db: db, chain: chain, txpool: pool, handler: handler}
}

func makeLocalTestTx(nonce uint64) *types.Transaction {
	tx := types.NewTransaction(nonce, common.Address{}, big.NewInt(0), 100000, big.NewInt(0), nil)
	tx, _ = types.SignTx(tx, types.HomesteadSigner{}, testKey)
	return tx
}

// connectEth wires an `eth` connection between a and b over a MsgPipe. a sees b as
// node id nodeB and b sees a as node id nodeA.
func connectEth(a, b *testHandler, nodeA, nodeB byte) func() {
	ap, bp := p2p.MsgPipe()
	aPeer := eth.NewPeer(eth.ETH69, p2p.NewPeerPipe(enode.ID{nodeB}, "", nil, ap), ap, a.txpool, nil)
	bPeer := eth.NewPeer(eth.ETH69, p2p.NewPeerPipe(enode.ID{nodeA}, "", nil, bp), bp, b.txpool, nil)

	go a.handler.runEthPeer(aPeer, func(peer *eth.Peer) error {
		return eth.Handle((*ethHandler)(a.handler), peer)
	})
	go b.handler.runEthPeer(bPeer, func(peer *eth.Peer) error {
		return eth.Handle((*ethHandler)(b.handler), peer)
	})
	return func() {
		ap.Close()
		bp.Close()
		aPeer.Close()
		bPeer.Close()
	}
}

// connectDle wires a `dle` (Dandelion++ stem) connection between a and b over a
// MsgPipe, registering each as the other's stem peer.
func connectDle(a, b *testHandler, nodeA, nodeB byte) func() {
	ap, bp := p2p.MsgPipe()
	aPeer := dleproto.NewPeer(dleproto.DLE1, p2p.NewPeerPipe(enode.ID{nodeB}, "", nil, ap), ap)
	bPeer := dleproto.NewPeer(dleproto.DLE1, p2p.NewPeerPipe(enode.ID{nodeA}, "", nil, bp), bp)

	go (*dandelionHandler)(a.handler).RunPeer(aPeer, func(peer *dleproto.Peer) error {
		defer peer.Close()
		return dleproto.Handle((*dandelionHandler)(a.handler), peer)
	})
	go (*dandelionHandler)(b.handler).RunPeer(bPeer, func(peer *dleproto.Peer) error {
		defer peer.Close()
		return dleproto.Handle((*dandelionHandler)(b.handler), peer)
	})
	return func() {
		ap.Close()
		bp.Close()
	}
}

// connectDleBlackHole connects a black-hole `dle` peer (node id holeNode) to relay:
// relay registers it as a stem successor, but the peer silently drains every stem
// message without ever fluffing or continuing the stem.
func connectDleBlackHole(relay *testHandler, holeNode byte) func() {
	rp, hp := p2p.MsgPipe()
	relayPeer := dleproto.NewPeer(dleproto.DLE1, p2p.NewPeerPipe(enode.ID{holeNode}, "", nil, rp), rp)

	go (*dandelionHandler)(relay.handler).RunPeer(relayPeer, func(peer *dleproto.Peer) error {
		defer peer.Close()
		return dleproto.Handle((*dandelionHandler)(relay.handler), peer)
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			msg, err := hp.ReadMsg()
			if err != nil {
				return
			}
			msg.Discard()
		}
	}()
	return func() {
		rp.Close()
		hp.Close()
		<-done
	}
}

func dlePeerCount(h *handler) int {
	h.dandelionPeerLock.RLock()
	defer h.dandelionPeerLock.RUnlock()
	return len(h.dandelionPeers)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func subscribePool(h *testHandler) (chan core.NewTxsEvent, func()) {
	ch := make(chan core.NewTxsEvent, 1024)
	sub := h.txpool.SubscribeTransactions(ch, false)
	return ch, sub.Unsubscribe
}

// poolReceived reports whether the target hash arrives on the pool-event channel
// within the timeout.
func poolReceived(ch chan core.NewTxsEvent, hash common.Hash, timeout time.Duration) bool {
	deadline := time.After(timeout)
	for {
		select {
		case ev := <-ch:
			for _, tx := range ev.Txs {
				if tx.Hash() == hash {
					return true
				}
			}
		case <-deadline:
			return false
		}
	}
}

// countReceiving reports how many of the channels deliver the target hash within
// the timeout.
func countReceiving(chs []chan core.NewTxsEvent, hash common.Hash, timeout time.Duration) int {
	seen := make([]bool, len(chs))
	count := 0
	deadline := time.After(timeout)
	for count < len(chs) {
		select {
		case <-deadline:
			return count
		default:
		}
		for i, ch := range chs {
			if seen[i] {
				continue
			}
			select {
			case ev := <-ch:
				for _, tx := range ev.Txs {
					if tx.Hash() == hash {
						seen[i] = true
						count++
					}
				}
			default:
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	return count
}

// TestDandelionStemReachesSinglePeer is the core origin-obfuscation test: a local
// transaction submitted with Dandelion++ enabled is relayed to exactly one stem
// successor over `dle`, not diffused to a square root of peers. The sinks act as an
// adversarial observer trying to localise the origin from who receives it.
func TestDandelionStemReachesSinglePeer(t *testing.T) {
	cfg := dandelion.DefaultConfig()
	cfg.EmbargoBase = 10 * time.Second // long: the failsafe must not fire during the test
	cfg.EmbargoJitter = 0

	source := buildDandelionHandler(t, cfg)
	defer source.close()

	const numSinks = 8
	txChs := make([]chan core.NewTxsEvent, numSinks)
	for i := 0; i < numSinks; i++ {
		sink := buildDandelionHandler(t, cfg)
		defer sink.close()

		nodeSource, nodeSink := byte(100), byte(i+1)
		defer connectEth(source, sink, nodeSource, nodeSink)()
		defer connectDle(source, sink, nodeSource, nodeSink)()

		ch, unsub := subscribePool(sink)
		defer unsub()
		txChs[i] = ch
	}
	waitFor(t, "dle peers", func() bool { return dlePeerCount(source.handler) == numSinks })

	tx := makeLocalTestTx(0)
	source.handler.markLocalTx(tx.Hash())
	source.txpool.Add([]*types.Transaction{tx}, false)

	if got := countReceiving(txChs, tx.Hash(), 2*time.Second); got != 1 {
		t.Fatalf("stemmed transaction reached %d peers, want exactly 1 (origin obfuscation failed)", got)
	}
}

// TestDandelionMultiHopStem is Correction 2: the stem continues across an honest
// relay via the explicit `dle` signal, so the fluff begins at least two hops from
// the origin. A -> B -> C: B relays onward (it must not appear in its own pool),
// and C is where the transaction fluffs into the mempool.
func TestDandelionMultiHopStem(t *testing.T) {
	cfg := dandelion.DefaultConfig()
	cfg.StemProbability = 1.0 // relays always continue the stem
	cfg.EmbargoBase = 10 * time.Second
	cfg.EmbargoJitter = 0

	a := buildDandelionHandler(t, cfg) // origin (node 1)
	defer a.close()
	b := buildDandelionHandler(t, cfg) // relay (node 2)
	defer b.close()
	c := buildDandelionHandler(t, cfg) // relay/fluff point (node 3)
	defer c.close()

	defer connectDle(a, b, 1, 2)()
	defer connectDle(b, c, 2, 3)()

	waitFor(t, "A stem peer", func() bool { return dlePeerCount(a.handler) == 1 })
	waitFor(t, "B stem peers", func() bool { return dlePeerCount(b.handler) == 2 })
	waitFor(t, "C stem peer", func() bool { return dlePeerCount(c.handler) == 1 })

	bCh, unsubB := subscribePool(b)
	defer unsubB()
	cCh, unsubC := subscribePool(c)
	defer unsubC()

	tx := makeLocalTestTx(0)
	a.handler.markLocalTx(tx.Hash())
	a.txpool.Add([]*types.Transaction{tx}, false)

	// The transaction must fluff into C's pool (two hops from A).
	if !poolReceived(cCh, tx.Hash(), 3*time.Second) {
		t.Fatal("transaction never reached the second-hop relay C: stem did not continue")
	}
	// B only relays; it must not admit the transaction to its own pool while
	// stemming.
	if b.txpool.Has(tx.Hash()) {
		t.Fatal("relay B admitted the stem transaction to its pool instead of relaying it onward")
	}
	// Drain any late B event defensively (should not arrive).
	if poolReceived(bCh, tx.Hash(), 200*time.Millisecond) {
		t.Fatal("relay B fluffed the transaction itself instead of continuing the stem")
	}
}

// TestDandelionRelayEmbargo is Correction 5: a relay arms its own embargo, so when
// the node it stems to is a black hole, the relay itself recovers the transaction
// by diffusing it. A -> B -> C(black hole); B's own failsafe must surface the tx.
func TestDandelionRelayEmbargo(t *testing.T) {
	cfg := dandelion.DefaultConfig()
	cfg.StemProbability = 1.0
	cfg.EmbargoBase = 150 * time.Millisecond
	cfg.EmbargoJitter = 0

	a := buildDandelionHandler(t, cfg) // origin (node 1)
	defer a.close()
	b := buildDandelionHandler(t, cfg) // relay (node 2)
	defer b.close()

	defer connectDle(a, b, 1, 2)()
	defer connectDleBlackHole(b, 3)() // B stems to node 3, which silently drops everything

	waitFor(t, "A stem peer", func() bool { return dlePeerCount(a.handler) == 1 })
	waitFor(t, "B stem peers", func() bool { return dlePeerCount(b.handler) == 2 })

	bCh, unsubB := subscribePool(b)
	defer unsubB()

	tx := makeLocalTestTx(0)
	a.handler.markLocalTx(tx.Hash())
	a.txpool.Add([]*types.Transaction{tx}, false)

	// B stemmed the transaction to the black hole and armed its own embargo. Since
	// the black hole never fluffs, B's failsafe must admit the transaction to B's
	// pool. A and B share only a `dle` link, so this can only come from B's own
	// embargo, not from A.
	if !poolReceived(bCh, tx.Hash(), 3*time.Second) {
		t.Fatal("relay B did not recover the black-holed transaction via its own embargo")
	}
}

// TestDandelionRemoteTxDiffuses verifies that transactions which did not originate
// locally are unaffected by Dandelion++: they diffuse normally to all peers.
func TestDandelionRemoteTxDiffuses(t *testing.T) {
	cfg := dandelion.DefaultConfig()
	cfg.EmbargoBase = 10 * time.Second
	cfg.EmbargoJitter = 0

	source := buildDandelionHandler(t, cfg)
	defer source.close()

	const numSinks = 6
	txChs := make([]chan core.NewTxsEvent, numSinks)
	for i := 0; i < numSinks; i++ {
		sink := buildDandelionHandler(t, cfg)
		defer sink.close()

		defer connectEth(source, sink, 100, byte(i+1))()
		defer connectDle(source, sink, 100, byte(i+1))()

		ch, unsub := subscribePool(sink)
		defer unsub()
		txChs[i] = ch
	}
	waitFor(t, "eth peers", func() bool { return source.handler.peers.len() == numSinks })

	// Not marked local: must diffuse like a relayed transaction.
	tx := makeLocalTestTx(0)
	source.txpool.Add([]*types.Transaction{tx}, false)

	if got := countReceiving(txChs, tx.Hash(), 3*time.Second); got != numSinks {
		t.Fatalf("non-local transaction reached %d/%d peers, want full diffusion", got, numSinks)
	}
}

// TestDandelionRebroadcastPersists is Correction 3: local-origin status persists,
// so repeated broadcasts of the same local transaction keep stemming instead of
// diffusing the origin after the first send.
func TestDandelionRebroadcastPersists(t *testing.T) {
	cfg := dandelion.DefaultConfig()
	cfg.EmbargoBase = 10 * time.Second
	cfg.EmbargoJitter = 0

	source := buildDandelionHandler(t, cfg)
	defer source.close()
	sink := buildDandelionHandler(t, cfg)
	defer sink.close()

	defer connectDle(source, sink, 100, 1)()
	waitFor(t, "dle peer", func() bool { return dlePeerCount(source.handler) == 1 })

	tx := makeLocalTestTx(0)
	source.handler.markLocalTx(tx.Hash())

	// Each broadcast must stem (return nothing to diffuse) and leave the origin
	// status intact for the next round. A consume-once tracker would diffuse from
	// the second call onward.
	for i := 0; i < 4; i++ {
		diffuse := source.handler.stemTransactions(types.Transactions{tx})
		if len(diffuse) != 0 {
			t.Fatalf("re-broadcast %d diffused the local transaction instead of stemming it", i+1)
		}
		if !source.handler.isLocalTx(tx.Hash()) {
			t.Fatalf("local-origin status lost after broadcast %d", i+1)
		}
	}

	// A fluff sighting clears the origin status (it is now public).
	source.handler.markFluffed(tx.Hash())
	if source.handler.isLocalTx(tx.Hash()) {
		t.Fatal("fluff sighting did not clear local-origin status")
	}
}

// TestOriginTracker exercises the local-origin tracker's persistence, clearing,
// TTL expiry, and size cap.
func TestOriginTracker(t *testing.T) {
	now := time.Unix(0, 0)
	tr := &originTracker{
		clock:   func() time.Time { return now },
		ttl:     time.Minute,
		max:     3,
		entries: make(map[common.Hash]time.Time),
	}

	h1 := common.Hash{1}
	tr.mark(h1)
	// Persistence: isLocal stays true across repeated checks (not consume-once).
	for i := 0; i < 3; i++ {
		if !tr.isLocal(h1) {
			t.Fatalf("isLocal returned false on check %d; origin status must persist", i+1)
		}
	}
	tr.clear(h1)
	if tr.isLocal(h1) {
		t.Fatal("cleared hash still reported as local")
	}

	// TTL expiry.
	tr.mark(h1)
	now = now.Add(2 * time.Minute)
	if tr.isLocal(h1) {
		t.Fatal("expired hash still reported as local")
	}

	// Size cap: marking more than max hashes evicts the oldest.
	now = time.Unix(0, 0)
	hashes := []common.Hash{{10}, {11}, {12}, {13}, {14}}
	for _, h := range hashes {
		tr.mark(h)
	}
	live := 0
	for _, h := range hashes {
		if tr.isLocal(h) {
			live++
		}
	}
	if live > tr.max {
		t.Fatalf("origin tracker kept %d entries, want at most %d", live, tr.max)
	}
	if live == 0 {
		t.Fatal("origin tracker evicted everything; most recent marks should survive")
	}
}

// TestDandelionWithholdFromSync checks that locally-originated transactions still
// in the stem phase are withheld from initial mempool syncing (so a freshly
// connected peer is not told this node holds them), and are released once fluffed.
func TestDandelionWithholdFromSync(t *testing.T) {
	cfg := dandelion.DefaultConfig()
	source := buildDandelionHandler(t, cfg)
	defer source.close()

	local := makeLocalTestTx(0)
	remote := makeLocalTestTx(1)

	source.handler.markLocalTx(local.Hash())
	if !source.handler.withholdFromSync(local.Hash()) {
		t.Fatal("local stem-phase transaction must be withheld from initial sync")
	}
	if source.handler.withholdFromSync(remote.Hash()) {
		t.Fatal("non-local transaction must not be withheld from sync")
	}

	// A fluff sighting makes it public; it should then be syncable normally.
	source.handler.markFluffed(local.Hash())
	if source.handler.withholdFromSync(local.Hash()) {
		t.Fatal("fluffed transaction must no longer be withheld from sync")
	}
}

// TestEligibleStemPeers exercises the eclipse/connection-reset hardening of
// stem-successor selection: stability gating, subnet diversity, and outbound
// preference.
func TestEligibleStemPeers(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	mk := func(id byte, ip string, ageSec int, inbound bool) *dlePeerInfo {
		var nip net.IP
		if ip != "" {
			nip = net.ParseIP(ip)
		}
		p := dleproto.NewPeer(dleproto.DLE1, p2p.NewPeer(enode.ID{id}, "", nil), nil)
		t.Cleanup(p.Close)
		return &dlePeerInfo{
			peer:        p,
			connectedAt: now.Add(-time.Duration(ageSec) * time.Second),
			ip:          nip,
			inbound:     inbound,
		}
	}
	has := func(ids []enode.ID, id byte) bool {
		for _, x := range ids {
			if x == (enode.ID{id}) {
				return true
			}
		}
		return false
	}

	// Stability gating: a peer younger than minAge is excluded.
	fresh := mk(1, "1.1.1.1", 5, false)
	stable := mk(2, "2.2.2.2", 120, false)
	got := eligibleStemPeers([]*dlePeerInfo{fresh, stable}, now, 30*time.Second)
	if has(got, 1) {
		t.Fatal("freshly-connected peer must not be stem-eligible under stability gating")
	}
	if !has(got, 2) {
		t.Fatal("stable peer should be stem-eligible")
	}

	// Subnet diversity: two peers in the same /24 collapse to one.
	a := mk(3, "10.0.0.1", 100, false)
	b := mk(4, "10.0.0.2", 50, false) // same /24, younger
	got = eligibleStemPeers([]*dlePeerInfo{a, b}, now, 0)
	if has(got, 3) == has(got, 4) {
		t.Fatalf("expected exactly one peer from a shared /24, got %v", got)
	}
	if !has(got, 3) {
		t.Fatal("subnet diversity should keep the longer-connected peer")
	}

	// Outbound preference within a subnet: outbound beats a longer-lived inbound.
	inOld := mk(5, "172.16.0.1", 200, true)
	outNew := mk(6, "172.16.0.2", 20, false) // same /24, outbound
	got = eligibleStemPeers([]*dlePeerInfo{inOld, outNew}, now, 0)
	if !has(got, 6) || has(got, 5) {
		t.Fatalf("outbound peer should be preferred within a subnet, got %v", got)
	}

	// Peers with no IP (in-process/test peers) are never collapsed together.
	n1, n2 := mk(7, "", 100, false), mk(8, "", 100, false)
	got = eligibleStemPeers([]*dlePeerInfo{n1, n2}, now, 0)
	if !has(got, 7) || !has(got, 8) {
		t.Fatalf("peers without IPs must not be collapsed, got %v", got)
	}
}

// TestChurnTracker exercises the connection-reset / eclipse pressure detector.
func TestChurnTracker(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	c := newChurnTracker(time.Minute)

	for i := 0; i < 5; i++ {
		c.record(now.Add(time.Duration(i) * time.Second))
	}
	if got := c.rate(now.Add(5 * time.Second)); got != 5 {
		t.Fatalf("churn rate = %d, want 5", got)
	}
	// Records outside the window are pruned.
	if got := c.rate(now.Add(2 * time.Minute)); got != 0 {
		t.Fatalf("churn rate after window = %d, want 0", got)
	}
}

// TestStemHoldSet exercises the relay-held transaction set.
func TestStemHoldSet(t *testing.T) {
	s := &stemHoldSet{max: 2, txs: make(map[common.Hash]*types.Transaction)}

	tx1 := makeLocalTestTx(0)
	tx2 := makeLocalTestTx(1)
	tx3 := makeLocalTestTx(2)

	s.add(tx1)
	if got := s.get(tx1.Hash()); got == nil || got.Hash() != tx1.Hash() {
		t.Fatal("held transaction not retrievable")
	}
	s.remove(tx1.Hash())
	if s.get(tx1.Hash()) != nil {
		t.Fatal("removed transaction still present")
	}

	// Cap eviction.
	s.add(tx1)
	s.add(tx2)
	s.add(tx3)
	if len(s.txs) > s.max {
		t.Fatalf("stem-hold set kept %d entries, want at most %d", len(s.txs), s.max)
	}
}
