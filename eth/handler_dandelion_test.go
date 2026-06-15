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
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth/ethconfig"
	"github.com/ethereum/go-ethereum/eth/protocols/eth"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/dandelion"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/params"
)

// buildDandelionHandler builds a test handler with Dandelion++ network-origin
// privacy enabled and the given tuning parameters, over a mock transaction pool.
func buildDandelionHandler(cfg dandelion.Config) *testHandler {
	db := rawdb.NewMemoryDatabase()
	gspec := &core.Genesis{
		Config: params.TestChainConfig,
		Alloc:  types.GenesisAlloc{testAddr: {Balance: big.NewInt(1000000)}},
	}
	chain, _ := core.NewBlockChain(db, gspec, ethash.NewFaker(), nil)
	pool := newTestTxPool()

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
		panic(err)
	}
	handler.Start(1000)

	return &testHandler{db: db, chain: chain, txpool: pool, handler: handler}
}

// makeLocalTestTx returns a signed legacy transaction for the test account.
func makeLocalTestTx(nonce uint64) *types.Transaction {
	tx := types.NewTransaction(nonce, common.Address{}, big.NewInt(0), 100000, big.NewInt(0), nil)
	tx, _ = types.SignTx(tx, types.HomesteadSigner{}, testKey)
	return tx
}

// connectSink wires a fresh sink handler to the source handler over a MsgPipe and
// returns the sink together with a channel that receives its pool events. The
// caller is responsible for keeping the returned cleanup until the test ends.
func connectSink(t *testing.T, source *testHandler, id byte, active bool) (*testHandler, chan core.NewTxsEvent, func()) {
	t.Helper()

	sink := newTestHandler(ethconfig.FullSync)
	sink.handler.synced.Store(true)

	sourcePipe, sinkPipe := p2p.MsgPipe()
	sourcePeer := eth.NewPeer(eth.ETH69, p2p.NewPeerPipe(enode.ID{id}, "", nil, sourcePipe), sourcePipe, source.txpool, nil)
	sinkPeer := eth.NewPeer(eth.ETH69, p2p.NewPeerPipe(enode.ID{0}, "", nil, sinkPipe), sinkPipe, sink.txpool, nil)

	go source.handler.runEthPeer(sourcePeer, func(peer *eth.Peer) error {
		return eth.Handle((*ethHandler)(source.handler), peer)
	})
	go sink.handler.runEthPeer(sinkPeer, func(peer *eth.Peer) error {
		if !active {
			// Passive observer (black-hole peer): drain and discard messages so the
			// transport never blocks, but never process or re-diffuse them, so it
			// produces no fluff sighting back to the source. Exits when the pipe is
			// closed so the handler can shut down cleanly.
			for {
				msg, err := sinkPipe.ReadMsg()
				if err != nil {
					return err
				}
				msg.Discard()
			}
		}
		return eth.Handle((*ethHandler)(sink.handler), peer)
	})

	ch := make(chan core.NewTxsEvent, 1024)
	sub := sink.txpool.SubscribeTransactions(ch, false)

	cleanup := func() {
		sub.Unsubscribe()
		sourcePeer.Close()
		sinkPeer.Close()
		sourcePipe.Close()
		sinkPipe.Close()
		sink.close()
	}
	return sink, ch, cleanup
}

// waitForPeers blocks until the handler has at least n connected peers.
func waitForPeers(t *testing.T, h *handler, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if h.peers.len() >= n {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d peers (have %d)", n, h.peers.len())
}

// countSinksReceiving reports how many of the given pool-event channels deliver
// the target transaction hash within the timeout.
func countSinksReceiving(chs []chan core.NewTxsEvent, hash common.Hash, timeout time.Duration) int {
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
		select {
		case <-deadline:
			return count
		default:
		}
	}
	return count
}

// TestDandelionStemReachesSinglePeer is the core origin-obfuscation test: a
// locally-originated transaction submitted with Dandelion++ enabled must be
// relayed to exactly one stem successor, not diffused to a square root of peers.
// The set of sinks acts as an adversarial observer attempting to localise the
// origin from who receives the transaction first.
func TestDandelionStemReachesSinglePeer(t *testing.T) {
	cfg := dandelion.Config{
		StemProbability: 1.0,              // always remain in the stem phase
		EpochDuration:   time.Minute,      // stable successor for the whole test
		EmbargoBase:     10 * time.Second, // long enough that the failsafe never fires here
		EmbargoJitter:   0,
	}
	source := buildDandelionHandler(cfg)
	defer source.close()
	source.handler.synced.Store(true)

	const numSinks = 8
	txChs := make([]chan core.NewTxsEvent, numSinks)
	for i := 0; i < numSinks; i++ {
		_, ch, cleanup := connectSink(t, source, byte(i+1), true)
		defer cleanup()
		txChs[i] = ch
	}
	waitForPeers(t, source.handler, numSinks)

	tx := makeLocalTestTx(0)
	source.handler.markLocalTx(tx.Hash())
	source.txpool.Add([]*types.Transaction{tx}, false)

	if got := countSinksReceiving(txChs, tx.Hash(), 2*time.Second); got != 1 {
		t.Fatalf("stemmed transaction reached %d peers, want exactly 1 (origin obfuscation failed)", got)
	}
}

// TestDandelionRemoteTxDiffuses verifies that transactions which did not originate
// locally are unaffected by Dandelion++: they diffuse normally to all peers. This
// guards against the privacy path accidentally throttling ordinary gossip.
func TestDandelionRemoteTxDiffuses(t *testing.T) {
	cfg := dandelion.Config{
		StemProbability: 1.0,
		EpochDuration:   time.Minute,
		EmbargoBase:     10 * time.Second,
		EmbargoJitter:   0,
	}
	source := buildDandelionHandler(cfg)
	defer source.close()
	source.handler.synced.Store(true)

	const numSinks = 6
	txChs := make([]chan core.NewTxsEvent, numSinks)
	for i := 0; i < numSinks; i++ {
		_, ch, cleanup := connectSink(t, source, byte(i+1), true)
		defer cleanup()
		txChs[i] = ch
	}
	waitForPeers(t, source.handler, numSinks)

	// Do NOT mark the transaction as local: it must diffuse like a relayed tx.
	tx := makeLocalTestTx(0)
	source.txpool.Add([]*types.Transaction{tx}, false)

	if got := countSinksReceiving(txChs, tx.Hash(), 3*time.Second); got != numSinks {
		t.Fatalf("non-local transaction reached %d/%d peers, want full diffusion", got, numSinks)
	}
}

// TestDandelionEmbargoFailsafe verifies the black-hole failsafe: when a stemmed
// transaction is never observed returning via diffusion, the embargo timer expires
// and the node diffuses it itself so it is never lost.
func TestDandelionEmbargoFailsafe(t *testing.T) {
	cfg := dandelion.Config{
		StemProbability: 1.0,
		EpochDuration:   time.Minute,
		EmbargoBase:     150 * time.Millisecond, // short embargo so the test is quick
		EmbargoJitter:   0,
	}
	source := buildDandelionHandler(cfg)
	defer source.close()
	source.handler.synced.Store(true)

	// First peer is a passive observer: it receives the stem relay but never
	// re-diffuses, so the source never gets a fluff sighting and the embargo fires.
	_, _, cleanupPassive := connectSink(t, source, 1, false)
	defer cleanupPassive()
	waitForPeers(t, source.handler, 1)

	tx := makeLocalTestTx(0)
	source.handler.markLocalTx(tx.Hash())
	source.txpool.Add([]*types.Transaction{tx}, false)

	// Now connect an active observer. When the embargo expires, the failsafe loop
	// must diffuse the transaction, and this peer must receive it.
	_, ch, cleanupActive := connectSink(t, source, 2, true)
	defer cleanupActive()
	waitForPeers(t, source.handler, 2)

	if got := countSinksReceiving([]chan core.NewTxsEvent{ch}, tx.Hash(), 3*time.Second); got != 1 {
		t.Fatalf("embargoed transaction was not diffused by the failsafe (received by %d/1 observers)", got)
	}
}

// TestOriginTracker exercises the local-origin tracker's consume-once semantics,
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
	if !tr.consume(h1) {
		t.Fatal("first consume of a marked hash should report local origin")
	}
	if tr.consume(h1) {
		t.Fatal("second consume of the same hash should report not-local (consume-once)")
	}

	// TTL expiry: a marked hash must not be considered local after its TTL.
	tr.mark(h1)
	now = now.Add(2 * time.Minute)
	if tr.consume(h1) {
		t.Fatal("expired hash should not report local origin")
	}

	// Size cap: marking more than max hashes evicts the oldest entries.
	now = time.Unix(0, 0)
	hashes := []common.Hash{{10}, {11}, {12}, {13}, {14}}
	for _, h := range hashes {
		tr.mark(h)
	}
	live := 0
	for _, h := range hashes {
		if tr.consume(h) {
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
