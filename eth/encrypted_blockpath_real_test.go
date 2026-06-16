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
	"context"
	"crypto/rand"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/beacon"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	encbuf "github.com/ethereum/go-ethereum/core/privacy/encmempool"
	"github.com/ethereum/go-ethereum/core/privacy/ibe"
	"github.com/ethereum/go-ethereum/core/privacy/keyper"
	"github.com/ethereum/go-ethereum/core/privacy/keyper/keypernet"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/txpool/legacypool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/miner"
	"github.com/ethereum/go-ethereum/params"
)

// blockPathMinerBackend is the minimal miner.Backend (chain + txpool) needed to
// drive real block production in this test.
type blockPathMinerBackend struct {
	chain *core.BlockChain
	pool  *txpool.TxPool
}

func (b *blockPathMinerBackend) BlockChain() *core.BlockChain { return b.chain }
func (b *blockPathMinerBackend) TxPool() *txpool.TxPool       { return b.pool }

// newBlockPathGenesis returns a merged + privacy-enabled genesis funding `sender`
// and installing the IBE committee registry from `mpk` at encRegistryAddr.
func newBlockPathGenesis(t *testing.T, sender common.Address, tt int, mpk *ibe.MasterPublicKey) *core.Genesis {
	t.Helper()
	cfg := *params.MergedTestChainConfig
	gspec := &core.Genesis{
		Config: &cfg,
		Alloc: types.GenesisAlloc{
			sender: types.Account{Balance: new(big.Int).Mul(big.NewInt(100), big.NewInt(params.Ether))},
		},
	}
	if err := core.EnablePrivacyDevnet(gspec); err != nil {
		t.Fatalf("EnablePrivacyDevnet: %v", err)
	}
	storage, err := keyper.BuildRegistryStorageIBE(tt, mpk, []common.Address{{1}, {2}, {3}, {4}, {5}})
	if err != nil {
		t.Fatalf("registry storage: %v", err)
	}
	gspec.Alloc[encRegistryAddr] = types.Account{Balance: new(big.Int), Storage: storage}
	return gspec
}

// TestEncryptedTxThroughRealMinerAndImport is the definitive block-path test: the
// real miner produces a block via its production block-building path (including the
// encrypted-tx inclusion hook, backed by the real decrypt source and the keyper
// network), the resulting payload is converted to a block exactly as the engine API
// does, and that block is imported and validated by a separate chain — with the
// recipient balance and sender nonce changing only after block processing.
func TestEncryptedTxThroughRealMinerAndImport(t *testing.T) {
	const tt, n = 3, 5
	const blockEpoch = 1

	senderKey, _ := crypto.GenerateKey()
	sender := crypto.PubkeyToAddress(senderKey.PublicKey)
	recipient := common.Address{0xbe, 0xef}

	keypers, mpk, _, err := keypernet.Bootstrap(tt, n, rand.Reader)
	if err != nil {
		t.Fatalf("keyper bootstrap: %v", err)
	}
	gspec := newBlockPathGenesis(t, sender, tt, mpk)
	signer := types.LatestSigner(gspec.Config)

	// The private value transfer, IBE-encrypted to the committee for this epoch.
	innerTx, _ := types.SignTx(types.NewTx(&types.DynamicFeeTx{
		ChainID:   gspec.Config.ChainID,
		Nonce:     0,
		GasTipCap: big.NewInt(0),
		GasFeeCap: big.NewInt(params.InitialBaseFee),
		Gas:       21000,
		To:        &recipient,
		Value:     big.NewInt(1000),
	}), signer, senderKey)
	rawTx, _ := innerTx.MarshalBinary()
	ct, _ := ibe.Encrypt(mpk, blockEpoch, rawTx, rand.Reader)
	ctBlob, _ := ct.Marshal()
	env, _ := encbuf.NewEnvelope(ctBlob)
	encPool := encbuf.NewPool(16)
	encPool.Add(env)

	eng := beacon.New(ethash.NewFaker())

	// Proposer node: real chain, real txpool, real miner with the production
	// encrypted-tx inclusion source.
	proposer, err := core.NewBlockChain(rawdb.NewMemoryDatabase(), gspec, eng, nil)
	if err != nil {
		t.Fatalf("proposer chain: %v", err)
	}
	defer proposer.Stop()

	lp := legacypool.New(legacypool.DefaultConfig, proposer)
	tp, err := txpool.New(legacypool.DefaultConfig.PriceLimit, proposer, []txpool.SubPool{lp})
	if err != nil {
		t.Fatalf("txpool: %v", err)
	}
	defer tp.Close()

	mcfg := miner.DefaultConfig
	mcfg.PendingFeeRecipient = common.Address{0x01}
	mcfg.Recommit = 100 * time.Millisecond
	m := miner.New(&blockPathMinerBackend{chain: proposer, pool: tp}, mcfg, eng)

	provider := keypernet.NewInmemProvider(keypers, ^uint64(0))
	m.SetEncryptedTxSource(newEncryptedTxSource(encPool, encRegistryAddr, provider, gspec.Config))

	// Build the block through the production block-builder path.
	beaconRoot := common.Hash{}
	payload, err := m.BuildPayload(context.Background(), &miner.BuildPayloadArgs{
		Parent:       proposer.CurrentBlock().Hash(),
		Timestamp:    proposer.CurrentBlock().Time + 12,
		Random:       common.Hash{0x01},
		FeeRecipient: common.Address{0x01},
		Withdrawals:  types.Withdrawals{},
		BeaconRoot:   &beaconRoot,
	}, false)
	if err != nil {
		t.Fatalf("BuildPayload: %v", err)
	}
	envelope := payload.ResolveFull()
	if envelope == nil {
		t.Fatal("nil payload envelope")
	}
	if got := len(envelope.ExecutionPayload.Transactions); got != 1 {
		t.Fatalf("built block has %d txs, want exactly the decrypted one", got)
	}

	// Convert the payload to a block exactly as the engine API does, then import it
	// into a separate node and verify the state effect appears only after import.
	block, err := engine.ExecutableDataToBlock(*envelope.ExecutionPayload, nil, &beaconRoot, envelope.Requests)
	if err != nil {
		t.Fatalf("ExecutableDataToBlock: %v", err)
	}

	importer, err := core.NewBlockChain(rawdb.NewMemoryDatabase(), gspec, beacon.New(ethash.NewFaker()), nil)
	if err != nil {
		t.Fatalf("importer chain: %v", err)
	}
	defer importer.Stop()
	pre, _ := importer.State()
	if pre.GetBalance(recipient).Sign() != 0 {
		t.Fatal("recipient funded before import")
	}
	if _, err := importer.InsertChain([]*types.Block{block}); err != nil {
		t.Fatalf("InsertChain: %v", err)
	}
	post, _ := importer.State()
	if got := post.GetBalance(recipient).ToBig(); got.Cmp(big.NewInt(1000)) != 0 {
		t.Fatalf("recipient balance after import = %s, want 1000", got)
	}
	if post.GetNonce(sender) != 1 {
		t.Fatalf("sender nonce after import = %d, want 1", post.GetNonce(sender))
	}
}

// TestEncryptedTxReorgSafety checks reorg/rebroadcast privacy semantics: when an
// encrypted transaction is decrypted and included in a block, its envelope is NOT
// dropped from the buffer until the inner transaction's nonce is actually consumed
// on the canonical state. So if the block is reorged out (its nonce not consumed
// canonically), the still-encrypted envelope remains buffered and can be
// re-included on the new canonical chain — the plaintext only ever existed inside
// the orphaned block, never in the buffer or on the wire.
func TestEncryptedTxReorgSafety(t *testing.T) {
	const tt, n = 3, 5
	const blockEpoch = 1

	senderKey, _ := crypto.GenerateKey()
	sender := crypto.PubkeyToAddress(senderKey.PublicKey)

	keypers, mpk, vks, err := keypernet.Bootstrap(tt, n, rand.Reader)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	gspec := newBlockPathGenesis(t, sender, tt, mpk)
	signer := types.LatestSigner(gspec.Config)
	innerTx, _ := types.SignTx(types.NewTx(&types.DynamicFeeTx{
		ChainID: gspec.Config.ChainID, Nonce: 0, GasTipCap: big.NewInt(0),
		GasFeeCap: big.NewInt(params.InitialBaseFee), Gas: 21000, To: &common.Address{0xbe, 0xef}, Value: big.NewInt(1000),
	}), signer, senderKey)
	rawTx, _ := innerTx.MarshalBinary()
	ct, _ := ibe.Encrypt(mpk, blockEpoch, rawTx, rand.Reader)
	ctBlob, _ := ct.Marshal()
	env, _ := encbuf.NewEnvelope(ctBlob)
	encPool := encbuf.NewPool(16)
	encPool.Add(env)

	provider := keypernet.NewProvider(keypernet.NewInmemTransport(keypers, ^uint64(0)), vks)
	src := newEncryptedTxSource(encPool, encRegistryAddr, provider, gspec.Config)

	chain, err := core.NewBlockChain(rawdb.NewMemoryDatabase(), gspec, beacon.New(ethash.NewFaker()), nil)
	if err != nil {
		t.Fatalf("chain: %v", err)
	}
	defer chain.Stop()
	header := &types.Header{Number: big.NewInt(blockEpoch), Time: chain.CurrentBlock().Time + 12}

	// Decrypt for a block while the sender's nonce is still 0 (tx not yet consumed
	// on canonical state, e.g. its block was just built or has been reorged out).
	notConsumed := &mockAcctState{regAddr: encRegistryAddr, storage: registryStorageFromGenesis(t, gspec), nonces: map[common.Address]uint64{sender: 0}}
	got := src.decrypt(header, notConsumed)
	if len(got) != 1 {
		t.Fatalf("decrypted %d, want the includable tx", len(got))
	}
	if !encPool.Has(env.ID()) {
		t.Fatal("envelope was dropped on inclusion; a reorg would lose it. It must stay buffered until canonically consumed")
	}

	// Once the inner transaction's nonce is consumed on canonical state, the
	// envelope is no longer needed and is dropped.
	consumed := &mockAcctState{regAddr: encRegistryAddr, storage: notConsumed.storage, nonces: map[common.Address]uint64{sender: 1}}
	if got := src.decrypt(header, consumed); len(got) != 0 {
		t.Fatalf("re-included an already-consumed tx (%d)", len(got))
	}
	if encPool.Has(env.ID()) {
		t.Fatal("envelope retained after its nonce was canonically consumed")
	}
}

// registryStorageFromGenesis extracts the keyper registry storage installed in the
// genesis alloc at encRegistryAddr.
func registryStorageFromGenesis(t *testing.T, gspec *core.Genesis) map[common.Hash]common.Hash {
	t.Helper()
	acct, ok := gspec.Alloc[encRegistryAddr]
	if !ok {
		t.Fatal("no registry account in genesis")
	}
	return acct.Storage
}

// TestEncryptedTxCommitteeUnavailable checks the committee-unavailable fallback:
// when the keyper committee has not released the epoch key, the encrypted
// transaction is not included and its envelope stays buffered for a later block,
// with no plaintext exposed.
func TestEncryptedTxCommitteeUnavailable(t *testing.T) {
	const tt, n = 3, 5
	const blockEpoch = 1

	senderKey, _ := crypto.GenerateKey()
	sender := crypto.PubkeyToAddress(senderKey.PublicKey)

	keypers, mpk, vks, err := keypernet.Bootstrap(tt, n, rand.Reader)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	gspec := newBlockPathGenesis(t, sender, tt, mpk)
	signer := types.LatestSigner(gspec.Config)
	innerTx, _ := types.SignTx(types.NewTx(&types.DynamicFeeTx{
		ChainID: gspec.Config.ChainID, Nonce: 0, GasTipCap: big.NewInt(0),
		GasFeeCap: big.NewInt(params.InitialBaseFee), Gas: 21000, To: &common.Address{0xbe, 0xef}, Value: big.NewInt(1000),
	}), signer, senderKey)
	rawTx, _ := innerTx.MarshalBinary()
	ct, _ := ibe.Encrypt(mpk, blockEpoch, rawTx, rand.Reader)
	ctBlob, _ := ct.Marshal()
	env, _ := encbuf.NewEnvelope(ctBlob)
	encPool := encbuf.NewPool(16)
	encPool.Add(env)

	// Committee trigger is 0: the epoch-1 key is never released.
	provider := keypernet.NewProvider(keypernet.NewInmemTransport(keypers, 0), vks)
	src := newEncryptedTxSource(encPool, encRegistryAddr, provider, gspec.Config)

	chain, err := core.NewBlockChain(rawdb.NewMemoryDatabase(), gspec, beacon.New(ethash.NewFaker()), nil)
	if err != nil {
		t.Fatalf("chain: %v", err)
	}
	defer chain.Stop()
	genState, _ := chain.State()
	header := &types.Header{Number: big.NewInt(blockEpoch), Time: chain.CurrentBlock().Time + 12}

	if got := src.decrypt(header, genState); len(got) != 0 {
		t.Fatalf("decrypted %d txs with the committee unavailable, want 0", len(got))
	}
	if !encPool.Has(env.ID()) {
		t.Fatal("undecryptable envelope was dropped; it must stay buffered for a later block")
	}
}
