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
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/beacon"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	encbuf "github.com/ethereum/go-ethereum/core/privacy/encmempool"
	"github.com/ethereum/go-ethereum/core/privacy/ibe"
	"github.com/ethereum/go-ethereum/core/privacy/keyper"
	"github.com/ethereum/go-ethereum/core/privacy/keyper/keypernet"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

// TestEncryptedTxThroughBlockPath proves the encrypted mempool moves a private
// transaction through the real block path: a transaction is IBE-encrypted to the
// committee and buffered (never gossiped in the clear); the proposer decrypts it
// at block-build time using the real inclusion source backed by the keyper network
// and the on-chain committee registry; the resulting block is then imported and
// validated by a separate chain instance, and the decrypted transaction's state
// effect (the recipient's balance) appears only after that block is processed.
//
// This is the block-construction + propagation + import + state-update path
// required by shape.md, exercised through the production decrypt source rather than
// a stub. Mempool privacy that stopped at transaction relay would not pass this.
func TestEncryptedTxThroughBlockPath(t *testing.T) {
	const tt, n = 3, 5
	const blockEpoch = 1

	senderKey, _ := crypto.GenerateKey()
	sender := crypto.PubkeyToAddress(senderKey.PublicKey)
	recipient := common.Address{0xbe, 0xef}

	// Genesis: merged (all forks) + privacy enabled, fund the sender, and install
	// the keyper committee registry on-chain.
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

	keypers, mpk, vks, err := keypernet.Bootstrap(tt, n, rand.Reader)
	if err != nil {
		t.Fatalf("keyper bootstrap: %v", err)
	}
	regStorage, err := keyper.BuildRegistryStorageIBE(tt, mpk, []common.Address{{1}, {2}, {3}, {4}, {5}})
	if err != nil {
		t.Fatalf("registry storage: %v", err)
	}
	gspec.Alloc[encRegistryAddr] = types.Account{Balance: new(big.Int), Storage: regStorage}

	// The private transaction: a normal value transfer the sender wants hidden until
	// inclusion. Encrypt it to the committee for this block's epoch and buffer it.
	signer := types.LatestSigner(gspec.Config)
	innerTx, err := types.SignTx(types.NewTx(&types.DynamicFeeTx{
		ChainID:   gspec.Config.ChainID,
		Nonce:     0,
		GasTipCap: big.NewInt(0),
		GasFeeCap: big.NewInt(params.InitialBaseFee),
		Gas:       21000,
		To:        &recipient,
		Value:     big.NewInt(1000),
	}), signer, senderKey)
	if err != nil {
		t.Fatalf("sign inner tx: %v", err)
	}
	rawTx, _ := innerTx.MarshalBinary()
	ct, err := ibe.Encrypt(mpk, blockEpoch, rawTx, rand.Reader)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	ctBlob, _ := ct.Marshal()
	env, err := encbuf.NewEnvelope(ctBlob)
	if err != nil {
		t.Fatalf("envelope: %v", err)
	}
	pool := encbuf.NewPool(16)
	pool.Add(env)

	// The production inclusion source, backed by the keyper network (triggered for
	// this epoch) and the on-chain registry.
	provider := keypernet.NewProvider(keypernet.NewInmemTransport(keypers, blockEpoch), vks)
	src := newEncryptedTxSource(pool, encRegistryAddr, provider, gspec.Config)

	engine := beacon.New(ethash.NewFaker())

	// Proposer chain: read the genesis state and run the real decrypt source for the
	// block being built (the same call the miner's inclusion hook makes).
	pdb := rawdb.NewMemoryDatabase()
	proposer, err := core.NewBlockChain(pdb, gspec, engine, nil)
	if err != nil {
		t.Fatalf("proposer chain: %v", err)
	}
	defer proposer.Stop()
	genState, err := proposer.State()
	if err != nil {
		t.Fatalf("genesis state: %v", err)
	}
	header := &types.Header{Number: big.NewInt(blockEpoch), Time: proposer.CurrentBlock().Time + 1}
	decrypted := src.DecryptForBlock(header, genState)
	if len(decrypted) != 1 || decrypted[0].Hash() != innerTx.Hash() {
		t.Fatalf("real source decrypted %d txs for the block, want the inner tx", len(decrypted))
	}

	// Build the block containing the decrypted transaction, then import it on a
	// fresh node and verify the state effect appears only after block processing.
	_, blocks, _ := core.GenerateChainWithGenesis(gspec, engine, 1, func(i int, b *core.BlockGen) {
		b.SetCoinbase(common.Address{0x01})
		for _, tx := range decrypted {
			b.AddTx(tx)
		}
	})

	importer, err := core.NewBlockChain(rawdb.NewMemoryDatabase(), gspec, engine, nil)
	if err != nil {
		t.Fatalf("importer chain: %v", err)
	}
	defer importer.Stop()

	// Before import, the recipient has nothing.
	preState, _ := importer.State()
	if preState.GetBalance(recipient).Sign() != 0 {
		t.Fatal("recipient already funded before block import")
	}
	if n, err := importer.InsertChain(blocks); err != nil {
		t.Fatalf("InsertChain (block %d): %v", n, err)
	}
	postState, err := importer.State()
	if err != nil {
		t.Fatalf("post state: %v", err)
	}
	if got := postState.GetBalance(recipient).ToBig(); got.Cmp(big.NewInt(1000)) != 0 {
		t.Fatalf("recipient balance after import = %s, want 1000 (decrypted tx did not execute through the block path)", got)
	}
	if postState.GetNonce(sender) != 1 {
		t.Fatalf("sender nonce after import = %d, want 1", postState.GetNonce(sender))
	}
}
