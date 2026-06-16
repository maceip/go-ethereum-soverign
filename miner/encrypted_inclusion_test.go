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

package miner

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
)

// stubEncSource is a test EncryptedTxSource that returns a fixed set of already-
// decrypted transactions, standing in for the real keyper-backed source (whose
// gating and decryption are tested in package eth).
type stubEncSource struct{ txs []*types.Transaction }

func (s stubEncSource) DecryptForBlock(header *types.Header, st *state.StateDB) []*types.Transaction {
	return s.txs
}

// TestMinerIncludesEncryptedTransactions verifies that transactions returned by an
// EncryptedTxSource are committed directly into the built block (the decrypt-at-
// inclusion path), without ever being placed in the public transaction pool.
func TestMinerIncludesEncryptedTransactions(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	engine := ethash.NewFaker()
	// Backend with an empty transaction pool, so anything in the block must have
	// come from the encrypted-tx source.
	backend := newTestWorkerBackend(t, params.TestChainConfig, engine, db, 0)
	w := New(backend, testConfig, engine)

	signer := types.LatestSigner(params.TestChainConfig)
	encTx := types.MustSignNewTx(testBankKey, signer, &types.LegacyTx{
		Nonce:    0,
		To:       &testUserAddress,
		Value:    big.NewInt(1234),
		Gas:      params.TxGas,
		GasPrice: big.NewInt(params.InitialBaseFee),
	})
	w.SetEncryptedTxSource(stubEncSource{txs: []*types.Transaction{encTx}})

	args := &BuildPayloadArgs{
		Parent:       backend.chain.CurrentBlock().Hash(),
		Timestamp:    uint64(time.Now().Unix()),
		Random:       common.Hash{},
		FeeRecipient: common.HexToAddress("0xdeadbeef"),
	}
	payload, err := w.buildPayload(context.Background(), args, false)
	if err != nil {
		t.Fatalf("failed to build payload: %v", err)
	}
	full := payload.ResolveFull()
	txs := full.ExecutionPayload.Transactions
	if len(txs) != 1 {
		t.Fatalf("block has %d transactions, want exactly the decrypted one", len(txs))
	}
	var got types.Transaction
	if err := got.UnmarshalBinary(txs[0]); err != nil {
		t.Fatalf("decode block tx: %v", err)
	}
	if got.Hash() != encTx.Hash() {
		t.Fatal("block does not contain the decrypted encrypted-mempool transaction")
	}
	// The decrypted transaction must not have been added to the public pool.
	if backend.txPool.Has(encTx.Hash()) {
		t.Fatal("decrypted transaction leaked into the public transaction pool")
	}
}
