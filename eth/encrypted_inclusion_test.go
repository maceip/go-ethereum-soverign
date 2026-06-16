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
	encbuf "github.com/ethereum/go-ethereum/core/privacy/encmempool"
	"github.com/ethereum/go-ethereum/core/privacy/ibe"
	"github.com/ethereum/go-ethereum/core/privacy/keyper"
	"github.com/ethereum/go-ethereum/core/privacy/keyper/keypernet"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

var encRegistryAddr = common.HexToAddress("0x00000000000000000000000000000000000a11ce")

// mockAcctState is an in-memory accountState for the registry account and nonces.
type mockAcctState struct {
	regAddr common.Address
	storage map[common.Hash]common.Hash
	nonces  map[common.Address]uint64
}

func (m *mockAcctState) GetState(addr common.Address, key common.Hash) common.Hash {
	if addr != m.regAddr {
		return common.Hash{}
	}
	return m.storage[key]
}

func (m *mockAcctState) GetNonce(addr common.Address) uint64 { return m.nonces[addr] }

// privacyChainConfig returns a minimal chain config with the Privacy1 fork active.
func privacyChainConfig() *params.ChainConfig {
	zero := uint64(0)
	return &params.ChainConfig{
		ChainID:      big.NewInt(1),
		LondonBlock:  big.NewInt(0),
		PragueTime:   &zero,
		Privacy1Time: &zero,
	}
}

func ibeEnvelope(t *testing.T, mpk *ibe.MasterPublicKey, epoch uint64, tx *types.Transaction) *encbuf.Envelope {
	t.Helper()
	raw, err := tx.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal tx: %v", err)
	}
	ct, err := ibe.Encrypt(mpk, epoch, raw, rand.Reader)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	blob, _ := ct.Marshal()
	env, err := encbuf.NewEnvelope(blob)
	if err != nil {
		t.Fatalf("envelope: %v", err)
	}
	return env
}

// TestEncryptedInclusionViaKeyperNetwork proves the full chain: a transaction
// IBE-encrypted to the committee for an epoch is decrypted for block inclusion
// using the epoch key released by the (in-process) keyper network, with the
// committee threshold read from the on-chain registry; an already-included envelope
// (nonce consumed) is dropped, and an envelope for a future epoch is not yet due.
func TestEncryptedInclusionViaKeyperNetwork(t *testing.T) {
	const tt, n = 3, 5
	cfg := privacyChainConfig()
	signer := types.LatestSigner(cfg)

	keypers, mpk, vks, err := keypernet.Bootstrap(tt, n, rand.Reader)
	if err != nil {
		t.Fatalf("keyper bootstrap: %v", err)
	}
	storage, err := keyper.BuildRegistryStorageIBE(tt, mpk, []common.Address{{1}, {2}, {3}, {4}, {5}})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}

	key, _ := crypto.GenerateKey()
	from := crypto.PubkeyToAddress(key.PublicKey)
	mkTx := func(nonce uint64) *types.Transaction {
		return types.MustSignNewTx(key, signer, &types.DynamicFeeTx{
			ChainID: cfg.ChainID, Nonce: nonce, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(1),
			Gas: 21000, To: &common.Address{0xaa}, Value: big.NewInt(7),
		})
	}
	const blockEpoch = 1
	includable := mkTx(5) // due (epoch 1) and nonce matches -> include
	stale := mkTx(3)      // due but already included (nonce < state) -> drop
	future := mkTx(9)     // targets a future epoch -> not yet due

	pool := encbuf.NewPool(16)
	pool.Add(ibeEnvelope(t, mpk, blockEpoch, includable))
	staleEnv := ibeEnvelope(t, mpk, blockEpoch, stale)
	pool.Add(staleEnv)
	futureEnv := ibeEnvelope(t, mpk, 5, future)
	pool.Add(futureEnv)

	// Keyper network triggered up to the current block epoch only.
	provider := keypernet.NewProvider(keypernet.NewInmemTransport(keypers, blockEpoch), vks)
	src := newEncryptedTxSource(pool, encRegistryAddr, provider, cfg)

	st := &mockAcctState{regAddr: encRegistryAddr, storage: storage, nonces: map[common.Address]uint64{from: 5}}
	got := src.decrypt(&types.Header{Number: big.NewInt(blockEpoch), Time: 1}, st)
	if len(got) != 1 || got[0].Hash() != includable.Hash() {
		t.Fatalf("keyper-network decryption did not recover exactly the includable tx (got %d)", len(got))
	}
	if pool.Has(staleEnv.ID()) {
		t.Fatal("already-included envelope was not dropped")
	}
	if !pool.Has(futureEnv.ID()) {
		t.Fatal("future-epoch envelope should remain buffered until its epoch is due")
	}
}

// TestEncryptedInclusionGatedByFork checks no decryption happens when the Privacy1
// fork is not active.
func TestEncryptedInclusionGatedByFork(t *testing.T) {
	const tt, n = 2, 3
	cfg := privacyChainConfig()
	cfg.Privacy1Time = nil // fork disabled

	keypers, mpk, vks, err := keypernet.Bootstrap(tt, n, rand.Reader)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	storage, _ := keyper.BuildRegistryStorageIBE(tt, mpk, []common.Address{{1}, {2}, {3}})

	signer := types.LatestSigner(cfg)
	key, _ := crypto.GenerateKey()
	tx := types.MustSignNewTx(key, signer, &types.DynamicFeeTx{
		ChainID: cfg.ChainID, Nonce: 0, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(1),
		Gas: 21000, To: &common.Address{0xaa}, Value: big.NewInt(1),
	})
	pool := encbuf.NewPool(16)
	pool.Add(ibeEnvelope(t, mpk, 1, tx))

	provider := keypernet.NewProvider(keypernet.NewInmemTransport(keypers, ^uint64(0)), vks)
	src := newEncryptedTxSource(pool, encRegistryAddr, provider, cfg)
	st := &mockAcctState{regAddr: encRegistryAddr, storage: storage, nonces: map[common.Address]uint64{}}
	if got := src.decrypt(&types.Header{Number: big.NewInt(1), Time: 1}, st); got != nil {
		t.Fatalf("decrypted %d txs with Privacy1 inactive, want none", len(got))
	}
}
