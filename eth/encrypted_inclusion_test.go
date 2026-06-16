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
	"github.com/ethereum/go-ethereum/core/privacy/keyper"
	"github.com/ethereum/go-ethereum/core/privacy/keyper/keypernet"
	"github.com/ethereum/go-ethereum/core/privacy/threshold"
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

func encEnvelopeFor(t *testing.T, pk *threshold.PublicKey, tx *types.Transaction) *encbuf.Envelope {
	t.Helper()
	raw, err := tx.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal tx: %v", err)
	}
	ct, err := threshold.Encrypt(pk, raw, rand.Reader)
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

// TestEncryptedInclusionDecryptsForBlock checks the eth-side block-inclusion source
// end to end: a transaction threshold-encrypted to the committee, buffered in the
// encrypted mempool, is decrypted for inclusion using the on-chain registry's
// threshold and a committee share provider — while an already-included envelope
// (nonce consumed) is dropped and not re-included.
func TestEncryptedInclusionDecryptsForBlock(t *testing.T) {
	const tt, n = 2, 3
	cfg := privacyChainConfig()
	signer := types.LatestSigner(cfg)

	// Trustless committee via DKG; registry installed in mock state.
	eon, shares, _, err := keyper.RunDKG(tt, n, rand.Reader)
	if err != nil {
		t.Fatalf("dkg: %v", err)
	}
	storage, err := keyper.BuildRegistryStorage(tt, eon, []common.Address{{1}, {2}, {3}})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}

	key, _ := crypto.GenerateKey()
	from := crypto.PubkeyToAddress(key.PublicKey)
	mkTx := func(nonce uint64) *types.Transaction {
		return types.MustSignNewTx(key, signer, &types.DynamicFeeTx{
			ChainID:   cfg.ChainID,
			Nonce:     nonce,
			GasTipCap: big.NewInt(1),
			GasFeeCap: big.NewInt(1),
			Gas:       21000,
			To:        &common.Address{0xaa},
			Value:     big.NewInt(1),
		})
	}
	includable := mkTx(5) // sender nonce will be 5 -> include
	stale := mkTx(3)      // nonce < sender nonce -> already included, drop

	pool := encbuf.NewPool(16)
	pool.Add(encEnvelopeFor(t, eon, includable))
	staleEnv := encEnvelopeFor(t, eon, stale)
	pool.Add(staleEnv)

	st := &mockAcctState{
		regAddr: encRegistryAddr,
		storage: storage,
		nonces:  map[common.Address]uint64{from: 5},
	}
	src := newEncryptedTxSource(pool, encRegistryAddr, encbuf.NewLocalShareProvider(shares), cfg)

	got := src.decrypt(&types.Header{Number: big.NewInt(1), Time: 1}, st)
	if len(got) != 1 {
		t.Fatalf("decrypted %d txs for inclusion, want 1", len(got))
	}
	if got[0].Hash() != includable.Hash() {
		t.Fatal("included the wrong transaction")
	}
	// The stale (already-included) envelope must have been dropped from the pool.
	if pool.Has(staleEnv.ID()) {
		t.Fatal("stale envelope was not dropped after inclusion")
	}
}

// TestEncryptedInclusionViaKeyperNetwork proves the full chain: a transaction
// encrypted to a DKG-generated committee is decrypted for block inclusion using
// decryption shares collected from the (in-process) keyper network, with the
// committee threshold read from the on-chain registry.
func TestEncryptedInclusionViaKeyperNetwork(t *testing.T) {
	const tt, n = 3, 5
	cfg := privacyChainConfig()
	signer := types.LatestSigner(cfg)

	// Stand up a keyper committee via DKG and install it in the registry.
	keypers, eon, _, err := keypernet.Bootstrap(tt, n, rand.Reader)
	if err != nil {
		t.Fatalf("keyper bootstrap: %v", err)
	}
	storage, err := keyper.BuildRegistryStorage(tt, eon, []common.Address{{1}, {2}, {3}, {4}, {5}})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}

	key, _ := crypto.GenerateKey()
	from := crypto.PubkeyToAddress(key.PublicKey)
	tx := types.MustSignNewTx(key, signer, &types.DynamicFeeTx{
		ChainID: cfg.ChainID, Nonce: 0, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(1),
		Gas: 21000, To: &common.Address{0xaa}, Value: big.NewInt(7),
	})
	pool := encbuf.NewPool(16)
	pool.Add(encEnvelopeFor(t, eon, tx))

	// Decryption shares come from the keyper network, not a local key.
	provider := keypernet.NewProvider(keypernet.NewInmemTransport(keypers))
	src := newEncryptedTxSource(pool, encRegistryAddr, provider, cfg)

	st := &mockAcctState{regAddr: encRegistryAddr, storage: storage, nonces: map[common.Address]uint64{from: 0}}
	got := src.decrypt(&types.Header{Number: big.NewInt(1), Time: 1}, st)
	if len(got) != 1 || got[0].Hash() != tx.Hash() {
		t.Fatalf("keyper-network decryption did not recover the transaction for inclusion")
	}
}

// TestEncryptedInclusionGatedByFork checks no decryption happens when the Privacy1
// fork is not active.
func TestEncryptedInclusionGatedByFork(t *testing.T) {
	const tt, n = 2, 3
	cfg := privacyChainConfig()
	cfg.Privacy1Time = nil // fork disabled

	eon, shares, _, err := keyper.RunDKG(tt, n, rand.Reader)
	if err != nil {
		t.Fatalf("dkg: %v", err)
	}
	storage, _ := keyper.BuildRegistryStorage(tt, eon, []common.Address{{1}, {2}, {3}})

	signer := types.LatestSigner(cfg)
	key, _ := crypto.GenerateKey()
	tx := types.MustSignNewTx(key, signer, &types.DynamicFeeTx{
		ChainID: cfg.ChainID, Nonce: 0, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(1),
		Gas: 21000, To: &common.Address{0xaa}, Value: big.NewInt(1),
	})
	pool := encbuf.NewPool(16)
	pool.Add(encEnvelopeFor(t, eon, tx))

	st := &mockAcctState{regAddr: encRegistryAddr, storage: storage, nonces: map[common.Address]uint64{}}
	src := newEncryptedTxSource(pool, encRegistryAddr, encbuf.NewLocalShareProvider(shares), cfg)

	if got := src.decrypt(&types.Header{Number: big.NewInt(1), Time: 1}, st); got != nil {
		t.Fatalf("decrypted %d txs with Privacy1 inactive, want none", len(got))
	}
}
