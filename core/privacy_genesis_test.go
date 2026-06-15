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

package core

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/beacon"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/privacy/circuit"
	"github.com/ethereum/go-ethereum/core/privacy/pool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

// TestGenesisVerifyingKeyInstalled checks the genesis helper installs a verifying
// key that the pool reads back identically.
func TestGenesisVerifyingKeyInstalled(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping trusted-setup in -short mode")
	}
	vk, err := circuit.DevnetVerifyingKey()
	if err != nil {
		t.Fatalf("DevnetVerifyingKey: %v", err)
	}
	be := make(mapBackend)
	for k, v := range pool.GenesisStorage(vk) {
		be[k] = v
	}
	got := pool.New(be).VerifyingKey()
	if len(got) == 0 {
		t.Fatal("verifying key not installed in genesis storage")
	}
	if string(got) != string(vk) {
		t.Fatal("installed verifying key does not round-trip")
	}
}

// mapBackend is a trivial pool.Backend over a map for the test above.
type mapBackend map[common.Hash]common.Hash

func (m mapBackend) GetState(_ common.Address, key common.Hash) common.Hash { return m[key] }
func (m mapBackend) SetState(_ common.Address, key, value common.Hash) common.Hash {
	prev := m[key]
	m[key] = value
	return prev
}

// TestShieldedTxThroughBlockProcessing is the end-to-end devnet proof: a genesis
// with Privacy Phase 1 enabled and the verifying key installed, a signed
// ShieldedTx mined into a real block via the production block producer, and the
// block imported and validated by a real BlockChain — exercising the full path
// (signing → TransactionToMessage → state processor → settlement → receipts).
func TestShieldedTxThroughBlockProcessing(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping shielded block-processing (proving) in -short mode")
	}

	key, _ := crypto.GenerateKey()
	from := crypto.PubkeyToAddress(key.PublicKey)

	// Genesis: clone the merged test config (all forks active) and enable privacy.
	cfg := *params.MergedTestChainConfig
	gspec := &Genesis{
		Config: &cfg,
		Alloc: types.GenesisAlloc{
			from: types.Account{Balance: new(big.Int).Mul(big.NewInt(100), big.NewInt(params.Ether))},
		},
	}
	if err := EnablePrivacyDevnet(gspec); err != nil {
		t.Fatalf("EnablePrivacyDevnet: %v", err)
	}
	signer := types.LatestSigner(gspec.Config)

	// Build a shield of 1 ETH: note A worth 1 ETH, two dummy inputs.
	noteA := circuit.RandomNote(wei(1))
	asg, nfs, cms, err := circuit.BuildTransfer(
		circuit.NewTree(), common.Hash{}, // fresh pool: empty/zero anchor
		nil,
		[]circuit.Output{{Value: wei(1), Apk: noteA.Apk(), Rho: noteA.Rho}},
		wei(-1),
	)
	if err != nil {
		t.Fatalf("BuildTransfer: %v", err)
	}
	proof, err := circuit.Prove(asg)
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	shieldTx, err := types.SignTx(types.NewTx(&types.ShieldedTx{
		ChainID:      gspec.Config.ChainID,
		Nonce:        0,
		GasTipCap:    big.NewInt(0),
		GasFeeCap:    big.NewInt(params.InitialBaseFee),
		Gas:          1_000_000,
		Anchor:       common.Hash{},
		Nullifiers:   nfs,
		Commitments:  cms,
		ValueBalance: wei(-1),
		Proof:        proof,
	}), signer, key)
	if err != nil {
		t.Fatalf("SignTx: %v", err)
	}

	engine := beacon.New(ethash.NewFaker())
	db, blocks, _ := GenerateChainWithGenesis(gspec, engine, 1, func(i int, b *BlockGen) {
		b.SetCoinbase(common.Address{1})
		b.AddTx(shieldTx)
	})

	chain, err := NewBlockChain(db, gspec, engine, nil)
	if err != nil {
		t.Fatalf("NewBlockChain: %v", err)
	}
	defer chain.Stop()
	if n, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("InsertChain (block %d): %v", n, err)
	}

	// Validate post-state: the pool holds 1 ETH, the sender lost 1 ETH (plus gas),
	// and the commitment tree advanced by two leaves.
	state, err := chain.State()
	if err != nil {
		t.Fatalf("State: %v", err)
	}
	if got := state.GetBalance(pool.SystemAddress).ToBig(); got.Cmp(wei(1)) != 0 {
		t.Fatalf("pool balance = %v, want 1 ETH", got)
	}
	p := pool.New(state)
	if p.Leaves() != 2 {
		t.Fatalf("pool leaves = %d, want 2", p.Leaves())
	}
	if !p.IsNullifierSpent(nfs[0]) || !p.IsNullifierSpent(nfs[1]) {
		t.Fatal("shield nullifiers not recorded as spent in post-state")
	}
	// Sender paid 1 ETH into the pool plus some gas; balance must be below 99 ETH.
	senderBal := state.GetBalance(from).ToBig()
	if senderBal.Cmp(new(big.Int).Mul(big.NewInt(99), big.NewInt(params.Ether))) >= 0 {
		t.Fatalf("sender balance = %v, expected < 99 ETH", senderBal)
	}
}
