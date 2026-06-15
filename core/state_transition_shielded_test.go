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
	"github.com/ethereum/go-ethereum/core/privacy/circuit"
	"github.com/ethereum/go-ethereum/core/privacy/pool"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

// shieldedTestEnv bundles the state, EVM and config for driving ApplyMessage, plus
// a prover-side Merkle tree mirroring the pool so we can build membership proofs.
type shieldedTestEnv struct {
	statedb *state.StateDB
	evm     *vm.EVM
	tree    *circuit.Tree
}

func newShieldedTestEnv(t *testing.T) *shieldedTestEnv {
	t.Helper()
	statedb, err := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	if err != nil {
		t.Fatalf("state: %v", err)
	}
	cfgCopy := *params.MergedTestChainConfig
	zero := uint64(0)
	cfgCopy.Privacy1Time = &zero

	random := common.Hash{} // non-nil Random => post-merge, so time-based forks apply
	blockCtx := vm.BlockContext{
		CanTransfer: CanTransfer,
		Transfer:    Transfer,
		GetHash:     func(uint64) common.Hash { return common.Hash{} },
		Coinbase:    common.Address{},
		BlockNumber: big.NewInt(1),
		Time:        1,
		Difficulty:  big.NewInt(0),
		Random:      &random,
		GasLimit:    30_000_000,
		BaseFee:     big.NewInt(0),
	}
	evm := vm.NewEVM(blockCtx, statedb, &cfgCopy, vm.Config{})
	return &shieldedTestEnv{statedb: statedb, evm: evm, tree: circuit.NewTree()}
}

func ether(n int64) *uint256.Int {
	return new(uint256.Int).Mul(uint256.NewInt(uint64(n)), uint256.NewInt(params.Ether))
}

func wei(n int64) *big.Int {
	return new(big.Int).Mul(big.NewInt(n), big.NewInt(params.Ether))
}

// applyShielded builds and applies a shielded message with zero gas price (so gas
// is free and the test focuses on shielded settlement). On success it mirrors the
// appended commitments into the prover tree.
func (env *shieldedTestEnv) applyShielded(t *testing.T, from common.Address, nonce uint64, to *common.Address, anchor common.Hash, nullifiers, commitments []common.Hash, valueBalance *big.Int, proof []byte) error {
	t.Helper()
	msg := &Message{
		From:      from,
		To:        to,
		Nonce:     nonce,
		Value:     new(uint256.Int),
		GasLimit:  3_000_000,
		GasPrice:  new(uint256.Int),
		GasFeeCap: new(uint256.Int),
		GasTipCap: new(uint256.Int),
		Shielded: &ShieldedData{
			Anchor:       anchor,
			Nullifiers:   nullifiers,
			Commitments:  commitments,
			ValueBalance: valueBalance,
			Proof:        proof,
		},
	}
	_, err := ApplyMessage(env.evm, msg, NewGasPool(10_000_000))
	if err == nil {
		for _, c := range commitments {
			env.tree.Append(c)
		}
	}
	return err
}

// TestShieldedLifecycleRealCircuit drives shield -> transfer -> unshield ->
// double-spend through ApplyMessage using REAL PlonK proofs from the production
// shielded-transfer circuit. It is the end-to-end consensus test of Privacy
// Phase 1.
func TestShieldedLifecycleRealCircuit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping shielded circuit proving in -short mode")
	}
	vk, err := circuit.DevnetSetup()
	if err != nil {
		t.Fatalf("DevnetSetup: %v", err)
	}

	env := newShieldedTestEnv(t)
	from := common.HexToAddress("0x1111111111111111111111111111111111111111")
	recipient := common.HexToAddress("0x2222222222222222222222222222222222222222")
	env.statedb.AddBalance(from, ether(100), 0)
	pool.New(env.statedb).InstallVerifyingKey(vk)

	// --- Shield 10 ETH: create note A worth 10 ETH -----------------------------
	noteA := circuit.RandomNote(wei(10))
	anchor := pool.New(env.statedb).Root() // fresh pool root
	asg, nfs, cms, err := circuit.BuildTransfer(
		env.tree, anchor,
		nil,
		[]circuit.Output{{Value: wei(10), Apk: noteA.Apk(), Rho: noteA.Rho}},
		wei(-10),
	)
	if err != nil {
		t.Fatalf("BuildTransfer shield: %v", err)
	}
	proof, err := circuit.Prove(asg)
	if err != nil {
		t.Fatalf("Prove shield: %v", err)
	}
	if err := env.applyShielded(t, from, 0, nil, anchor, nfs, cms, wei(-10), proof); err != nil {
		t.Fatalf("shield failed: %v", err)
	}
	if got := env.statedb.GetBalance(from); got.Cmp(ether(90)) != 0 {
		t.Fatalf("after shield, sender = %v, want 90 ETH", got)
	}
	if got := env.statedb.GetBalance(pool.SystemAddress); got.Cmp(ether(10)) != 0 {
		t.Fatalf("after shield, pool = %v, want 10 ETH", got)
	}
	noteALeaf := uint64(0) // cms[0] (note A) was the first commitment appended

	// --- Transfer: spend note A (10) -> note B (6) + note C (4) ----------------
	noteB := circuit.RandomNote(wei(6))
	noteC := circuit.RandomNote(wei(4))
	anchor = pool.New(env.statedb).Root()
	asg, nfs, cms, err = circuit.BuildTransfer(
		env.tree, anchor,
		[]circuit.Spend{{Note: noteA, LeafIndex: noteALeaf}},
		[]circuit.Output{
			{Value: wei(6), Apk: noteB.Apk(), Rho: noteB.Rho},
			{Value: wei(4), Apk: noteC.Apk(), Rho: noteC.Rho},
		},
		big.NewInt(0), // pure shielded transfer
	)
	if err != nil {
		t.Fatalf("BuildTransfer transfer: %v", err)
	}
	transferNullifiers := nfs
	transferCommitments := cms
	proof, err = circuit.Prove(asg)
	if err != nil {
		t.Fatalf("Prove transfer: %v", err)
	}
	noteBLeaf := pool.New(env.statedb).Leaves() // cms[0] (note B) index after this append
	if err := env.applyShielded(t, from, 1, nil, anchor, nfs, cms, big.NewInt(0), proof); err != nil {
		t.Fatalf("transfer failed: %v", err)
	}
	if got := env.statedb.GetBalance(pool.SystemAddress); got.Cmp(ether(10)) != 0 {
		t.Fatalf("after transfer, pool = %v, want 10 ETH (unchanged)", got)
	}
	if !pool.New(env.statedb).IsNullifierSpent(transferNullifiers[0]) {
		t.Fatal("note A nullifier not spent after transfer")
	}

	// --- Unshield 6 ETH: spend note B (6) -> recipient, no shielded outputs ----
	anchor = pool.New(env.statedb).Root()
	asg, nfs, cms, err = circuit.BuildTransfer(
		env.tree, anchor,
		[]circuit.Spend{{Note: noteB, LeafIndex: noteBLeaf}},
		nil,    // both outputs are dummies (value 0)
		wei(6), // unshield 6 ETH
	)
	if err != nil {
		t.Fatalf("BuildTransfer unshield: %v", err)
	}
	proof, err = circuit.Prove(asg)
	if err != nil {
		t.Fatalf("Prove unshield: %v", err)
	}
	if err := env.applyShielded(t, from, 2, &recipient, anchor, nfs, cms, wei(6), proof); err != nil {
		t.Fatalf("unshield failed: %v", err)
	}
	if got := env.statedb.GetBalance(recipient); got.Cmp(ether(6)) != 0 {
		t.Fatalf("after unshield, recipient = %v, want 6 ETH", got)
	}
	if got := env.statedb.GetBalance(pool.SystemAddress); got.Cmp(ether(4)) != 0 {
		t.Fatalf("after unshield, pool = %v, want 4 ETH", got)
	}

	// --- Double-spend: replay the transfer's nullifier -------------------------
	// Reuse the transfer transaction verbatim; its first nullifier is already spent.
	err = env.applyShielded(t, from, 3, nil, pool.New(env.statedb).Root(), transferNullifiers, transferCommitments, big.NewInt(0), proof)
	if err != ErrShieldedDoubleSpend {
		t.Fatalf("double spend: got %v, want ErrShieldedDoubleSpend", err)
	}
	_ = transferCommitments
}

// TestShieldedRejectsTamperedTx checks that a valid proof does not validate a
// transaction whose public fields were altered after proving (binding).
func TestShieldedRejectsTamperedTx(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping shielded circuit proving in -short mode")
	}
	vk, err := circuit.DevnetSetup()
	if err != nil {
		t.Fatalf("DevnetSetup: %v", err)
	}
	env := newShieldedTestEnv(t)
	from := common.HexToAddress("0x3333333333333333333333333333333333333333")
	env.statedb.AddBalance(from, ether(100), 0)
	pool.New(env.statedb).InstallVerifyingKey(vk)

	noteA := circuit.RandomNote(wei(10))
	anchor := pool.New(env.statedb).Root()
	asg, nfs, cms, err := circuit.BuildTransfer(env.tree, anchor, nil,
		[]circuit.Output{{Value: wei(10), Apk: noteA.Apk(), Rho: noteA.Rho}}, wei(-10))
	if err != nil {
		t.Fatal(err)
	}
	proof, err := circuit.Prove(asg)
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}
	// Tamper: replace an output commitment with an arbitrary value.
	cms[0] = circuit.RandomField()
	if err := env.applyShielded(t, from, 0, nil, anchor, nfs, cms, wei(-10), proof); err != pool.ErrInvalidProof {
		t.Fatalf("tampered tx: got %v, want ErrInvalidProof", err)
	}
}

// TestShieldedRejectsUnknownAnchor checks an anchor that is not a known root is
// rejected before any proof work.
func TestShieldedRejectsUnknownAnchor(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping shielded circuit proving in -short mode")
	}
	vk, err := circuit.DevnetSetup()
	if err != nil {
		t.Fatalf("DevnetSetup: %v", err)
	}
	env := newShieldedTestEnv(t)
	from := common.HexToAddress("0x4444444444444444444444444444444444444444")
	env.statedb.AddBalance(from, ether(100), 0)
	pool.New(env.statedb).InstallVerifyingKey(vk)

	noteA := circuit.RandomNote(wei(10))
	bogusAnchor := circuit.RandomField()
	asg, nfs, cms, err := circuit.BuildTransfer(env.tree, bogusAnchor, nil,
		[]circuit.Output{{Value: wei(10), Apk: noteA.Apk(), Rho: noteA.Rho}}, wei(-10))
	if err != nil {
		t.Fatal(err)
	}
	proof, _ := circuit.Prove(asg)
	if err := env.applyShielded(t, from, 0, nil, bogusAnchor, nfs, cms, wei(-10), proof); err != ErrShieldedUnknownAnchor {
		t.Fatalf("unknown anchor: got %v, want ErrShieldedUnknownAnchor", err)
	}
}
