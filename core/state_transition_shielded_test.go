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
	"bytes"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/privacy/pool"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

// digestCircuit is the stand-in shielded-transfer circuit used by these tests. It
// has a single public input D (the public digest binding the transaction) and a
// secret X, and asserts D == X. This exercises the full consensus verification
// plumbing (digest reconstruction -> witness build -> PlonK verify) with a real
// proof; the production circuit replaces the trivial constraint with Merkle
// membership, nullifier derivation and value-conservation constraints over the
// same public digest.
type digestCircuit struct {
	D frontend.Variable `gnark:",public"`
	X frontend.Variable `gnark:",secret"`
}

func (c *digestCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.D, c.X)
	return nil
}

// shieldedProver holds a one-time circuit setup so each test can cheaply produce a
// proof binding a given public digest.
type shieldedProver struct {
	ccs   constraint.ConstraintSystem
	pk    plonk.ProvingKey
	vk    plonk.VerifyingKey
	vkRaw []byte
}

func newShieldedProver(t *testing.T) *shieldedProver {
	t.Helper()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &digestCircuit{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	if err != nil {
		t.Fatalf("srs: %v", err)
	}
	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	var buf bytes.Buffer
	if _, err := vk.WriteTo(&buf); err != nil {
		t.Fatalf("vk encode: %v", err)
	}
	return &shieldedProver{ccs: ccs, pk: pk, vk: vk, vkRaw: buf.Bytes()}
}

// prove returns a serialized PlonK proof for the statement "public digest == d".
func (p *shieldedProver) prove(t *testing.T, d *big.Int) []byte {
	t.Helper()
	full, err := frontend.NewWitness(&digestCircuit{D: d, X: d}, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	proof, err := plonk.Prove(p.ccs, p.pk, full)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	var buf bytes.Buffer
	if _, err := proof.WriteTo(&buf); err != nil {
		t.Fatalf("proof encode: %v", err)
	}
	return buf.Bytes()
}

// shieldedTestEnv bundles the state, EVM and config for driving ApplyMessage.
type shieldedTestEnv struct {
	statedb *state.StateDB
	evm     *vm.EVM
	cfg     *params.ChainConfig
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
	return &shieldedTestEnv{statedb: statedb, evm: evm, cfg: &cfgCopy}
}

func hashByte(b byte) common.Hash {
	var h common.Hash
	h[0] = b
	return h
}

func ether(n int64) *uint256.Int {
	return new(uint256.Int).Mul(uint256.NewInt(uint64(n)), uint256.NewInt(params.Ether))
}

// applyShielded builds and applies a shielded message with zero gas price (so gas
// is free and the test focuses on shielded settlement).
func (env *shieldedTestEnv) applyShielded(t *testing.T, from common.Address, nonce uint64, to *common.Address, sd *ShieldedData) error {
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
		Shielded:  sd,
	}
	_, err := ApplyMessage(env.evm, msg, NewGasPool(10_000_000))
	return err
}

// TestShieldedLifecycle exercises shield -> unshield -> double-spend end to end
// through ApplyMessage against a real StateDB.
func TestShieldedLifecycle(t *testing.T) {
	prover := newShieldedProver(t)
	env := newShieldedTestEnv(t)

	from := common.HexToAddress("0x1111111111111111111111111111111111111111")
	recipient := common.HexToAddress("0x2222222222222222222222222222222222222222")
	env.statedb.AddBalance(from, ether(100), 0)

	// Install the circuit verifying key into the shielded pool.
	pool.New(env.statedb).InstallVerifyingKey(prover.vkRaw)

	// --- Shield 10 ETH ---------------------------------------------------------
	// Fresh pool: the anchor must be the empty/zero root.
	commit1 := hashByte(0xc1)
	shieldVB := new(big.Int).Neg(new(big.Int).Mul(big.NewInt(10), big.NewInt(params.Ether)))
	shieldSD := &ShieldedData{
		Anchor:       common.Hash{},
		Nullifiers:   nil,
		Commitments:  []common.Hash{commit1},
		ValueBalance: shieldVB,
	}
	shieldSD.Proof = prover.prove(t, pool.PublicDigest(shieldSD.Anchor, shieldSD.Nullifiers, shieldSD.Commitments, shieldSD.ValueBalance))

	if err := env.applyShielded(t, from, 0, nil, shieldSD); err != nil {
		t.Fatalf("shield failed: %v", err)
	}
	if got := env.statedb.GetBalance(from); got.Cmp(ether(90)) != 0 {
		t.Fatalf("after shield, sender balance = %v, want 90 ETH", got)
	}
	if got := env.statedb.GetBalance(pool.SystemAddress); got.Cmp(ether(10)) != 0 {
		t.Fatalf("after shield, pool balance = %v, want 10 ETH", got)
	}
	p := pool.New(env.statedb)
	if p.Leaves() != 1 {
		t.Fatalf("after shield, pool leaves = %d, want 1", p.Leaves())
	}

	// --- Unshield 4 ETH to recipient ------------------------------------------
	anchor := p.Root()
	nullifier1 := hashByte(0x91)
	commit2 := hashByte(0xc2)
	unshieldVB := new(big.Int).Mul(big.NewInt(4), big.NewInt(params.Ether))
	unshieldSD := &ShieldedData{
		Anchor:       anchor,
		Nullifiers:   []common.Hash{nullifier1},
		Commitments:  []common.Hash{commit2},
		ValueBalance: unshieldVB,
	}
	unshieldSD.Proof = prover.prove(t, pool.PublicDigest(unshieldSD.Anchor, unshieldSD.Nullifiers, unshieldSD.Commitments, unshieldSD.ValueBalance))

	if err := env.applyShielded(t, from, 1, &recipient, unshieldSD); err != nil {
		t.Fatalf("unshield failed: %v", err)
	}
	if got := env.statedb.GetBalance(recipient); got.Cmp(ether(4)) != 0 {
		t.Fatalf("after unshield, recipient balance = %v, want 4 ETH", got)
	}
	if got := env.statedb.GetBalance(pool.SystemAddress); got.Cmp(ether(6)) != 0 {
		t.Fatalf("after unshield, pool balance = %v, want 6 ETH", got)
	}
	if !pool.New(env.statedb).IsNullifierSpent(nullifier1) {
		t.Fatal("nullifier not marked spent after unshield")
	}

	// --- Double-spend the same nullifier --------------------------------------
	anchor2 := pool.New(env.statedb).Root()
	dsSD := &ShieldedData{
		Anchor:       anchor2,
		Nullifiers:   []common.Hash{nullifier1}, // reused
		Commitments:  nil,
		ValueBalance: big.NewInt(0),
	}
	dsSD.Proof = prover.prove(t, pool.PublicDigest(dsSD.Anchor, dsSD.Nullifiers, dsSD.Commitments, dsSD.ValueBalance))
	if err := env.applyShielded(t, from, 2, nil, dsSD); err != ErrShieldedDoubleSpend {
		t.Fatalf("double spend: got %v, want ErrShieldedDoubleSpend", err)
	}
}

// TestShieldedRejectsBadProof checks a proof bound to different fields is rejected.
func TestShieldedRejectsBadProof(t *testing.T) {
	prover := newShieldedProver(t)
	env := newShieldedTestEnv(t)

	from := common.HexToAddress("0x3333333333333333333333333333333333333333")
	env.statedb.AddBalance(from, ether(100), 0)
	pool.New(env.statedb).InstallVerifyingKey(prover.vkRaw)

	sd := &ShieldedData{
		Anchor:       common.Hash{},
		Commitments:  []common.Hash{hashByte(0xaa)},
		ValueBalance: new(big.Int).Neg(big.NewInt(params.Ether)),
	}
	// Prove a digest for a DIFFERENT commitment than the one in the transaction.
	wrongDigest := pool.PublicDigest(sd.Anchor, sd.Nullifiers, []common.Hash{hashByte(0xbb)}, sd.ValueBalance)
	sd.Proof = prover.prove(t, wrongDigest)

	if err := env.applyShielded(t, from, 0, nil, sd); err != pool.ErrInvalidProof {
		t.Fatalf("bad proof: got %v, want ErrInvalidProof", err)
	}
}

// TestShieldedRejectsUnknownAnchor checks an anchor that is not a known root is
// rejected before any proof work.
func TestShieldedRejectsUnknownAnchor(t *testing.T) {
	prover := newShieldedProver(t)
	env := newShieldedTestEnv(t)

	from := common.HexToAddress("0x4444444444444444444444444444444444444444")
	env.statedb.AddBalance(from, ether(100), 0)
	pool.New(env.statedb).InstallVerifyingKey(prover.vkRaw)

	sd := &ShieldedData{
		Anchor:       hashByte(0xde), // not a known root on a fresh pool
		Commitments:  []common.Hash{hashByte(0xaa)},
		ValueBalance: new(big.Int).Neg(big.NewInt(params.Ether)),
	}
	sd.Proof = prover.prove(t, pool.PublicDigest(sd.Anchor, sd.Nullifiers, sd.Commitments, sd.ValueBalance))
	if err := env.applyShielded(t, from, 0, nil, sd); err != ErrShieldedUnknownAnchor {
		t.Fatalf("unknown anchor: got %v, want ErrShieldedUnknownAnchor", err)
	}
}
