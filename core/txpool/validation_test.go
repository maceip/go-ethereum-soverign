// Copyright 2025 The go-ethereum Authors
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

package txpool

import (
	"crypto/ecdsa"
	"errors"
	"math"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

// TestValidateShieldedDepositFunding checks that a shielded deposit (a shield with
// negative ValueBalance) is rejected at txpool admission when the fee payer cannot
// cover the deposit amount, even though the transaction's transparent value is
// zero. Otherwise underfunded shields would enter and propagate through the pool
// only to fail during execution.
func TestValidateShieldedDepositFunding(t *testing.T) {
	key, _ := crypto.GenerateKey()
	from := crypto.PubkeyToAddress(key.PublicKey)
	signer := types.LatestSigner(params.MergedTestChainConfig)

	mkShield := func(deposit *big.Int) *types.Transaction {
		tx, err := types.SignTx(types.NewTx(&types.ShieldedTx{
			ChainID:      params.MergedTestChainConfig.ChainID,
			Nonce:        0,
			GasTipCap:    big.NewInt(0),
			GasFeeCap:    big.NewInt(0),
			Gas:          1_000_000,
			Anchor:       common.Hash{},
			Nullifiers:   []common.Hash{{1}, {2}},
			Commitments:  []common.Hash{{3}, {4}},
			ValueBalance: new(big.Int).Neg(deposit), // negative => shield
			Proof:        []byte{0x01},
		}), signer, key)
		if err != nil {
			t.Fatal(err)
		}
		return tx
	}

	newState := func(balanceEth int64) *state.StateDB {
		sdb, err := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
		if err != nil {
			t.Fatal(err)
		}
		bal := new(uint256.Int).Mul(uint256.NewInt(uint64(balanceEth)), uint256.NewInt(params.Ether))
		sdb.AddBalance(from, bal, 0)
		return sdb
	}

	opts := func(sdb *state.StateDB) *ValidationOptionsWithState {
		return &ValidationOptionsWithState{
			State:               sdb,
			ExistingExpenditure: func(common.Address) *big.Int { return new(big.Int) },
			ExistingCost:        func(common.Address, uint64) *big.Int { return nil },
		}
	}

	deposit := new(big.Int).Mul(big.NewInt(10), big.NewInt(params.Ether))

	// Underfunded: 5 ETH balance, 10 ETH shield deposit -> must be rejected.
	if err := ValidateTransactionWithState(mkShield(deposit), signer, opts(newState(5))); !errors.Is(err, core.ErrInsufficientFunds) {
		t.Fatalf("underfunded shield: got %v, want ErrInsufficientFunds", err)
	}
	// Funded: 100 ETH balance -> must be accepted.
	if err := ValidateTransactionWithState(mkShield(deposit), signer, opts(newState(100))); err != nil {
		t.Fatalf("funded shield rejected: %v", err)
	}
}

func TestValidateTransactionEIP2681(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	head := &types.Header{
		Number:     big.NewInt(1),
		GasLimit:   5000000,
		Time:       1,
		Difficulty: big.NewInt(1),
	}

	signer := types.LatestSigner(params.TestChainConfig)

	// Create validation options
	opts := &ValidationOptions{
		Config:       params.TestChainConfig,
		Accept:       0xFF, // Accept all transaction types
		MaxSize:      32 * 1024,
		MaxBlobCount: 6,
		MinTip:       big.NewInt(0),
	}

	tests := []struct {
		name    string
		nonce   uint64
		wantErr error
	}{
		{
			name:    "normal nonce",
			nonce:   42,
			wantErr: nil,
		},
		{
			name:    "max allowed nonce (2^64-2)",
			nonce:   math.MaxUint64 - 1,
			wantErr: nil,
		},
		{
			name:    "EIP-2681 nonce overflow (2^64-1)",
			nonce:   math.MaxUint64,
			wantErr: core.ErrNonceMax,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := createTestTransaction(key, tt.nonce)
			err := ValidateTransaction(tx, head, signer, opts)

			if tt.wantErr == nil {
				if err != nil {
					t.Errorf("ValidateTransaction() error = %v, wantErr nil", err)
				}
			} else {
				if err == nil {
					t.Errorf("ValidateTransaction() error = nil, wantErr %v", tt.wantErr)
				} else if !errors.Is(err, tt.wantErr) {
					t.Errorf("ValidateTransaction() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
		})
	}
}

// createTestTransaction creates a basic transaction for testing
func createTestTransaction(key *ecdsa.PrivateKey, nonce uint64) *types.Transaction {
	to := common.HexToAddress("0x0000000000000000000000000000000000000001")

	txdata := &types.LegacyTx{
		Nonce:    nonce,
		To:       &to,
		Value:    big.NewInt(1000),
		Gas:      21000,
		GasPrice: big.NewInt(1),
		Data:     nil,
	}

	tx := types.NewTx(txdata)
	signedTx, _ := types.SignTx(tx, types.HomesteadSigner{}, key)
	return signedTx
}
