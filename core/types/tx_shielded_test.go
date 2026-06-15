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

package types

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func sampleShieldedTx() *ShieldedTx {
	to := common.HexToAddress("0xabcdef0000000000000000000000000000000001")
	return &ShieldedTx{
		ChainID:      big.NewInt(1),
		Nonce:        7,
		GasTipCap:    big.NewInt(1),
		GasFeeCap:    big.NewInt(100),
		Gas:          500000,
		To:           &to,
		Anchor:       common.HexToHash("0x1234"),
		Nullifiers:   []common.Hash{common.HexToHash("0xaa"), common.HexToHash("0xbb")},
		Commitments:  []common.Hash{common.HexToHash("0xcc")},
		ValueBalance: big.NewInt(-4200),
		Proof:        []byte{0x01, 0x02, 0x03, 0x04},
	}
}

// TestShieldedTxRoundTrip checks RLP binary encode/decode preserves all fields.
func TestShieldedTxRoundTrip(t *testing.T) {
	tx := NewTx(sampleShieldedTx())
	if tx.Type() != ShieldedTxType {
		t.Fatalf("type = %d, want %d", tx.Type(), ShieldedTxType)
	}

	bin, err := tx.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if bin[0] != ShieldedTxType {
		t.Fatalf("envelope type byte = %d, want %d", bin[0], ShieldedTxType)
	}

	var got Transaction
	if err := got.UnmarshalBinary(bin); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}
	st, ok := got.Shielded()
	if !ok {
		t.Fatal("decoded tx is not a ShieldedTx")
	}
	want := sampleShieldedTx()
	if st.Anchor != want.Anchor || len(st.Nullifiers) != 2 || len(st.Commitments) != 1 {
		t.Fatal("shielded fields not preserved")
	}
	if st.ValueBalance.Cmp(want.ValueBalance) != 0 {
		t.Fatalf("valueBalance = %v, want %v", st.ValueBalance, want.ValueBalance)
	}
	if !bytes.Equal(st.Proof, want.Proof) {
		t.Fatal("proof not preserved")
	}
	if got.ShieldedValueBalance().Cmp(want.ValueBalance) != 0 {
		t.Fatal("ShieldedValueBalance mismatch")
	}
	// A shielded tx never moves transparent value through the ordinary path.
	if got.Value().Sign() != 0 {
		t.Fatalf("Value() = %v, want 0", got.Value())
	}
}

// TestShieldedTxSignRecover checks the fee payer's signature recovers correctly
// under the modern (Prague) signer.
func TestShieldedTxSignRecover(t *testing.T) {
	key, _ := crypto.GenerateKey()
	addr := crypto.PubkeyToAddress(key.PublicKey)
	signer := NewPragueSigner(big.NewInt(1))

	tx, err := SignTx(NewTx(sampleShieldedTx()), signer, key)
	if err != nil {
		t.Fatalf("SignTx: %v", err)
	}
	from, err := Sender(signer, tx)
	if err != nil {
		t.Fatalf("Sender: %v", err)
	}
	if from != addr {
		t.Fatalf("recovered %x, want %x", from, addr)
	}
}

// TestShieldedTxCopy checks copy() produces an independent deep copy.
func TestShieldedTxCopy(t *testing.T) {
	orig := sampleShieldedTx()
	cpy := orig.copy().(*ShieldedTx)

	cpy.ValueBalance.SetInt64(999)
	cpy.Nullifiers[0] = common.HexToHash("0xdead")
	if orig.ValueBalance.Int64() == 999 {
		t.Fatal("copy shares ValueBalance with original")
	}
	if orig.Nullifiers[0] == common.HexToHash("0xdead") {
		t.Fatal("copy shares Nullifiers slice with original")
	}
}
