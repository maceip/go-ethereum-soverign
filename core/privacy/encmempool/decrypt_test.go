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

package encmempool

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/privacy/threshold"
	"github.com/ethereum/go-ethereum/core/types"
)

// encryptTx threshold-encrypts a transaction's canonical encoding and returns the
// buffered envelope.
func encryptTx(t *testing.T, pk *threshold.PublicKey, tx *types.Transaction) *Envelope {
	t.Helper()
	raw, err := tx.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal tx: %v", err)
	}
	ct, err := threshold.Encrypt(pk, raw, rand.Reader)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	blob, err := ct.Marshal()
	if err != nil {
		t.Fatalf("marshal ct: %v", err)
	}
	env, err := NewEnvelope(blob)
	if err != nil {
		t.Fatalf("envelope: %v", err)
	}
	return env
}

func sampleTx(nonce uint64) *types.Transaction {
	return types.NewTransaction(nonce, common.Address{0xde, 0xad}, big.NewInt(1), 21000, big.NewInt(1), nil)
}

// TestDecryptRecoversInnerTxs checks the full path: encrypt transactions to the
// committee key, buffer the envelopes, and recover the exact inner transactions
// with a threshold of committee shares.
func TestDecryptRecoversInnerTxs(t *testing.T) {
	const tt, n = 3, 5
	pk, shares, _, err := threshold.DealerSetup(tt, n, rand.Reader)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	provider := NewLocalShareProvider(shares)

	txs := []*types.Transaction{sampleTx(0), sampleTx(1), sampleTx(2)}
	envs := make([]*Envelope, len(txs))
	for i, tx := range txs {
		envs[i] = encryptTx(t, pk, tx)
	}

	dec := Decrypt(envs, tt, provider)
	if len(dec) != len(txs) {
		t.Fatalf("decrypted %d txs, want %d", len(dec), len(txs))
	}
	for i, d := range dec {
		if d.Tx.Hash() != txs[i].Hash() {
			t.Fatalf("decrypted tx %d hash mismatch", i)
		}
		if d.EnvelopeID != envs[i].ID() {
			t.Fatalf("decrypted tx %d envelope id mismatch", i)
		}
	}
}

// TestDecryptInsufficientSharesSkips checks that envelopes for which the committee
// has not released a threshold of shares are skipped, not aborted on.
func TestDecryptInsufficientSharesSkips(t *testing.T) {
	const tt, n = 3, 5
	pk, shares, _, err := threshold.DealerSetup(tt, n, rand.Reader)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	// Provider holding only t-1 shares cannot reach the threshold.
	provider := NewLocalShareProvider(shares[:tt-1])
	env := encryptTx(t, pk, sampleTx(0))

	if dec := Decrypt([]*Envelope{env}, tt, provider); len(dec) != 0 {
		t.Fatalf("decrypted %d with insufficient shares, want 0", len(dec))
	}
}

// TestDecryptMalformedSkips checks that a non-ciphertext or non-transaction
// envelope is skipped rather than aborting the batch, and good envelopes alongside
// it still decrypt.
func TestDecryptMalformedSkips(t *testing.T) {
	const tt, n = 2, 3
	pk, shares, _, err := threshold.DealerSetup(tt, n, rand.Reader)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	provider := NewLocalShareProvider(shares)

	good := encryptTx(t, pk, sampleTx(0))
	garbage, _ := NewEnvelope([]byte("not a ciphertext"))
	// A valid ciphertext whose plaintext is not a transaction.
	ctNonTx, _ := threshold.Encrypt(pk, []byte("hello, not a tx"), rand.Reader)
	blob, _ := ctNonTx.Marshal()
	nonTx, _ := NewEnvelope(blob)

	dec := Decrypt([]*Envelope{garbage, good, nonTx}, tt, provider)
	if len(dec) != 1 {
		t.Fatalf("decrypted %d, want exactly the one good tx", len(dec))
	}
	if dec[0].Tx.Hash() != sampleTx(0).Hash() {
		t.Fatal("decrypted the wrong transaction")
	}
}
