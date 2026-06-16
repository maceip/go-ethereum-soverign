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
	"github.com/ethereum/go-ethereum/core/privacy/ibe"
	"github.com/ethereum/go-ethereum/core/privacy/threshold"
	"github.com/ethereum/go-ethereum/core/types"
)

// testEpochProvider releases epoch keys from in-process committee shares, gated by
// a trigger epoch, standing in for the keyper network.
type testEpochProvider struct {
	shares  []*threshold.KeyShare
	trigger uint64
}

func (p *testEpochProvider) EpochKey(epoch uint64, t int) *ibe.EpochKey {
	if epoch > p.trigger || len(p.shares) < t {
		return nil
	}
	ss := make([]*ibe.EpochKeyShare, 0, t)
	for i := 0; i < t; i++ {
		s, err := ibe.EpochShare(p.shares[i], epoch)
		if err != nil {
			return nil
		}
		ss = append(ss, s)
	}
	sk, err := ibe.CombineEpochKey(t, epoch, ss)
	if err != nil {
		return nil
	}
	return sk
}

func ibeCommittee(t *testing.T, tt, n int) (*ibe.MasterPublicKey, []*threshold.KeyShare) {
	t.Helper()
	_, shares, vks, err := threshold.DealerSetup(tt, n, rand.Reader)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	mpk, err := ibe.DeriveMasterPublicKey(vks, tt)
	if err != nil {
		t.Fatalf("derive mpk: %v", err)
	}
	return mpk, shares
}

func encryptTx(t *testing.T, mpk *ibe.MasterPublicKey, epoch uint64, tx *types.Transaction) *Envelope {
	t.Helper()
	raw, err := tx.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal tx: %v", err)
	}
	ct, err := ibe.Encrypt(mpk, epoch, raw, rand.Reader)
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

// TestDecryptRecoversInnerTxs checks the full path: encrypt transactions for an
// epoch, buffer the envelopes, and recover the exact inner transactions once the
// epoch key is released.
func TestDecryptRecoversInnerTxs(t *testing.T) {
	const tt, n = 3, 5
	const epoch = 11
	mpk, shares := ibeCommittee(t, tt, n)
	provider := &testEpochProvider{shares: shares, trigger: epoch}

	txs := []*types.Transaction{sampleTx(0), sampleTx(1), sampleTx(2)}
	envs := make([]*Envelope, len(txs))
	for i, tx := range txs {
		envs[i] = encryptTx(t, mpk, epoch, tx)
	}
	dec := Decrypt(envs, tt, provider)
	if len(dec) != len(txs) {
		t.Fatalf("decrypted %d txs, want %d", len(dec), len(txs))
	}
	for i, d := range dec {
		if d.Tx.Hash() != txs[i].Hash() {
			t.Fatalf("decrypted tx %d hash mismatch", i)
		}
	}
}

// TestDecryptEpochNotReleasedSkips checks envelopes whose epoch key the committee
// has not released are skipped (the trigger has not fired).
func TestDecryptEpochNotReleasedSkips(t *testing.T) {
	const tt, n = 3, 5
	mpk, shares := ibeCommittee(t, tt, n)
	// Trigger only up to epoch 5; the envelope targets epoch 6.
	provider := &testEpochProvider{shares: shares, trigger: 5}
	env := encryptTx(t, mpk, 6, sampleTx(0))
	if dec := Decrypt([]*Envelope{env}, tt, provider); len(dec) != 0 {
		t.Fatalf("decrypted %d for an unreleased epoch, want 0", len(dec))
	}
}

// TestDecryptMalformedSkips checks a non-IBE or non-transaction envelope is skipped
// while a good one alongside still decrypts.
func TestDecryptMalformedSkips(t *testing.T) {
	const tt, n = 2, 3
	const epoch = 1
	mpk, shares := ibeCommittee(t, tt, n)
	provider := &testEpochProvider{shares: shares, trigger: epoch}

	good := encryptTx(t, mpk, epoch, sampleTx(0))
	garbage, _ := NewEnvelope([]byte("not an ibe ciphertext"))
	ctNonTx, _ := ibe.Encrypt(mpk, epoch, []byte("hello, not a tx"), rand.Reader)
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
