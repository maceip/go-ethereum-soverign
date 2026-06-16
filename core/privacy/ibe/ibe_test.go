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

package ibe

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/ethereum/go-ethereum/core/privacy/keyper"
	"github.com/ethereum/go-ethereum/core/privacy/threshold"
)

// committee builds a DKG committee and the IBE master public key derived from it.
func committee(t *testing.T, tt, n int) (*MasterPublicKey, []*threshold.KeyShare, []*threshold.VerificationKey) {
	t.Helper()
	_, shares, vks, err := keyper.RunDKG(tt, n, rand.Reader)
	if err != nil {
		t.Fatalf("dkg: %v", err)
	}
	mpk, err := DeriveMasterPublicKey(vks, tt)
	if err != nil {
		t.Fatalf("derive mpk: %v", err)
	}
	return mpk, shares, vks
}

// epochKey releases and combines the epoch key from the given committee members.
func epochKey(t *testing.T, tt int, epoch uint64, shares []*threshold.KeyShare, vks []*threshold.VerificationKey, idx ...int) *EpochKey {
	t.Helper()
	ss := make([]*EpochKeyShare, 0, len(idx))
	for _, i := range idx {
		s, err := EpochShare(shares[i], epoch)
		if err != nil {
			t.Fatalf("epoch share: %v", err)
		}
		if !VerifyEpochShare(vks[i], epoch, s) {
			t.Fatalf("epoch share %d failed verification", i)
		}
		ss = append(ss, s)
	}
	sk, err := CombineEpochKey(tt, epoch, ss)
	if err != nil {
		t.Fatalf("combine epoch key: %v", err)
	}
	return sk
}

// TestIBERoundTrip checks encryption to an epoch and decryption with that epoch's
// committee-released key, across several committee subsets.
func TestIBERoundTrip(t *testing.T) {
	const tt, n = 3, 5
	mpk, shares, vks := committee(t, tt, n)
	const epoch = 42
	msg := []byte("confidential transaction for epoch 42")

	ct, err := Encrypt(mpk, epoch, msg, rand.Reader)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	for _, sub := range [][]int{{0, 1, 2}, {1, 3, 4}, {0, 2, 4}} {
		sk := epochKey(t, tt, epoch, shares, vks, sub...)
		got, err := Decrypt(sk, ct)
		if err != nil {
			t.Fatalf("decrypt %v: %v", sub, err)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("decrypt %v: got %q", sub, got)
		}
	}
}

// TestIBEEpochIsolation is the crux: the key released for one epoch cannot decrypt
// a ciphertext for a different epoch. This is what makes the per-epoch trigger
// cryptographic — a future epoch's transactions are undecryptable until that
// epoch's key is released.
func TestIBEEpochIsolation(t *testing.T) {
	const tt, n = 3, 5
	mpk, shares, vks := committee(t, tt, n)

	ct, err := Encrypt(mpk, 100, []byte("only for epoch 100"), rand.Reader)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	// Release the key for a different epoch.
	wrongKey := epochKey(t, tt, 99, shares, vks, 0, 1, 2)
	if _, err := Decrypt(wrongKey, ct); err == nil {
		t.Fatal("epoch-99 key decrypted an epoch-100 ciphertext")
	}
	// The correct epoch key works.
	rightKey := epochKey(t, tt, 100, shares, vks, 0, 1, 2)
	if _, err := Decrypt(rightKey, ct); err != nil {
		t.Fatalf("correct epoch key failed: %v", err)
	}
}

// TestIBEThreshold checks fewer than t epoch-key shares cannot reconstruct a usable
// key.
func TestIBEThreshold(t *testing.T) {
	const tt, n = 3, 5
	mpk, shares, vks := committee(t, tt, n)
	const epoch = 7
	ct, _ := Encrypt(mpk, epoch, []byte("secret"), rand.Reader)

	// Combine with only t-1 shares: CombineEpochKey must refuse.
	ss := make([]*EpochKeyShare, 0, tt-1)
	for i := 0; i < tt-1; i++ {
		s, _ := EpochShare(shares[i], epoch)
		ss = append(ss, s)
	}
	if _, err := CombineEpochKey(tt, epoch, ss); err == nil {
		t.Fatal("combined an epoch key with fewer than t shares")
	}
	_ = ct
	_ = vks
}

// TestIBERejectsForeignShare checks an epoch-key share from an unrelated committee
// does not verify and does not yield a working key.
func TestIBERejectsForeignShare(t *testing.T) {
	const tt, n = 2, 3
	mpk, shares, vks := committee(t, tt, n)
	_, foreignShares, _, err := keyper.RunDKG(tt, n, rand.Reader)
	if err != nil {
		t.Fatalf("foreign dkg: %v", err)
	}
	const epoch = 5

	honest, _ := EpochShare(shares[0], epoch)
	foreign, _ := EpochShare(foreignShares[1], epoch)
	foreign.Index = shares[1].Index // re-label so the index check passes

	if VerifyEpochShare(vks[1], epoch, foreign) {
		t.Fatal("foreign epoch-key share passed verification")
	}

	// Combining honest + foreign yields a key that does not decrypt.
	ct, _ := Encrypt(mpk, epoch, []byte("secret"), rand.Reader)
	sk, err := CombineEpochKey(tt, epoch, []*EpochKeyShare{honest, foreign})
	if err != nil {
		t.Fatalf("combine: %v", err)
	}
	if _, err := Decrypt(sk, ct); err == nil {
		t.Fatal("foreign-share key decrypted the ciphertext")
	}
}

// TestDeriveMasterPublicKeyConsistent checks mpk derived from different t-subsets of
// verification keys is the same (it is s·G2 regardless of subset).
func TestDeriveMasterPublicKeyConsistent(t *testing.T) {
	const tt, n = 3, 5
	_, _, vks := committee(t, tt, n)
	mpk1, err := DeriveMasterPublicKey(vks[:tt], tt)
	if err != nil {
		t.Fatalf("derive 1: %v", err)
	}
	mpk2, err := DeriveMasterPublicKey(vks[2:2+tt], tt)
	if err != nil {
		t.Fatalf("derive 2: %v", err)
	}
	if !bytes.Equal(mpk1.Point.Marshal(), mpk2.Point.Marshal()) {
		t.Fatal("master public key differs between verification-key subsets")
	}
}
