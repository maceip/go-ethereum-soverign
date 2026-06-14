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

package privacy

import (
	"crypto/ecdsa"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestStealthRoundTrip exercises the full EIP-5564 flow: a sender derives a
// stealth address, the recipient detects it with its viewing key, and the
// recipient reconstructs the controlling private key with its spending key.
func TestStealthRoundTrip(t *testing.T) {
	spend := newKey(t)
	view := newKey(t)
	meta := StealthMetaAddress{Spend: &spend.PublicKey, View: &view.PublicKey}

	payment, err := GenerateStealthAddress(meta)
	if err != nil {
		t.Fatalf("GenerateStealthAddress: %v", err)
	}

	// Recipient scans the announcement and must detect the payment.
	addr, ok, err := CheckStealthAddress(view, &spend.PublicKey, payment.EphemeralPubKey, payment.ViewTag)
	if err != nil {
		t.Fatalf("CheckStealthAddress: %v", err)
	}
	if !ok {
		t.Fatal("recipient failed to detect its own payment")
	}
	if addr != payment.StealthAddress {
		t.Fatalf("detected address %x != sender address %x", addr, payment.StealthAddress)
	}

	// Recipient derives the spending key and it must control the stealth address.
	stealthKey, err := ComputeStealthKey(spend, view, payment.EphemeralPubKey)
	if err != nil {
		t.Fatalf("ComputeStealthKey: %v", err)
	}
	if got := crypto.PubkeyToAddress(stealthKey.PublicKey); got != payment.StealthAddress {
		t.Fatalf("derived key controls %x, want %x", got, payment.StealthAddress)
	}
}

// TestStealthUnlinkability checks that two payments to the same meta-address
// produce different one-time addresses, so on-chain observers cannot link them.
func TestStealthUnlinkability(t *testing.T) {
	spend := newKey(t)
	view := newKey(t)
	meta := StealthMetaAddress{Spend: &spend.PublicKey, View: &view.PublicKey}

	p1, err := GenerateStealthAddress(meta)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := GenerateStealthAddress(meta)
	if err != nil {
		t.Fatal(err)
	}
	if p1.StealthAddress == p2.StealthAddress {
		t.Fatal("two payments produced the same stealth address (linkable)")
	}
}

// TestStealthWrongRecipient ensures an unrelated viewing key does not match a
// payment, and that even when the (1/256) view-tag collision happens the derived
// address differs.
func TestStealthWrongRecipient(t *testing.T) {
	spend := newKey(t)
	view := newKey(t)
	meta := StealthMetaAddress{Spend: &spend.PublicKey, View: &view.PublicKey}

	payment, err := GenerateStealthAddress(meta)
	if err != nil {
		t.Fatal(err)
	}

	otherView := newKey(t)
	addr, ok, err := CheckStealthAddress(otherView, &spend.PublicKey, payment.EphemeralPubKey, payment.ViewTag)
	if err != nil {
		t.Fatal(err)
	}
	if ok && addr == payment.StealthAddress {
		t.Fatal("unrelated viewing key recovered the stealth address")
	}
}

// TestComputeStealthKeyDeterministic checks the recipient and sender agree on the
// stealth public key when driven from a fixed ephemeral key.
func TestComputeStealthKeyDeterministic(t *testing.T) {
	spend := newKey(t)
	view := newKey(t)
	ephemeral := newKey(t)
	meta := StealthMetaAddress{Spend: &spend.PublicKey, View: &view.PublicKey}

	payment, err := generateStealthAddress(meta, ephemeral)
	if err != nil {
		t.Fatal(err)
	}
	stealthKey, err := ComputeStealthKey(spend, view, &ephemeral.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if crypto.PubkeyToAddress(stealthKey.PublicKey) != payment.StealthAddress {
		t.Fatal("sender and recipient disagree on stealth address")
	}
}
