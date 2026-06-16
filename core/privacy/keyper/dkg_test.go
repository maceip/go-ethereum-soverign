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

package keyper

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/core/privacy/threshold"
	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
)

// TestDKGProducesWorkingCommittee runs a full DKG and checks that the resulting
// committee key encrypts and that any t-of-n DKG shares decrypt — i.e. the DKG is
// a drop-in trustless replacement for the trusted dealer.
func TestDKGProducesWorkingCommittee(t *testing.T) {
	const tt, n = 3, 5
	eon, shares, vks, err := RunDKG(tt, n, rand.Reader)
	if err != nil {
		t.Fatalf("dkg: %v", err)
	}
	if len(shares) != n || len(vks) != n {
		t.Fatalf("got %d shares, %d vks, want %d", len(shares), len(vks), n)
	}

	msg := []byte("decrypted only by a keyper threshold")
	ct, err := threshold.Encrypt(eon, msg, rand.Reader)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Multiple distinct t-subsets of DKG shares must all decrypt.
	for _, sub := range [][]int{{0, 1, 2}, {1, 3, 4}, {0, 2, 4}} {
		ds := make([]*threshold.DecryptionShare, 0, tt)
		for _, i := range sub {
			ds = append(ds, shares[i].Decrypt(ct))
		}
		got, err := threshold.Combine(tt, ct, ds)
		if err != nil {
			t.Fatalf("combine %v: %v", sub, err)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("combine %v: got %q", sub, got)
		}
	}

	// DKG verification keys must match the DKG shares.
	for i := range shares {
		if !threshold.VerifyShare(vks[i], ct, shares[i].Decrypt(ct)) {
			t.Fatalf("dkg verification key %d does not match its share", i)
		}
	}
}

// TestDKGThreshold checks t-1 DKG shares cannot decrypt.
func TestDKGThreshold(t *testing.T) {
	const tt, n = 3, 5
	eon, shares, _, err := RunDKG(tt, n, rand.Reader)
	if err != nil {
		t.Fatalf("dkg: %v", err)
	}
	ct, err := threshold.Encrypt(eon, []byte("secret"), rand.Reader)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	ds := []*threshold.DecryptionShare{shares[0].Decrypt(ct), shares[1].Decrypt(ct)}
	if _, err := threshold.Combine(tt, ct, ds); err == nil {
		t.Fatal("decrypted with fewer than t DKG shares")
	}
}

// TestFeldmanVerifyDetectsBadShare checks the Feldman check accepts honest shares
// and rejects a tampered one (a cheating dealer).
func TestFeldmanVerifyDetectsBadShare(t *testing.T) {
	const tt, n = 2, 4
	p, err := NewParticipant(1, tt, n, rand.Reader)
	if err != nil {
		t.Fatalf("participant: %v", err)
	}
	comms := p.Commitments()
	for j := uint32(1); j <= n; j++ {
		if !VerifyShare(comms, j, p.Share(j)) {
			t.Fatalf("honest share for %d failed verification", j)
		}
	}
	// Tamper with a share: must be rejected.
	bad := new(big.Int).Add(p.Share(2), big.NewInt(1))
	if VerifyShare(comms, 2, bad) {
		t.Fatal("tampered share passed Feldman verification")
	}
}

// TestDKGEonKeyAggregates checks AggregateEonKey combines per-keyper commitments
// into a usable committee key (no single keyper holds the master secret).
func TestDKGEonKeyAggregates(t *testing.T) {
	const tt, n = 2, 3
	raw := make([][]*bn256.G1, n)
	for i := 0; i < n; i++ {
		p, err := NewParticipant(uint32(i+1), tt, n, rand.Reader)
		if err != nil {
			t.Fatalf("participant: %v", err)
		}
		raw[i] = p.Commitments()
	}
	eon, err := AggregateEonKey(raw)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if eon == nil || eon.P == nil {
		t.Fatal("nil eon key")
	}
	if _, err := AggregateEonKey(nil); err == nil {
		t.Fatal("aggregate accepted empty input")
	}
}
