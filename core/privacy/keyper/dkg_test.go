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

func TestDKGProducesVerifiableThresholdCommittee(t *testing.T) {
	const thresholdSize, members = 3, 5
	eon, shares, vks, err := RunDKG(thresholdSize, members, rand.Reader)
	if err != nil {
		t.Fatalf("dkg: %v", err)
	}
	if len(shares) != members || len(vks) != members {
		t.Fatalf("got %d shares, %d verification keys, want %d", len(shares), len(vks), members)
	}
	plaintext := []byte("decrypted only by a keyper threshold")
	ct, err := threshold.Encrypt(eon, plaintext, rand.Reader)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	for _, subset := range [][]int{{0, 1, 2}, {1, 3, 4}, {0, 2, 4}} {
		var dshares []*threshold.DecryptionShare
		for _, i := range subset {
			share := shares[i].Decrypt(ct)
			if !threshold.VerifyShare(vks[i], ct, share) {
				t.Fatalf("share %d failed verification", i)
			}
			dshares = append(dshares, share)
		}
		got, err := threshold.Combine(thresholdSize, ct, dshares)
		if err != nil {
			t.Fatalf("combine %v: %v", subset, err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("combine %v recovered %q, want %q", subset, got, plaintext)
		}
	}
	if _, err := threshold.Combine(thresholdSize, ct, []*threshold.DecryptionShare{
		shares[0].Decrypt(ct),
		shares[1].Decrypt(ct),
	}); err == nil {
		t.Fatal("decrypted with fewer than threshold DKG shares")
	}
}

func TestDKGRejectsInvalidSharesAndAggregates(t *testing.T) {
	const thresholdSize, members = 2, 4
	p, err := NewParticipant(1, thresholdSize, members, rand.Reader)
	if err != nil {
		t.Fatalf("participant: %v", err)
	}
	commitments := p.Commitments()
	for j := uint32(1); j <= members; j++ {
		if !VerifyShare(commitments, j, p.Share(j)) {
			t.Fatalf("honest share for member %d failed verification", j)
		}
	}
	badShare := new(big.Int).Add(p.Share(2), big.NewInt(1))
	if VerifyShare(commitments, 2, badShare) {
		t.Fatal("tampered share passed Feldman verification")
	}
	if _, err := AggregateEonKey(nil); err == nil {
		t.Fatal("aggregate accepted empty commitments")
	}
	if _, err := AggregateEonKey([][]*bn256.G1{{}}); err == nil {
		t.Fatal("aggregate accepted an empty participant commitment")
	}
	raw := make([][]*bn256.G1, members)
	for i := 0; i < members; i++ {
		p, err := NewParticipant(uint32(i+1), thresholdSize, members, rand.Reader)
		if err != nil {
			t.Fatalf("participant %d: %v", i+1, err)
		}
		raw[i] = p.Commitments()
	}
	eon, err := AggregateEonKey(raw)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if eon == nil || eon.P == nil {
		t.Fatal("aggregate returned nil eon key")
	}
}
