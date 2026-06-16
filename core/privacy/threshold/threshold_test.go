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

package threshold

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func collectShares(shares []*KeyShare, ct *Ciphertext, idx ...int) []*DecryptionShare {
	out := make([]*DecryptionShare, 0, len(idx))
	for _, i := range idx {
		out = append(out, shares[i].Decrypt(ct))
	}
	return out
}

func TestThresholdCommitteeBoundary(t *testing.T) {
	const threshold, members = 3, 5
	pk, shares, vks, err := DealerSetup(threshold, members, rand.Reader)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	plaintext := []byte("confidential transaction payload")
	ct, err := Encrypt(pk, plaintext, rand.Reader)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	for _, subset := range [][]int{{0, 1, 2}, {2, 3, 4}, {0, 2, 4}, {1, 3, 4}} {
		got, err := Combine(threshold, ct, collectShares(shares, ct, subset...))
		if err != nil {
			t.Fatalf("combine %v: %v", subset, err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("combine %v recovered %q, want %q", subset, got, plaintext)
		}
	}
	if _, err := Combine(threshold, ct, collectShares(shares, ct, 0, 1)); err == nil {
		t.Fatal("combined with fewer than threshold shares")
	}
	s0 := shares[0].Decrypt(ct)
	if _, err := Combine(2, ct, []*DecryptionShare{s0, s0}); err != errDuplicate {
		t.Fatalf("duplicate share err = %v, want %v", err, errDuplicate)
	}

	for i := range shares {
		share := shares[i].Decrypt(ct)
		if !VerifyShare(vks[i], ct, share) {
			t.Fatalf("honest share %d failed verification", i)
		}
		if VerifyShare(vks[(i+1)%members], ct, share) {
			t.Fatalf("share %d verified against the wrong member key", i)
		}
	}
	_, foreignShares, _, err := DealerSetup(threshold, members, rand.Reader)
	if err != nil {
		t.Fatalf("foreign setup: %v", err)
	}
	bad := append(collectShares(shares, ct, 0, 1), foreignShares[2].Decrypt(ct))
	if msg, err := Combine(threshold, ct, bad); err == nil {
		t.Fatalf("combined with a foreign share, leaking %q", msg)
	}
	if VerifyShare(vks[0], ct, foreignShares[0].Decrypt(ct)) {
		t.Fatal("foreign share passed verification")
	}
}

func TestThresholdSerializationAndValidation(t *testing.T) {
	const threshold, members = 2, 3
	pk, shares, _, err := DealerSetup(threshold, members, rand.Reader)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	pkBlob, err := pk.Marshal()
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	decodedPK, err := UnmarshalPublicKey(pkBlob)
	if err != nil {
		t.Fatalf("unmarshal public key: %v", err)
	}
	plaintext := []byte("round-trip me")
	ct, err := Encrypt(decodedPK, plaintext, rand.Reader)
	if err != nil {
		t.Fatalf("encrypt with decoded key: %v", err)
	}
	ctBlob, err := ct.Marshal()
	if err != nil {
		t.Fatalf("marshal ciphertext: %v", err)
	}
	decodedCT, err := UnmarshalCiphertext(ctBlob)
	if err != nil {
		t.Fatalf("unmarshal ciphertext: %v", err)
	}
	got, err := Combine(threshold, decodedCT, collectShares(shares, decodedCT, 0, 2))
	if err != nil {
		t.Fatalf("combine decoded ciphertext: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("decoded ciphertext recovered %q, want %q", got, plaintext)
	}
	if _, _, _, err := DealerSetup(0, members, rand.Reader); err == nil {
		t.Fatal("accepted zero threshold")
	}
	if _, _, _, err := DealerSetup(members+1, members, rand.Reader); err == nil {
		t.Fatal("accepted threshold greater than member count")
	}
}
