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

// collectShares returns decryption shares from the given committee members.
func collectShares(shares []*KeyShare, ct *Ciphertext, idx ...int) []*DecryptionShare {
	out := make([]*DecryptionShare, 0, len(idx))
	for _, i := range idx {
		out = append(out, shares[i].Decrypt(ct))
	}
	return out
}

// TestEncryptDecryptRoundTrip checks that any t-of-n subset of honest members can
// recover the plaintext.
func TestEncryptDecryptRoundTrip(t *testing.T) {
	const tt, n = 3, 5
	pk, shares, _, err := DealerSetup(tt, n, rand.Reader)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	msg := []byte("confidential transaction payload")
	ct, err := Encrypt(pk, msg, rand.Reader)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Several different t-subsets must all decrypt to the same plaintext.
	subsets := [][]int{{0, 1, 2}, {2, 3, 4}, {0, 2, 4}, {1, 3, 4}}
	for _, sub := range subsets {
		got, err := Combine(tt, ct, collectShares(shares, ct, sub...))
		if err != nil {
			t.Fatalf("combine %v: %v", sub, err)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("combine %v: got %q, want %q", sub, got, msg)
		}
	}
}

// TestThresholdNotMet checks that fewer than t shares cannot decrypt.
func TestThresholdNotMet(t *testing.T) {
	const tt, n = 3, 5
	pk, shares, _, err := DealerSetup(tt, n, rand.Reader)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	ct, err := Encrypt(pk, []byte("secret"), rand.Reader)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	// t-1 shares: Combine must refuse.
	if _, err := Combine(tt, ct, collectShares(shares, ct, 0, 1)); err == nil {
		t.Fatal("combine succeeded with fewer than t shares")
	}
}

// TestWrongSubThresholdDoesNotLeak checks that combining a t-sized set that
// includes a forged/foreign share does not recover the plaintext: an attacker
// holding t-1 honest shares plus one wrong share learns nothing.
func TestWrongShareFailsToDecrypt(t *testing.T) {
	const tt, n = 3, 5
	pk, shares, _, err := DealerSetup(tt, n, rand.Reader)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	ct, err := Encrypt(pk, []byte("secret"), rand.Reader)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	// Two honest shares plus a share from an unrelated committee.
	_, otherShares, _, _ := DealerSetup(tt, n, rand.Reader)
	bad := collectShares(shares, ct, 0, 1)
	bad = append(bad, otherShares[2].Decrypt(ct))

	if msg, err := Combine(tt, ct, bad); err == nil {
		t.Fatalf("combine succeeded with a foreign share, leaking %q", msg)
	}
}

// TestVerifyShare checks share verifiability: honest shares verify, and a share
// from the wrong member or a tampered share is rejected (decryption-share abuse
// is detectable).
func TestVerifyShare(t *testing.T) {
	const tt, n = 2, 4
	pk, shares, vks, err := DealerSetup(tt, n, rand.Reader)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	ct, err := Encrypt(pk, []byte("secret"), rand.Reader)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	for i := range shares {
		share := shares[i].Decrypt(ct)
		if !VerifyShare(vks[i], ct, share) {
			t.Fatalf("honest share %d failed verification", i)
		}
		// Verifying against the wrong member's key must fail.
		wrong := vks[(i+1)%n]
		if VerifyShare(wrong, ct, share) {
			t.Fatalf("share %d verified against the wrong member's key", i)
		}
	}

	// A forged share (from a foreign committee, same index) must not verify.
	_, otherShares, _, _ := DealerSetup(tt, n, rand.Reader)
	forged := otherShares[0].Decrypt(ct)
	if VerifyShare(vks[0], ct, forged) {
		t.Fatal("forged decryption share passed verification")
	}
}

// TestCombineDuplicateIndices ensures duplicate share indices are rejected (a
// caller cannot reach the threshold by replaying one member's share).
func TestCombineDuplicateIndices(t *testing.T) {
	const tt, n = 2, 3
	pk, shares, _, err := DealerSetup(tt, n, rand.Reader)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	ct, err := Encrypt(pk, []byte("secret"), rand.Reader)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	s0 := shares[0].Decrypt(ct)
	if _, err := Combine(tt, ct, []*DecryptionShare{s0, s0}); err != errDuplicate {
		t.Fatalf("combine with duplicate index: err = %v, want %v", err, errDuplicate)
	}
}

// TestCiphertextMarshal checks ciphertext serialization round-trips and that the
// decoded ciphertext still decrypts.
func TestCiphertextMarshal(t *testing.T) {
	const tt, n = 2, 3
	pk, shares, _, err := DealerSetup(tt, n, rand.Reader)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	msg := []byte("round-trip me")
	ct, err := Encrypt(pk, msg, rand.Reader)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	blob, err := ct.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	dec, err := UnmarshalCiphertext(blob)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	got, err := Combine(tt, dec, collectShares(shares, dec, 0, 2))
	if err != nil {
		t.Fatalf("combine after round-trip: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("got %q, want %q", got, msg)
	}
}

// TestPublicKeyMarshal checks public-key serialization round-trips and remains
// usable for encryption.
func TestPublicKeyMarshal(t *testing.T) {
	const tt, n = 2, 3
	pk, shares, _, err := DealerSetup(tt, n, rand.Reader)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	blob, err := pk.Marshal()
	if err != nil {
		t.Fatalf("marshal pk: %v", err)
	}
	pk2, err := UnmarshalPublicKey(blob)
	if err != nil {
		t.Fatalf("unmarshal pk: %v", err)
	}
	msg := []byte("encrypt with decoded key")
	ct, err := Encrypt(pk2, msg, rand.Reader)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	got, err := Combine(tt, ct, collectShares(shares, ct, 0, 1))
	if err != nil {
		t.Fatalf("combine: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("got %q, want %q", got, msg)
	}
}

// TestBadParams checks parameter validation.
func TestBadParams(t *testing.T) {
	if _, _, _, err := DealerSetup(0, 3, rand.Reader); err == nil {
		t.Fatal("t=0 accepted")
	}
	if _, _, _, err := DealerSetup(4, 3, rand.Reader); err == nil {
		t.Fatal("t>n accepted")
	}
}
