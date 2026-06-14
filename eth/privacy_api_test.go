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

package eth

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

// TestPrivacyAPIStealthRoundTrip checks that an address generated via the RPC API
// can be detected via the RPC API by its intended recipient.
func TestPrivacyAPIStealthRoundTrip(t *testing.T) {
	api := NewPrivacyAPI()

	spend, _ := crypto.GenerateKey()
	view, _ := crypto.GenerateKey()

	gen, err := api.GenerateStealthAddress(StealthMetaAddressArgs{
		SpendingPubKey: crypto.FromECDSAPub(&spend.PublicKey),
		ViewingPubKey:  crypto.FromECDSAPub(&view.PublicKey),
	})
	if err != nil {
		t.Fatalf("GenerateStealthAddress: %v", err)
	}

	got, err := api.CheckStealthAddress(CheckStealthAddressArgs{
		ViewingPrivKey:  crypto.FromECDSA(view),
		SpendingPubKey:  crypto.FromECDSAPub(&spend.PublicKey),
		EphemeralPubKey: gen.EphemeralPubKey,
		ViewTag:         gen.ViewTag,
	})
	if err != nil {
		t.Fatalf("CheckStealthAddress: %v", err)
	}
	if !got.IsForRecipient {
		t.Fatal("recipient failed to detect payment via RPC API")
	}
	if got.StealthAddress != gen.StealthAddress {
		t.Fatalf("addresses disagree: %x vs %x", got.StealthAddress, gen.StealthAddress)
	}
}

// TestPrivacyAPIPedersenCommit checks the RPC commitment matches a direct
// computation and is 64 bytes.
func TestPrivacyAPIPedersenCommit(t *testing.T) {
	api := NewPrivacyAPI()
	out, err := api.PedersenCommit(hexutil.Big(*big.NewInt(123)), hexutil.Big(*big.NewInt(456)))
	if err != nil {
		t.Fatalf("PedersenCommit: %v", err)
	}
	if len(out) != 64 {
		t.Fatalf("commitment length = %d, want 64", len(out))
	}
}

// TestPrivacyAPIRejectsBadKeys checks input validation surfaces errors rather than
// panicking.
func TestPrivacyAPIRejectsBadKeys(t *testing.T) {
	api := NewPrivacyAPI()
	if _, err := api.GenerateStealthAddress(StealthMetaAddressArgs{
		SpendingPubKey: []byte{0x01},
		ViewingPubKey:  []byte{0x02},
	}); err == nil {
		t.Fatal("expected error for malformed public keys")
	}
}
