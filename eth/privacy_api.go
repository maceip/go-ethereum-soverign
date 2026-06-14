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
	"crypto/ecdsa"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/privacy"
	"github.com/ethereum/go-ethereum/crypto"
)

// PrivacyAPI exposes the node-side privacy primitives from package privacy over
// JSON-RPC under the "privacy" namespace. It addresses the Phase 1 "UX & Wallet
// Integration" item of the Ethereum Privacy roadmap, which calls for wallets to be
// able to generate stealth addresses and confidential-value commitments without
// users needing to be cryptography experts:
//
//	"Wallets must handle stealth address generation, encryption, and proof
//	 generation automatically."
//
// These are stateless cryptographic helpers; they do not touch chain state, hold
// keys, or sign anything, so the namespace is safe to expose to wallet tooling.
type PrivacyAPI struct{}

// NewPrivacyAPI creates a new PrivacyAPI instance.
func NewPrivacyAPI() *PrivacyAPI { return &PrivacyAPI{} }

// StealthMetaAddressArgs is a recipient's published stealth meta-address, encoded
// as two uncompressed/compressed secp256k1 public keys.
type StealthMetaAddressArgs struct {
	SpendingPubKey hexutil.Bytes `json:"spendingPubKey"`
	ViewingPubKey  hexutil.Bytes `json:"viewingPubKey"`
}

// StealthAddressResult is the public output of a stealth-address derivation.
type StealthAddressResult struct {
	StealthAddress  common.Address `json:"stealthAddress"`
	EphemeralPubKey hexutil.Bytes  `json:"ephemeralPubKey"`
	ViewTag         hexutil.Uint   `json:"viewTag"`
}

// GenerateStealthAddress derives a fresh one-time stealth address (EIP-5564) for
// the supplied meta-address. The returned ephemeral public key must be published
// (e.g. via a stealth-announcer event) so the recipient can detect and later spend
// the payment.
func (api *PrivacyAPI) GenerateStealthAddress(meta StealthMetaAddressArgs) (*StealthAddressResult, error) {
	spend, err := unmarshalPubkey(meta.SpendingPubKey)
	if err != nil {
		return nil, errors.New("invalid spendingPubKey: " + err.Error())
	}
	view, err := unmarshalPubkey(meta.ViewingPubKey)
	if err != nil {
		return nil, errors.New("invalid viewingPubKey: " + err.Error())
	}
	payment, err := privacy.GenerateStealthAddress(privacy.StealthMetaAddress{Spend: spend, View: view})
	if err != nil {
		return nil, err
	}
	return &StealthAddressResult{
		StealthAddress:  payment.StealthAddress,
		EphemeralPubKey: crypto.FromECDSAPub(payment.EphemeralPubKey),
		ViewTag:         hexutil.Uint(payment.ViewTag),
	}, nil
}

// CheckStealthAddressArgs are the inputs for scanning a single stealth
// announcement against the recipient's keys.
type CheckStealthAddressArgs struct {
	ViewingPrivKey  hexutil.Bytes `json:"viewingPrivKey"`
	SpendingPubKey  hexutil.Bytes `json:"spendingPubKey"`
	EphemeralPubKey hexutil.Bytes `json:"ephemeralPubKey"`
	ViewTag         hexutil.Uint  `json:"viewTag"`
}

// CheckStealthAddressResult reports whether an announcement belongs to the caller.
type CheckStealthAddressResult struct {
	IsForRecipient bool           `json:"isForRecipient"`
	StealthAddress common.Address `json:"stealthAddress"`
}

// CheckStealthAddress reports whether a published stealth announcement is a payment
// to the holder of the given viewing key, using only the (non-spending) viewing
// key so it is safe for watch-only scanners.
func (api *PrivacyAPI) CheckStealthAddress(args CheckStealthAddressArgs) (*CheckStealthAddressResult, error) {
	viewKey, err := crypto.ToECDSA(args.ViewingPrivKey)
	if err != nil {
		return nil, errors.New("invalid viewingPrivKey: " + err.Error())
	}
	spendPub, err := unmarshalPubkey(args.SpendingPubKey)
	if err != nil {
		return nil, errors.New("invalid spendingPubKey: " + err.Error())
	}
	ephemeralPub, err := unmarshalPubkey(args.EphemeralPubKey)
	if err != nil {
		return nil, errors.New("invalid ephemeralPubKey: " + err.Error())
	}
	addr, ok, err := privacy.CheckStealthAddress(viewKey, spendPub, ephemeralPub, byte(args.ViewTag))
	if err != nil {
		return nil, err
	}
	return &CheckStealthAddressResult{IsForRecipient: ok, StealthAddress: addr}, nil
}

// PedersenCommit returns the Pedersen commitment C = value*G + blinding*H for the
// supplied amount and blinding factor, encoded as a 64-byte bn256 G1 point. This
// is the same commitment the PEDERSEN_COMMIT (0x12) precompile computes, allowing
// a wallet to build confidential outputs off-chain that contracts can verify
// on-chain.
func (api *PrivacyAPI) PedersenCommit(value, blinding hexutil.Big) (hexutil.Bytes, error) {
	out, err := privacy.Commit((*big.Int)(&value), (*big.Int)(&blinding))
	if err != nil {
		return nil, err
	}
	return out, nil
}

// unmarshalPubkey parses a secp256k1 public key in either the 65-byte
// uncompressed or 33-byte compressed encoding.
func unmarshalPubkey(b []byte) (*ecdsa.PublicKey, error) {
	if len(b) == 33 {
		return crypto.DecompressPubkey(b)
	}
	return crypto.UnmarshalPubkey(b)
}
