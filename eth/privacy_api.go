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
	"github.com/ethereum/go-ethereum/core/privacy/circuit"
	"github.com/ethereum/go-ethereum/core/privacy/pool"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// privacyBackend exposes the chain state the privacy RPC needs.
type privacyBackend interface {
	CurrentShieldedState() (*state.StateDB, error)
	ChainID() *big.Int
	Privacy1Active() bool
}

// PrivacyAPI exposes the node-side privacy primitives from package privacy over
// JSON-RPC under the "privacy" namespace. It addresses the Phase 1 "UX & Wallet
// Integration" item of the Ethereum Privacy roadmap, which calls for wallets to be
// able to generate stealth addresses and confidential-value commitments without
// users needing to be cryptography experts:
//
//	"Wallets must handle stealth address generation, encryption, and proof
//	 generation automatically."
//
// It exposes read-only shielded-pool introspection (PoolInfo), an unsigned
// shield-transaction builder (BuildShield), and stateless cryptographic helpers
// (stealth addresses, Pedersen commitments). The API never holds private keys and
// never signs: BuildShield returns an unsigned transaction for the caller to sign
// and submit, and emits the created note's secret to the caller only.
type PrivacyAPI struct {
	b privacyBackend // may be nil for the stateless helpers
}

// NewPrivacyAPI creates a new PrivacyAPI instance backed by the given chain
// accessor. b may be nil, in which case only the stateless helpers are usable.
func NewPrivacyAPI(b privacyBackend) *PrivacyAPI { return &PrivacyAPI{b: b} }

// PoolInfoResult describes the current state of the shielded pool.
type PoolInfoResult struct {
	Active bool           `json:"active"` // whether Privacy Phase 1 is active
	Root   common.Hash    `json:"root"`   // current note-commitment tree root
	Leaves hexutil.Uint64 `json:"leaves"` // number of note commitments
}

// PoolInfo returns the live shielded-pool root and size, so wallets can pick a
// valid anchor and know their note indices.
func (api *PrivacyAPI) PoolInfo() (*PoolInfoResult, error) {
	if api.b == nil {
		return nil, errors.New("privacy: node backend unavailable")
	}
	if !api.b.Privacy1Active() {
		return &PoolInfoResult{Active: false}, nil
	}
	st, err := api.b.CurrentShieldedState()
	if err != nil {
		return nil, err
	}
	p := pool.New(st)
	return &PoolInfoResult{Active: true, Root: p.Root(), Leaves: hexutil.Uint64(p.Leaves())}, nil
}

// ShieldArgs requests a confidential deposit of Value wei from the fee-paying
// account into the shielded pool, creating a single shielded note.
type ShieldArgs struct {
	Value     *hexutil.Big   `json:"value"`                // amount to shield (wei)
	Nonce     hexutil.Uint64 `json:"nonce"`                // fee-payer nonce
	Gas       hexutil.Uint64 `json:"gas"`                  // gas limit
	GasFeeCap *hexutil.Big   `json:"maxFeePerGas"`         // fee cap
	GasTipCap *hexutil.Big   `json:"maxPriorityFeePerGas"` // priority fee
}

// ShieldResult is the output of BuildShield: an unsigned, RLP-encoded ShieldedTx
// ready to be signed and submitted, plus the secret of the created note so the
// owner can later spend it.
type ShieldResult struct {
	UnsignedTx hexutil.Bytes `json:"unsignedTx"` // EIP-2718 encoding (unsigned)
	NoteValue  *hexutil.Big  `json:"noteValue"`
	NoteAsk    common.Hash   `json:"noteAsk"` // note spending key (KEEP SECRET)
	NoteRho    common.Hash   `json:"noteRho"` // note randomness (KEEP SECRET)
}

// BuildShield assembles and proves a shield transaction against the current pool
// state, creating a fresh note owned by a newly generated note key. It returns the
// unsigned transaction for the caller to sign with the fee-payer key and submit via
// eth_sendRawTransaction, along with the note secret needed to spend the note
// later. Proving runs the (devnet) prover and may take a few seconds.
func (api *PrivacyAPI) BuildShield(args ShieldArgs) (*ShieldResult, error) {
	if api.b == nil {
		return nil, errors.New("privacy: node backend unavailable")
	}
	if !api.b.Privacy1Active() {
		return nil, errors.New("privacy: Phase 1 not active on this chain")
	}
	if args.Value == nil || (*big.Int)(args.Value).Sign() <= 0 {
		return nil, errors.New("privacy: shield value must be positive")
	}
	if _, err := circuit.DevnetSetup(); err != nil {
		return nil, err
	}
	st, err := api.b.CurrentShieldedState()
	if err != nil {
		return nil, err
	}
	anchor := pool.New(st).Root()
	value := (*big.Int)(args.Value)

	note := circuit.RandomNote(value)
	asg, nfs, cms, err := circuit.BuildTransfer(circuit.NewTree(), anchor, nil,
		[]circuit.Output{{Value: value, Apk: note.Apk(), Rho: note.Rho}}, new(big.Int).Neg(value))
	if err != nil {
		return nil, err
	}
	proof, err := circuit.Prove(asg)
	if err != nil {
		return nil, err
	}
	tx := types.NewTx(&types.ShieldedTx{
		ChainID:      api.b.ChainID(),
		Nonce:        uint64(args.Nonce),
		GasTipCap:    bigOrZero(args.GasTipCap),
		GasFeeCap:    bigOrZero(args.GasFeeCap),
		Gas:          uint64(args.Gas),
		Anchor:       anchor,
		Nullifiers:   nfs,
		Commitments:  cms,
		ValueBalance: new(big.Int).Neg(value),
		Proof:        proof,
	})
	enc, err := tx.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return &ShieldResult{
		UnsignedTx: enc,
		NoteValue:  (*hexutil.Big)(value),
		NoteAsk:    note.Ask,
		NoteRho:    note.Rho,
	}, nil
}

func bigOrZero(v *hexutil.Big) *big.Int {
	if v == nil {
		return new(big.Int)
	}
	return (*big.Int)(v)
}

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
// ethPrivacyBackend adapts *Ethereum to privacyBackend.
type ethPrivacyBackend struct{ eth *Ethereum }

func (b ethPrivacyBackend) CurrentShieldedState() (*state.StateDB, error) {
	return b.eth.BlockChain().State()
}

func (b ethPrivacyBackend) ChainID() *big.Int { return b.eth.BlockChain().Config().ChainID }

func (b ethPrivacyBackend) Privacy1Active() bool {
	bc := b.eth.BlockChain()
	head := bc.CurrentBlock()
	return bc.Config().IsPrivacy1(head.Number, head.Time)
}

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
