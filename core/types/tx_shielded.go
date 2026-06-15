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

package types

import (
	"bytes"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
)

// ShieldedTx is the confidential ETH transaction introduced by Privacy Phase 1 of
// the "Ethereum Privacy: The Road to Self-Sovereignty" roadmap:
//
//	"Rethinking transaction formats: Introduce a new transaction structure
//	 supporting privacy natively. Transactions should obscure sender, recipient,
//	 and amounts while remaining compatible with Ethereum validation."
//
// A ShieldedTx operates against the protocol-native shielded pool (see
// core/privacy/pool). It spends existing shielded notes — referenced indirectly by
// their Nullifiers so the inputs are never revealed — and creates new shielded
// notes given by their Commitments. A single zero-knowledge Proof attests, against
// the note-commitment tree root Anchor, that:
//
//   - every spent note exists in the tree and its nullifier is correctly derived,
//   - the new commitments are well-formed, and
//   - value is conserved: Σ(input values) == Σ(output values) + ValueBalance.
//
// ValueBalance is the only value revealed publicly. It is the net amount entering
// (negative) or leaving (positive) the shielded pool in transparent ETH:
//
//   - ValueBalance < 0  ("shield"):   |ValueBalance| transparent ETH is debited
//     from the fee-paying account and locked into the pool.
//   - ValueBalance > 0  ("unshield"): ValueBalance transparent ETH is released
//     from the pool to the To address.
//   - ValueBalance == 0 ("transfer"): a fully shielded transfer; nothing about the
//     value is revealed.
//
// The transaction is authorised (and its gas paid) by an ordinary EOA signature,
// exactly like an EIP-1559 transaction, so existing nonce/fee mechanics and
// account-abstraction relayers continue to work. The signer need not be the owner
// of the shielded notes, enabling third-party fee payment for genuine privacy.
type ShieldedTx struct {
	ChainID   *big.Int
	Nonce     uint64
	GasTipCap *big.Int // a.k.a. maxPriorityFeePerGas
	GasFeeCap *big.Int // a.k.a. maxFeePerGas
	Gas       uint64

	// To is the transparent recipient of an unshield (ValueBalance > 0). It is nil
	// for pure shielded transfers and for shield operations.
	To *common.Address `rlp:"nil"`

	// Anchor is the note-commitment tree root the Proof is verified against. It
	// must be a recent root known to the shielded pool.
	Anchor common.Hash

	// Nullifiers are the unlinkable spend tags of the notes being consumed. The
	// pool rejects the transaction if any nullifier has already been spent.
	Nullifiers []common.Hash

	// Commitments are the new note commitments to append to the tree.
	Commitments []common.Hash

	// ValueBalance is the net transparent value moved (see type doc). It is a
	// signed quantity encoded as a big.Int.
	ValueBalance *big.Int

	// Proof is the zero-knowledge proof binding Anchor, Nullifiers, Commitments and
	// ValueBalance. Its encoding is the gnark PlonK (BN254) proof consumed by
	// core/privacy/zk.
	Proof []byte

	// Signature values of the fee-paying account.
	V *big.Int
	R *big.Int
	S *big.Int
}

// copy creates a deep copy of the transaction data and initializes all fields.
func (tx *ShieldedTx) copy() TxData {
	cpy := &ShieldedTx{
		Nonce:        tx.Nonce,
		To:           copyAddressPtr(tx.To),
		Gas:          tx.Gas,
		Anchor:       tx.Anchor,
		Nullifiers:   make([]common.Hash, len(tx.Nullifiers)),
		Commitments:  make([]common.Hash, len(tx.Commitments)),
		Proof:        common.CopyBytes(tx.Proof),
		ChainID:      new(big.Int),
		GasTipCap:    new(big.Int),
		GasFeeCap:    new(big.Int),
		ValueBalance: new(big.Int),
		V:            new(big.Int),
		R:            new(big.Int),
		S:            new(big.Int),
	}
	copy(cpy.Nullifiers, tx.Nullifiers)
	copy(cpy.Commitments, tx.Commitments)
	if tx.ChainID != nil {
		cpy.ChainID.Set(tx.ChainID)
	}
	if tx.GasTipCap != nil {
		cpy.GasTipCap.Set(tx.GasTipCap)
	}
	if tx.GasFeeCap != nil {
		cpy.GasFeeCap.Set(tx.GasFeeCap)
	}
	if tx.ValueBalance != nil {
		cpy.ValueBalance.Set(tx.ValueBalance)
	}
	if tx.V != nil {
		cpy.V.Set(tx.V)
	}
	if tx.R != nil {
		cpy.R.Set(tx.R)
	}
	if tx.S != nil {
		cpy.S.Set(tx.S)
	}
	return cpy
}

// accessors for innerTx.
func (tx *ShieldedTx) txType() byte           { return ShieldedTxType }
func (tx *ShieldedTx) chainID() *big.Int      { return tx.ChainID }
func (tx *ShieldedTx) accessList() AccessList { return nil }
func (tx *ShieldedTx) data() []byte           { return nil }
func (tx *ShieldedTx) gas() uint64            { return tx.Gas }
func (tx *ShieldedTx) gasFeeCap() *big.Int    { return tx.GasFeeCap }
func (tx *ShieldedTx) gasTipCap() *big.Int    { return tx.GasTipCap }
func (tx *ShieldedTx) gasPrice() *big.Int     { return tx.GasFeeCap }
func (tx *ShieldedTx) nonce() uint64          { return tx.Nonce }
func (tx *ShieldedTx) to() *common.Address    { return tx.To }

// value returns the transparent ETH value moved through the ordinary value path,
// which is always zero for a shielded transaction: all value movement (shield from
// the sender, unshield to the recipient) is settled against the shielded pool
// during state transition, not transferred from the fee-paying sender. The signed
// net amount is surfaced separately via Transaction.ShieldedValueBalance.
func (tx *ShieldedTx) value() *big.Int {
	return new(big.Int)
}

func (tx *ShieldedTx) effectiveGasPrice(dst *big.Int, baseFee *big.Int) *big.Int {
	if baseFee == nil {
		return dst.Set(tx.GasFeeCap)
	}
	tip := dst.Sub(tx.GasFeeCap, baseFee)
	if tip.Cmp(tx.GasTipCap) > 0 {
		tip.Set(tx.GasTipCap)
	}
	return tip.Add(tip, baseFee)
}

func (tx *ShieldedTx) rawSignatureValues() (v, r, s *big.Int) {
	return tx.V, tx.R, tx.S
}

func (tx *ShieldedTx) setSignatureValues(chainID, v, r, s *big.Int) {
	tx.ChainID, tx.V, tx.R, tx.S = chainID, v, r, s
}

// shieldedTxRLP is the wire representation of a ShieldedTx. RLP cannot encode a
// negative big.Int, so the signed ValueBalance is split into a sign flag (1 if
// negative, i.e. a shield) and a non-negative magnitude.
type shieldedTxRLP struct {
	ChainID         *big.Int
	Nonce           uint64
	GasTipCap       *big.Int
	GasFeeCap       *big.Int
	Gas             uint64
	To              *common.Address `rlp:"nil"`
	Anchor          common.Hash
	Nullifiers      []common.Hash
	Commitments     []common.Hash
	ValueBalanceNeg bool
	ValueBalanceMag *big.Int
	Proof           []byte
	V, R, S         *big.Int
}

func (tx *ShieldedTx) toRLP() *shieldedTxRLP {
	vb := tx.ValueBalance
	if vb == nil {
		vb = new(big.Int)
	}
	return &shieldedTxRLP{
		ChainID:         tx.ChainID,
		Nonce:           tx.Nonce,
		GasTipCap:       tx.GasTipCap,
		GasFeeCap:       tx.GasFeeCap,
		Gas:             tx.Gas,
		To:              tx.To,
		Anchor:          tx.Anchor,
		Nullifiers:      tx.Nullifiers,
		Commitments:     tx.Commitments,
		ValueBalanceNeg: vb.Sign() < 0,
		ValueBalanceMag: new(big.Int).Abs(vb),
		Proof:           tx.Proof,
		V:               tx.V,
		R:               tx.R,
		S:               tx.S,
	}
}

func (tx *ShieldedTx) fromRLP(dec *shieldedTxRLP) {
	tx.ChainID = dec.ChainID
	tx.Nonce = dec.Nonce
	tx.GasTipCap = dec.GasTipCap
	tx.GasFeeCap = dec.GasFeeCap
	tx.Gas = dec.Gas
	tx.To = dec.To
	tx.Anchor = dec.Anchor
	tx.Nullifiers = dec.Nullifiers
	tx.Commitments = dec.Commitments
	vb := dec.ValueBalanceMag
	if vb == nil {
		vb = new(big.Int)
	}
	if dec.ValueBalanceNeg {
		vb = new(big.Int).Neg(vb)
	}
	tx.ValueBalance = vb
	tx.Proof = dec.Proof
	tx.V, tx.R, tx.S = dec.V, dec.R, dec.S
}

func (tx *ShieldedTx) encode(b *bytes.Buffer) error {
	return rlp.Encode(b, tx.toRLP())
}

func (tx *ShieldedTx) decode(input []byte) error {
	var dec shieldedTxRLP
	if err := rlp.DecodeBytes(input, &dec); err != nil {
		return err
	}
	tx.fromRLP(&dec)
	return nil
}

func (tx *ShieldedTx) sigHash(chainID *big.Int) common.Hash {
	vb := tx.ValueBalance
	if vb == nil {
		vb = new(big.Int)
	}
	return prefixedRlpHash(
		ShieldedTxType,
		[]any{
			chainID,
			tx.Nonce,
			tx.GasTipCap,
			tx.GasFeeCap,
			tx.Gas,
			tx.To,
			tx.Anchor,
			tx.Nullifiers,
			tx.Commitments,
			vb.Sign() < 0,
			new(big.Int).Abs(vb),
			tx.Proof,
		})
}

// Shielded returns the shielded payload of the transaction together with a flag
// indicating whether this is a ShieldedTx. The returned struct is the live inner
// data and must not be mutated by callers.
func (tx *Transaction) Shielded() (*ShieldedTx, bool) {
	st, ok := tx.inner.(*ShieldedTx)
	return st, ok
}

// ShieldedValueBalance returns the signed net transparent value moved by a
// shielded transaction (negative = shield, positive = unshield). It returns nil
// for non-shielded transactions.
func (tx *Transaction) ShieldedValueBalance() *big.Int {
	if st, ok := tx.inner.(*ShieldedTx); ok && st.ValueBalance != nil {
		return new(big.Int).Set(st.ValueBalance)
	}
	return nil
}
