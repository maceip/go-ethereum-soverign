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

package encmempool

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/privacy/threshold"
	"github.com/ethereum/go-ethereum/core/types"
)

// ShareProvider supplies threshold decryption shares for a ciphertext at inclusion
// time. In production it is backed by the keyper network, which releases shares
// when the per-epoch decryption trigger fires; a single-operator devnet may back
// it with locally-held committee shares (see LocalShareProvider). It returns fewer
// than `threshold` shares (or none) when the committee has not released enough,
// which makes the affected transaction stay encrypted.
type ShareProvider interface {
	Shares(ct *threshold.Ciphertext, threshold int) []*threshold.DecryptionShare
}

// DecryptedTx pairs a recovered inner transaction with the envelope it came from,
// so the caller can drop the envelope once the transaction is included.
type DecryptedTx struct {
	Tx         *types.Transaction
	EnvelopeID common.Hash
}

// Decrypt recovers inner transactions from the given envelopes using the share
// provider and threshold t. Recovery of one envelope never aborts the batch: an
// envelope is skipped when its ciphertext is malformed, the committee has not
// released t shares, the combined plaintext fails authentication, or the plaintext
// does not decode to a transaction. This "skip, don't abort" behaviour is the
// committee-unavailable fallback — one undecryptable envelope cannot stall block
// building.
func Decrypt(envelopes []*Envelope, t int, provider ShareProvider) []DecryptedTx {
	if t < 1 || provider == nil {
		return nil
	}
	out := make([]DecryptedTx, 0, len(envelopes))
	for _, env := range envelopes {
		ct, err := threshold.UnmarshalCiphertext(env.Ciphertext)
		if err != nil {
			continue
		}
		shares := provider.Shares(ct, t)
		if len(shares) < t {
			continue // committee has not released enough shares yet
		}
		plaintext, err := threshold.Combine(t, ct, shares)
		if err != nil {
			continue
		}
		tx := new(types.Transaction)
		if err := tx.UnmarshalBinary(plaintext); err != nil {
			continue // plaintext is not a transaction
		}
		out = append(out, DecryptedTx{Tx: tx, EnvelopeID: env.ID()})
	}
	return out
}

// LocalShareProvider holds committee key shares in-process and produces decryption
// shares itself.
//
// DEVNET ONLY. A single party holding the whole committee defeats the threshold
// trust model entirely. Production releases shares through the keyper network — a
// ShareProvider that collects shares from independent keyper processes — never from
// one process. This type exists for tests and single-operator devnets, and is
// labelled to make that misuse obvious.
type LocalShareProvider struct {
	keyShares []*threshold.KeyShare
}

// NewLocalShareProvider builds a devnet-only share provider from locally-held
// committee key shares.
func NewLocalShareProvider(shares []*threshold.KeyShare) *LocalShareProvider {
	return &LocalShareProvider{keyShares: shares}
}

// Shares produces up to t decryption shares for ct from the locally-held key
// shares, or nil if fewer than t are held.
func (p *LocalShareProvider) Shares(ct *threshold.Ciphertext, t int) []*threshold.DecryptionShare {
	if len(p.keyShares) < t {
		return nil
	}
	out := make([]*threshold.DecryptionShare, 0, t)
	for i := 0; i < t; i++ {
		out = append(out, p.keyShares[i].Decrypt(ct))
	}
	return out
}
