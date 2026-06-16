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
	"github.com/ethereum/go-ethereum/core/privacy/ibe"
	"github.com/ethereum/go-ethereum/core/types"
)

// EpochKeyProvider supplies the committee epoch key for a given epoch at inclusion
// time, or nil if it has not been released (the decryption trigger for that epoch
// has not fired, or too few keypers are available). In production it is backed by
// the keyper network. threshold is the committee decryption threshold.
type EpochKeyProvider interface {
	EpochKey(epoch uint64, threshold int) *ibe.EpochKey
}

// DecryptedTx pairs a recovered inner transaction with the envelope it came from,
// so the caller can drop the envelope once the transaction is included.
type DecryptedTx struct {
	Tx         *types.Transaction
	EnvelopeID common.Hash
}

// Decrypt recovers inner transactions from envelopes whose epoch decryption key has
// been released by the committee. Envelopes are grouped by epoch and one epoch key
// is fetched per epoch; each ciphertext is then decrypted and decoded. Recovery
// never aborts the batch: an envelope is skipped when its ciphertext is malformed,
// its epoch key has not been released, the IBE decryption fails, or the plaintext
// does not decode to a transaction. This "skip, don't abort" behaviour is the
// committee-unavailable fallback.
func Decrypt(envelopes []*Envelope, threshold int, provider EpochKeyProvider) []DecryptedTx {
	if threshold < 1 || provider == nil {
		return nil
	}
	// Cache epoch keys so each epoch is fetched/combined at most once per call.
	keys := make(map[uint64]*ibe.EpochKey)
	fetched := make(map[uint64]bool)

	out := make([]DecryptedTx, 0, len(envelopes))
	for _, env := range envelopes {
		ct, err := ibe.UnmarshalCiphertext(env.Ciphertext)
		if err != nil {
			continue
		}
		key, ok := keys[ct.Epoch]
		if !ok && !fetched[ct.Epoch] {
			key = provider.EpochKey(ct.Epoch, threshold)
			keys[ct.Epoch] = key
			fetched[ct.Epoch] = true
		}
		if key == nil {
			continue // epoch key not released; transaction stays encrypted
		}
		plaintext, err := ibe.Decrypt(key, ct)
		if err != nil {
			continue
		}
		tx := new(types.Transaction)
		if err := tx.UnmarshalBinary(plaintext); err != nil {
			continue
		}
		out = append(out, DecryptedTx{Tx: tx, EnvelopeID: env.ID()})
	}
	return out
}
