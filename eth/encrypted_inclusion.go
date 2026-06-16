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
	"github.com/ethereum/go-ethereum/common"
	encbuf "github.com/ethereum/go-ethereum/core/privacy/encmempool"
	"github.com/ethereum/go-ethereum/core/privacy/ibe"
	"github.com/ethereum/go-ethereum/core/privacy/keyper"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/params"
)

// encryptedTxSource implements miner.EncryptedTxSource: at block-building time it
// decrypts the threshold-IBE-encrypted envelopes the encrypted mempool is holding,
// using per-epoch committee keys released by the keyper network, and returns the
// recovered inner transactions for direct inclusion. Decrypted transactions are
// never added to the public pool, so their contents stay hidden until inclusion.
//
// The block being built defines the current epoch (its block number). Only
// envelopes whose target epoch is due (<= the block epoch) are attempted, and a
// transaction is recovered only if the committee has released that epoch's key —
// so a transaction targeted at a future epoch is cryptographically undecryptable
// until that epoch arrives.
type encryptedTxSource struct {
	pool        *encbuf.Pool
	registry    *keyper.Registry
	provider    encbuf.EpochKeyProvider
	chainConfig *params.ChainConfig
}

var (
	// encDecryptedMeter counts envelopes decrypted and included at block build.
	encDecryptedMeter = metrics.NewRegisteredMeter("eth/encmempool/decrypted", nil)
	// encUndecryptableMeter counts envelopes that were due for the block but could
	// not be decrypted (the committee had not released the epoch key) — the
	// committee-unavailable fallback, surfaced for observability.
	encUndecryptableMeter = metrics.NewRegisteredMeter("eth/encmempool/undecryptable", nil)
)

// accountState is the slice of state the source needs: the registry storage and
// account nonces. *state.StateDB satisfies it.
type accountState interface {
	GetState(addr common.Address, key common.Hash) common.Hash
	GetNonce(addr common.Address) uint64
}

func newEncryptedTxSource(pool *encbuf.Pool, registryAddr common.Address, provider encbuf.EpochKeyProvider, cfg *params.ChainConfig) *encryptedTxSource {
	return &encryptedTxSource{
		pool:        pool,
		registry:    keyper.NewRegistry(registryAddr),
		provider:    provider,
		chainConfig: cfg,
	}
}

// DecryptForBlock implements miner.EncryptedTxSource.
func (s *encryptedTxSource) DecryptForBlock(header *types.Header, st *state.StateDB) []*types.Transaction {
	if st == nil {
		return nil
	}
	return s.decrypt(header, st)
}

// decrypt is the testable core of DecryptForBlock, abstracted over the state.
func (s *encryptedTxSource) decrypt(header *types.Header, st accountState) []*types.Transaction {
	if s == nil || s.pool == nil || s.provider == nil || st == nil {
		return nil
	}
	if !s.chainConfig.IsPrivacy1(header.Number, header.Time) {
		return nil
	}
	t := s.registry.Threshold(st)
	if t < 1 {
		return nil
	}
	blockEpoch := header.Number.Uint64()

	// Only attempt envelopes whose target epoch is due for this block.
	all := s.pool.Pending()
	due := make([]*encbuf.Envelope, 0, len(all))
	for _, env := range all {
		ct, err := ibe.UnmarshalCiphertext(env.Ciphertext)
		if err != nil {
			s.pool.Remove(env.ID()) // not an IBE ciphertext; drop junk
			continue
		}
		if ct.Epoch <= blockEpoch {
			due = append(due, env)
		}
	}

	decrypted := encbuf.Decrypt(due, t, s.provider)
	if undecryptable := len(due) - len(decrypted); undecryptable > 0 {
		// Due envelopes the committee has not unlocked stay buffered for a later
		// block; record the gap so the fallback is observable.
		encUndecryptableMeter.Mark(int64(undecryptable))
		log.Debug("Encrypted-mempool envelopes due but not decryptable", "count", undecryptable, "epoch", blockEpoch)
	}
	signer := types.LatestSigner(s.chainConfig)

	out := make([]*types.Transaction, 0, len(decrypted))
	for _, d := range decrypted {
		from, err := types.Sender(signer, d.Tx)
		if err != nil {
			s.pool.Remove(d.EnvelopeID)
			continue
		}
		// An envelope whose inner transaction nonce is already consumed has been
		// included in an earlier block; drop it and do not re-include.
		if d.Tx.Nonce() < st.GetNonce(from) {
			s.pool.Remove(d.EnvelopeID)
			continue
		}
		out = append(out, d.Tx)
	}
	if len(out) > 0 {
		encDecryptedMeter.Mark(int64(len(out)))
		log.Debug("Decrypted encrypted-mempool transactions for inclusion", "count", len(out), "epoch", blockEpoch)
	}
	return out
}
