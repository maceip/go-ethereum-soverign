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
	"github.com/ethereum/go-ethereum/core/privacy/encmempool"
	"github.com/ethereum/go-ethereum/core/privacy/keyper"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/params"
)

// encryptedTxSource implements miner.EncryptedTxSource: at block-building time it
// decrypts the threshold-encrypted envelopes the encrypted mempool is holding,
// using committee decryption shares from a ShareProvider, and returns the recovered
// inner transactions for direct inclusion in the block. Decrypted transactions are
// never added to the public pool, so their contents stay hidden until inclusion.
type encryptedTxSource struct {
	pool        *encmempool.Pool
	registry    *keyper.Registry
	provider    encmempool.ShareProvider
	chainConfig *params.ChainConfig
}

var encDecryptedMeter = metrics.NewRegisteredMeter("eth/encmempool/decrypted", nil)

// accountState is the slice of state the source needs: the registry storage and
// account nonces. *state.StateDB satisfies it.
type accountState interface {
	GetState(addr common.Address, key common.Hash) common.Hash
	GetNonce(addr common.Address) uint64
}

func newEncryptedTxSource(pool *encmempool.Pool, registryAddr common.Address, provider encmempool.ShareProvider, cfg *params.ChainConfig) *encryptedTxSource {
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
	// Encrypted-mempool inclusion is gated by the privacy fork.
	if !s.chainConfig.IsPrivacy1(header.Number, header.Time) {
		return nil
	}
	t := s.registry.Threshold(st)
	if t < 1 {
		return nil
	}
	envelopes := s.pool.Pending()
	if len(envelopes) == 0 {
		return nil
	}
	decrypted := encmempool.Decrypt(envelopes, t, s.provider)
	signer := types.LatestSigner(s.chainConfig)

	out := make([]*types.Transaction, 0, len(decrypted))
	for _, d := range decrypted {
		from, err := types.Sender(signer, d.Tx)
		if err != nil {
			s.pool.Remove(d.EnvelopeID) // not a usable transaction; drop it
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
		log.Debug("Decrypted encrypted-mempool transactions for inclusion", "count", len(out))
	}
	return out
}
