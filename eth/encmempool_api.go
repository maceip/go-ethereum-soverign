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
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	encbuf "github.com/ethereum/go-ethereum/core/privacy/encmempool"
	"github.com/ethereum/go-ethereum/core/privacy/ibe"
	"github.com/ethereum/go-ethereum/core/privacy/keyper"
)

// EncMempoolAPI is the user-facing RPC for the encrypted mempool, served under the
// "privacy" namespace. A wallet encrypts a transaction to the committee (eon) key
// client-side and submits the opaque ciphertext here; the node never sees the
// plaintext. This is the submit path the encrypted mempool needs to be useful, and
// it makes no guarantee the client cannot keep: the node only buffers and gossips
// ciphertext, and the transaction is decrypted by the keyper committee at inclusion.
type EncMempoolAPI struct {
	eth *Ethereum
}

// NewEncMempoolAPI creates the encrypted-mempool RPC.
func NewEncMempoolAPI(eth *Ethereum) *EncMempoolAPI { return &EncMempoolAPI{eth: eth} }

// CommitteeInfo describes the encrypted-mempool committee so wallets can encrypt to
// it (IBE: encrypt to the master public key together with a target epoch).
type CommitteeInfo struct {
	MasterPublicKey hexutil.Bytes    `json:"masterPublicKey"` // IBE master public key (ibe.MasterPublicKey)
	Threshold       hexutil.Uint64   `json:"threshold"`       // decryption threshold
	Keypers         []common.Address `json:"keypers"`         // committee member addresses
	Registry        common.Address   `json:"registry"`        // keyper registry address
}

// SendEncryptedTransaction accepts an IBE-encrypted transaction envelope (a
// marshalled ibe.Ciphertext, bound to a target epoch, whose plaintext is a
// canonical signed transaction), buffers it in the encrypted mempool, and gossips
// it to peers. It returns the envelope id. The node does not (and cannot) decrypt
// it here; it is decrypted by the keyper committee when its epoch is due.
func (api *EncMempoolAPI) SendEncryptedTransaction(data hexutil.Bytes) (common.Hash, error) {
	if api.eth.handler == nil || api.eth.handler.encPool == nil {
		return common.Hash{}, errors.New("encrypted mempool is not active on this network")
	}
	// Validate that the payload is a well-formed IBE ciphertext before admitting it,
	// so the buffer is not filled with junk.
	if _, err := ibe.UnmarshalCiphertext(data); err != nil {
		return common.Hash{}, fmt.Errorf("invalid IBE ciphertext: %w", err)
	}
	env, err := encbuf.NewEnvelope(data)
	if err != nil {
		return common.Hash{}, err
	}
	api.eth.handler.submitEncryptedEnvelope(env)
	return env.ID(), nil
}

// Committee reports the encrypted-mempool committee read from the on-chain keyper
// registry at the current head, so a wallet can encrypt a transaction to the eon
// key. It errors when no registry is configured or the registry holds no committee.
func (api *EncMempoolAPI) Committee() (*CommitteeInfo, error) {
	addr := api.eth.config.EncryptedMempoolRegistry
	if addr == (common.Address{}) {
		return nil, errors.New("encrypted-mempool registry is not configured")
	}
	st, err := api.eth.blockchain.State()
	if err != nil {
		return nil, err
	}
	reg := keyper.NewRegistry(addr)
	mpk, err := reg.MasterPublicKey(st)
	if err != nil {
		return nil, err
	}
	raw, err := mpk.Marshal()
	if err != nil {
		return nil, err
	}
	return &CommitteeInfo{
		MasterPublicKey: raw,
		Threshold:       hexutil.Uint64(reg.Threshold(st)),
		Keypers:         reg.Keypers(st),
		Registry:        addr,
	}, nil
}
