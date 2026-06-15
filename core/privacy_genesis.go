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

package core

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/privacy/circuit"
	"github.com/ethereum/go-ethereum/core/privacy/pool"
	"github.com/ethereum/go-ethereum/core/types"
)

// EnablePrivacyDevnet activates Privacy Phase 1 (confidential ETH transactions) on
// the given genesis from block 0 and installs the shielded-transfer verifying key
// into the shielded pool's genesis state, so a development network can produce and
// verify shielded transactions immediately after launch.
//
// SECURITY: this installs the DEVNET verifying key, whose trusted setup uses a
// public seed (see circuit.DevnetSetup). It must only be used for development
// networks; on such a network shielded value can be forged. Do not call this for a
// value-bearing chain.
func EnablePrivacyDevnet(gspec *Genesis) error {
	vk, err := circuit.DevnetVerifyingKey()
	if err != nil {
		return err
	}
	zero := uint64(0)
	gspec.Config.Privacy1Time = &zero

	if gspec.Alloc == nil {
		gspec.Alloc = make(types.GenesisAlloc)
	}
	acct := gspec.Alloc[pool.SystemAddress]
	if acct.Balance == nil {
		acct.Balance = new(big.Int)
	}
	if acct.Storage == nil {
		acct.Storage = make(map[common.Hash]common.Hash)
	}
	for k, v := range pool.GenesisStorage(vk) {
		acct.Storage[k] = v
	}
	gspec.Alloc[pool.SystemAddress] = acct
	return nil
}
