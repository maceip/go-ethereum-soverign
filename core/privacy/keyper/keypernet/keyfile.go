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

package keypernet

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/privacy/ibe"
	"github.com/ethereum/go-ethereum/core/privacy/keyper"
	"github.com/ethereum/go-ethereum/core/privacy/threshold"
)

// KeyFile is a keyper's persisted material: its secret DKG share and public
// verification key, hex-encoded. The share is private key material; the file is
// written 0600 and must be protected by the operator.
type KeyFile struct {
	Index uint32 `json:"index"`
	Share string `json:"share"` // hex of threshold.KeyShare.Marshal (SECRET)
	VK    string `json:"vk"`    // hex of threshold.VerificationKey.Marshal
}

// SaveKeyper writes a keyper's material to path with 0600 permissions.
func SaveKeyper(path string, k *Keyper) error {
	shareBytes, err := k.share.Marshal()
	if err != nil {
		return err
	}
	vkBytes, err := k.vk.Marshal()
	if err != nil {
		return err
	}
	kf := KeyFile{
		Index: k.Index(),
		Share: hex.EncodeToString(shareBytes),
		VK:    hex.EncodeToString(vkBytes),
	}
	blob, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, blob, 0o600)
}

// LoadKeyper reads a keyper from a file written by SaveKeyper.
func LoadKeyper(path string) (*Keyper, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var kf KeyFile
	if err := json.Unmarshal(blob, &kf); err != nil {
		return nil, err
	}
	shareBytes, err := hex.DecodeString(kf.Share)
	if err != nil {
		return nil, fmt.Errorf("bad share hex: %w", err)
	}
	vkBytes, err := hex.DecodeString(kf.VK)
	if err != nil {
		return nil, fmt.Errorf("bad vk hex: %w", err)
	}
	share, err := threshold.UnmarshalKeyShare(shareBytes)
	if err != nil {
		return nil, err
	}
	vk, err := threshold.UnmarshalVerificationKey(vkBytes)
	if err != nil {
		return nil, err
	}
	return NewKeyper(share, vk), nil
}

// CommitteeExport is the public committee description produced at bootstrap: the
// IBE master public key for wallets, and the keyper-registry storage to install at
// genesis so the chain advertises the committee on-chain.
type CommitteeExport struct {
	Threshold       int               `json:"threshold"`
	MasterPublicKey string            `json:"masterPublicKey"` // hex of ibe.MasterPublicKey.Marshal
	RegistryAddress common.Address    `json:"registryAddress"` // where to install the registry
	RegistryStorage map[string]string `json:"registryStorage"` // slot(hex) -> value(hex)
}

// ExportCommittee builds the public committee export, including the registry
// account storage (so it can be placed in a genesis alloc) for the given keyper
// addresses.
func ExportCommittee(t int, mpk *ibe.MasterPublicKey, registryAddr common.Address, keyperAddrs []common.Address) (*CommitteeExport, error) {
	storage, err := keyper.BuildRegistryStorageIBE(t, mpk, keyperAddrs)
	if err != nil {
		return nil, err
	}
	hexStorage := make(map[string]string, len(storage))
	for slot, val := range storage {
		hexStorage[slot.Hex()] = val.Hex()
	}
	mpkBytes, err := mpk.Marshal()
	if err != nil {
		return nil, err
	}
	return &CommitteeExport{
		Threshold:       t,
		MasterPublicKey: hex.EncodeToString(mpkBytes),
		RegistryAddress: registryAddr,
		RegistryStorage: hexStorage,
	}, nil
}
