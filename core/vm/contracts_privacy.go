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

package vm

import (
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/core/privacy"
	"github.com/ethereum/go-ethereum/params"
)

// This file implements the "privacy precompiles" called for by Phase 3 of the
// Ethereum Privacy roadmap ("Ethereum Privacy: The Road to Self-Sovereignty"):
//
//	"Introduce EVM precompiles for verifying common zk-SNARK schemes [...] to
//	 drastically reduce the mana cost of on-chain proof verification."
//
// and the supporting Phase 1 primitive:
//
//	"Sealed amounts and addresses: Employ cryptographic commitments like Pedersen
//	 commitments to encrypt transaction values."
//
// Verifying a Groth16/PlonK proof or computing a Pedersen commitment in pure EVM
// bytecode costs hundreds of thousands of gas; exposing the bn256 group operations
// as native precompiles makes confidential-value bookkeeping economically viable on
// L1. The existing bn256 add/mul/pairing precompiles (0x06–0x08, EIP-196/197)
// already cover generic SNARK verification, so here we add the two operations a
// confidential-value scheme needs that are awkward to express on top of them: a
// fused commitment computation against a fixed second generator H, and a
// homomorphic addition that returns a result in the same encoding.

var errPrivacyBadInput = errors.New("invalid input length")

// pedersenCommit is the precompile computing a Pedersen commitment
// C = value*G + blinding*H over bn256 G1.
//
// Input  (64 bytes): [32-byte big-endian value][32-byte big-endian blinding]
// Output (64 bytes): the commitment point in EVM bn256 G1 encoding (X || Y).
type pedersenCommit struct{}

func (c *pedersenCommit) RequiredGas(input []byte) uint64 {
	return params.PedersenCommitGas
}

func (c *pedersenCommit) Run(input []byte) ([]byte, error) {
	if len(input) != 64 {
		return nil, errPrivacyBadInput
	}
	value := new(big.Int).SetBytes(input[0:32])
	blinding := new(big.Int).SetBytes(input[32:64])
	out, err := privacy.Commit(value, blinding)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *pedersenCommit) Name() string { return "PEDERSEN_COMMIT" }

// pedersenAdd is the precompile computing the homomorphic sum of two Pedersen
// commitments. Because the commitment scheme is additively homomorphic, the
// returned point is a valid commitment to the sum of the two underlying values
// (and the sum of their blinding factors). Contracts use this to enforce that
// hidden inputs equal hidden outputs without learning either amount.
//
// Input  (128 bytes): [64-byte commitment A][64-byte commitment B]
// Output (64 bytes):   A + B in EVM bn256 G1 encoding.
type pedersenAdd struct{}

func (c *pedersenAdd) RequiredGas(input []byte) uint64 {
	return params.PedersenAddGas
}

func (c *pedersenAdd) Run(input []byte) ([]byte, error) {
	if len(input) != 128 {
		return nil, errPrivacyBadInput
	}
	out, err := privacy.Add(input[0:64], input[64:128])
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *pedersenAdd) Name() string { return "PEDERSEN_ADD" }
