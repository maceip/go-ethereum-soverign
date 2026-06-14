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
	"bytes"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/privacy"
)

// padScalar left-pads a big.Int to a 32-byte big-endian slice.
func padScalar(v *big.Int) []byte {
	return common.LeftPadBytes(v.Bytes(), 32)
}

// TestPedersenCommitPrecompile checks the precompile output matches the privacy
// package and that the commitment is homomorphic via the PEDERSEN_ADD precompile.
func TestPedersenCommitPrecompile(t *testing.T) {
	commit := &pedersenCommit{}
	add := &pedersenAdd{}

	// C1 = Commit(100, 7), C2 = Commit(50, 9).
	in1 := append(padScalar(big.NewInt(100)), padScalar(big.NewInt(7))...)
	in2 := append(padScalar(big.NewInt(50)), padScalar(big.NewInt(9))...)

	c1, err := commit.Run(in1)
	if err != nil {
		t.Fatalf("commit C1: %v", err)
	}
	c2, err := commit.Run(in2)
	if err != nil {
		t.Fatalf("commit C2: %v", err)
	}

	// Cross-check against the library directly.
	wantC1, _ := privacy.Commit(big.NewInt(100), big.NewInt(7))
	if !bytes.Equal(c1, wantC1) {
		t.Fatal("precompile commitment != library commitment")
	}

	// PEDERSEN_ADD(C1, C2) must equal Commit(150, 16).
	sum, err := add.Run(append(append([]byte{}, c1...), c2...))
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	wantSum, _ := privacy.Commit(big.NewInt(150), big.NewInt(16))
	if !bytes.Equal(sum, wantSum) {
		t.Fatal("homomorphic add via precompile mismatch")
	}
}

func TestPedersenCommitPrecompileBadInput(t *testing.T) {
	commit := &pedersenCommit{}
	if _, err := commit.Run(make([]byte, 63)); err != errPrivacyBadInput {
		t.Fatalf("short input: got %v, want errPrivacyBadInput", err)
	}
	add := &pedersenAdd{}
	if _, err := add.Run(make([]byte, 100)); err != errPrivacyBadInput {
		t.Fatalf("short add input: got %v, want errPrivacyBadInput", err)
	}
}

// TestPrivacyPrecompilesRegistered ensures the precompiles are live in the Osaka
// fork at the documented addresses.
func TestPrivacyPrecompilesRegistered(t *testing.T) {
	set := PrecompiledContractsOsaka
	if _, ok := set[common.BytesToAddress([]byte{0x12})]; !ok {
		t.Fatal("PEDERSEN_COMMIT not registered at 0x12 in Osaka set")
	}
	if _, ok := set[common.BytesToAddress([]byte{0x13})]; !ok {
		t.Fatal("PEDERSEN_ADD not registered at 0x13 in Osaka set")
	}
}
