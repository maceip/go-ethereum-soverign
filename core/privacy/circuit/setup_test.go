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

package circuit

import (
	"bytes"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
)

// TestDeterministicSetup is the key multi-node property: the seeded devnet setup
// must yield the identical verifying key on every independent run, otherwise nodes
// could not verify each other's proofs and a genesis-installed key would never
// match. It performs two fully independent setups and compares the verifying keys.
func TestDeterministicSetup(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping trusted-setup determinism check in -short mode")
	}
	vkBytes := func() []byte {
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &Transfer{})
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		srs, srsLagrange, err := unsafekzg.NewSRS(ccs, unsafekzg.WithToxicSeed(devnetToxicSeed))
		if err != nil {
			t.Fatalf("srs: %v", err)
		}
		_, vk, err := plonk.Setup(ccs, srs, srsLagrange)
		if err != nil {
			t.Fatalf("setup: %v", err)
		}
		var buf bytes.Buffer
		if _, err := vk.WriteTo(&buf); err != nil {
			t.Fatalf("encode: %v", err)
		}
		return buf.Bytes()
	}

	a := vkBytes()
	b := vkBytes()
	if !bytes.Equal(a, b) {
		t.Fatal("seeded setup is not deterministic: two runs produced different verifying keys")
	}

	// And the cached DevnetSetup must return the same key.
	c, err := DevnetSetup()
	if err != nil {
		t.Fatalf("DevnetSetup: %v", err)
	}
	if !bytes.Equal(a, c) {
		t.Fatal("DevnetSetup verifying key differs from a fresh seeded setup")
	}
}
