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
	"errors"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
)

// ===========================================================================
//  TRUSTED SETUP — DEVNET ONLY, NOT SECURE FOR PRODUCTION
// ===========================================================================
//
// PlonK requires a universal Structured Reference String (SRS) produced by a
// trusted-setup ceremony. DevnetSetup below generates that SRS locally via gnark's
// test-only unsafekzg generator from a FIXED, PUBLIC seed. Two properties follow:
//
//   - Deterministic: every node and every prover derives the identical proving and
//     verifying keys, so proofs verify across a multi-node network and the
//     genesis-installed verifying key matches what provers use. This is what makes
//     a real (multi-node) devnet function, as opposed to a single-process test.
//   - INSECURE: because the seed (and therefore the toxic waste) is public, anyone
//     can FORGE PROOFS — mint shielded value or spend notes they do not own.
//
// This is acceptable only for development networks. Before any value-bearing
// deployment the verifying key MUST be regenerated from an SRS produced by a real,
// multi-party ceremony (e.g. perpetual powers-of-tau) and that verifying key
// installed into the shielded pool. The circuit itself is unchanged by the
// ceremony; only the SRS and derived keys differ.
// ===========================================================================

// devnetToxicSeed is the fixed, public seed used to derive the devnet SRS. Its
// publicness is precisely why the devnet setup is insecure (see above).
var devnetToxicSeed = []byte("go-ethereum/privacy/circuit/devnet-srs/v1")

// ErrNotSetup is returned by Prove if DevnetSetup has not been run.
var ErrNotSetup = errors.New("circuit: trusted setup not initialised (call DevnetSetup)")

var (
	setupOnce  sync.Once
	setupErr   error
	compiled   constraint.ConstraintSystem
	provingKey plonk.ProvingKey
	verifyKey  plonk.VerifyingKey
	vkBytes    []byte
)

func doSetup() {
	var err error
	compiled, err = frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &Transfer{})
	if err != nil {
		setupErr = err
		return
	}
	// A fixed seed makes the SRS — and therefore the proving/verifying keys —
	// deterministic and identical on every node and prover.
	srs, srsLagrange, err := unsafekzg.NewSRS(compiled, unsafekzg.WithToxicSeed(devnetToxicSeed))
	if err != nil {
		setupErr = err
		return
	}
	provingKey, verifyKey, err = plonk.Setup(compiled, srs, srsLagrange)
	if err != nil {
		setupErr = err
		return
	}
	var buf bytes.Buffer
	if _, err = verifyKey.WriteTo(&buf); err != nil {
		setupErr = err
		return
	}
	vkBytes = buf.Bytes()
}

// DevnetSetup performs a one-time, in-process, deterministic (but UNSAFE) trusted
// setup and returns the serialized verifying key to install into the shielded
// pool. It compiles the circuit lazily, so consensus nodes that only verify proofs
// (using a genesis-installed key) never pay for it. It is safe to call
// concurrently; the heavy work runs once.
//
// SECURITY: the SRS is generated from a public seed; see the warning above. Do not
// use the returned verifying key on a value-bearing network.
func DevnetSetup() ([]byte, error) {
	setupOnce.Do(doSetup)
	if setupErr != nil {
		return nil, setupErr
	}
	return vkBytes, nil
}

// DevnetVerifyingKey returns the serialized devnet verifying key, running the
// deterministic setup if necessary. It is a convenience wrapper used by genesis
// construction.
func DevnetVerifyingKey() ([]byte, error) { return DevnetSetup() }

// Prove produces a serialized PlonK proof for the given fully-assigned transfer
// witness. DevnetSetup must have been called first. It returns an error if the
// assignment does not satisfy the circuit constraints — the prover cannot prove a
// false statement, which is precisely what makes invalid transfers unprovable.
func Prove(assignment *Transfer) ([]byte, error) {
	if vkBytes == nil {
		return nil, ErrNotSetup
	}
	full, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, err
	}
	proof, err := plonk.Prove(compiled, provingKey, full)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if _, err := proof.WriteTo(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
