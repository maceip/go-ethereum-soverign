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

package privacy

import (
	"bytes"
	"math/big"
	"testing"
)

func mustCommit(t *testing.T, v, r int64) []byte {
	t.Helper()
	c, err := Commit(big.NewInt(v), big.NewInt(r))
	if err != nil {
		t.Fatalf("Commit(%d,%d): %v", v, r, err)
	}
	if len(c) != CommitmentSize {
		t.Fatalf("commitment size = %d, want %d", len(c), CommitmentSize)
	}
	return c
}

// TestCommitDeterministic checks that committing to the same value/blinding pair
// always yields the same point (binding) and that the encoding is valid.
func TestCommitDeterministic(t *testing.T) {
	c1 := mustCommit(t, 42, 7)
	c2 := mustCommit(t, 42, 7)
	if !bytes.Equal(c1, c2) {
		t.Fatal("commitment to identical inputs is not deterministic")
	}
}

// TestCommitHiding checks that changing only the blinding factor changes the
// commitment, which is what hides the value.
func TestCommitHiding(t *testing.T) {
	c1 := mustCommit(t, 42, 7)
	c2 := mustCommit(t, 42, 8)
	if bytes.Equal(c1, c2) {
		t.Fatal("commitments with different blinding factors collided")
	}
}

// TestHomomorphicAddition verifies the additive homomorphism:
// Commit(a,r1) + Commit(b,r2) == Commit(a+b, r1+r2).
func TestHomomorphicAddition(t *testing.T) {
	a, b := int64(100), int64(250)
	r1, r2 := int64(11), int64(22)

	ca := mustCommit(t, a, r1)
	cb := mustCommit(t, b, r2)

	gotSum, err := Add(ca, cb)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	wantSum := mustCommit(t, a+b, r1+r2)
	if !bytes.Equal(gotSum, wantSum) {
		t.Fatal("homomorphic addition mismatch")
	}
}

// TestVerifySumBalanced models a confidential transfer with two inputs and two
// outputs whose values and blinding factors both balance.
func TestVerifySumBalanced(t *testing.T) {
	// inputs: 100 (r=5) + 50 (r=9) = 150 (r=14)
	// outputs: 120 (r=10) + 30 (r=4) = 150 (r=14)
	inputs := [][]byte{mustCommit(t, 100, 5), mustCommit(t, 50, 9)}
	outputs := [][]byte{mustCommit(t, 120, 10), mustCommit(t, 30, 4)}

	ok, err := VerifySum(inputs, outputs)
	if err != nil {
		t.Fatalf("VerifySum: %v", err)
	}
	if !ok {
		t.Fatal("balanced transfer rejected")
	}
}

// TestVerifySumUnbalancedValue ensures a value imbalance is rejected even when an
// attacker tries to keep the blinding factors balanced.
func TestVerifySumUnbalancedValue(t *testing.T) {
	inputs := [][]byte{mustCommit(t, 100, 14)}
	outputs := [][]byte{mustCommit(t, 101, 14)} // inflated by 1

	ok, err := VerifySum(inputs, outputs)
	if err != nil {
		t.Fatalf("VerifySum: %v", err)
	}
	if ok {
		t.Fatal("value-inflating transfer accepted")
	}
}

// TestNegDifference checks that Add(a, Neg(b)) yields the commitment to the
// difference, which callers use to form balance equations.
func TestNegDifference(t *testing.T) {
	ca := mustCommit(t, 200, 30)
	cb := mustCommit(t, 75, 12)

	negB, err := Neg(cb)
	if err != nil {
		t.Fatalf("Neg: %v", err)
	}
	diff, err := Add(ca, negB)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	want := mustCommit(t, 125, 18)
	if !bytes.Equal(diff, want) {
		t.Fatal("Add(a, Neg(b)) != Commit(a-b, r_a-r_b)")
	}
}

func TestCommitRejectsOutOfRange(t *testing.T) {
	if _, err := Commit(big.NewInt(-1), big.NewInt(1)); err != ErrValueOutOfRange {
		t.Fatalf("negative value: got %v, want ErrValueOutOfRange", err)
	}
	if _, err := Commit(big.NewInt(1), nil); err != ErrValueOutOfRange {
		t.Fatalf("nil blinding: got %v, want ErrValueOutOfRange", err)
	}
}

func TestAddRejectsMalformed(t *testing.T) {
	good := mustCommit(t, 1, 1)
	if _, err := Add(good, []byte{0x01, 0x02}); err != ErrInvalidCommitment {
		t.Fatalf("short input: got %v, want ErrInvalidCommitment", err)
	}
	bad := make([]byte, CommitmentSize)
	for i := range bad {
		bad[i] = 0xff // not a valid curve point
	}
	if _, err := Add(good, bad); err != ErrInvalidCommitment {
		t.Fatalf("off-curve input: got %v, want ErrInvalidCommitment", err)
	}
}

// TestRandomScalar sanity-checks the blinding-factor sampler.
func TestRandomScalar(t *testing.T) {
	a, err := RandomScalar()
	if err != nil {
		t.Fatal(err)
	}
	b, err := RandomScalar()
	if err != nil {
		t.Fatal(err)
	}
	if a.Sign() == 0 || b.Sign() == 0 {
		t.Fatal("RandomScalar returned zero")
	}
	if a.Cmp(b) == 0 {
		t.Fatal("RandomScalar returned identical values twice (astronomically unlikely)")
	}
}
