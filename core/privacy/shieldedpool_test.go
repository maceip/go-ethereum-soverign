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
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func leaf(b byte) common.Hash {
	var h common.Hash
	h[31] = b
	return h
}

// TestTreeRootChangesOnInsert checks the root advances as leaves are appended and
// that a depth-d tree built incrementally matches a naive full recomputation.
func TestTreeRootChangesOnInsert(t *testing.T) {
	const depth = 4
	tree := NewIncrementalMerkleTreeDepth(depth)
	empty := tree.Root()

	idx, err := tree.Insert(leaf(1))
	if err != nil {
		t.Fatal(err)
	}
	if idx != 0 {
		t.Fatalf("first leaf index = %d, want 0", idx)
	}
	if tree.Root() == empty {
		t.Fatal("root did not change after first insert")
	}
	if tree.Leaves() != 1 {
		t.Fatalf("leaves = %d, want 1", tree.Leaves())
	}
}

// naiveRoot recomputes a fixed-depth Merkle root from scratch for cross-checking.
func naiveRoot(depth uint, leaves []common.Hash) common.Hash {
	zeros := make([]common.Hash, depth+1)
	for i := uint(0); i < depth; i++ {
		zeros[i+1] = hashPair(zeros[i], zeros[i])
	}
	level := make([]common.Hash, 1<<depth)
	for i := range level {
		if i < len(leaves) {
			level[i] = leaves[i]
		} else {
			level[i] = zeros[0]
		}
	}
	for level := level; len(level) > 1; {
		next := make([]common.Hash, len(level)/2)
		for i := 0; i < len(next); i++ {
			next[i] = hashPair(level[2*i], level[2*i+1])
		}
		level = next
		if len(level) == 1 {
			return level[0]
		}
	}
	return level[0]
}

// TestTreeMatchesNaive ensures the incremental construction agrees with a full
// recomputation for several leaf counts.
func TestTreeMatchesNaive(t *testing.T) {
	const depth = 5
	leaves := []common.Hash{}
	tree := NewIncrementalMerkleTreeDepth(depth)
	for i := 0; i < 10; i++ {
		l := leaf(byte(i + 1))
		leaves = append(leaves, l)
		if _, err := tree.Insert(l); err != nil {
			t.Fatal(err)
		}
		if got, want := tree.Root(), naiveRoot(depth, leaves); got != want {
			t.Fatalf("after %d inserts: incremental root %x != naive root %x", i+1, got, want)
		}
	}
}

// TestTreeFull verifies the capacity bound is enforced.
func TestTreeFull(t *testing.T) {
	const depth = 2 // capacity 4
	tree := NewIncrementalMerkleTreeDepth(depth)
	for i := 0; i < 4; i++ {
		if _, err := tree.Insert(leaf(byte(i + 1))); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}
	if _, err := tree.Insert(leaf(99)); err != ErrTreeFull {
		t.Fatalf("overfull insert: got %v, want ErrTreeFull", err)
	}
}

// TestNullifierDoubleSpend checks the nullifier set rejects replays.
func TestNullifierDoubleSpend(t *testing.T) {
	set := NewNullifierSet()
	n := DeriveNullifier(leaf(7), 3, []byte("spendkey"))

	if set.Contains(n) {
		t.Fatal("fresh nullifier reported as seen")
	}
	if err := set.Spend(n); err != nil {
		t.Fatalf("first spend: %v", err)
	}
	if !set.Contains(n) {
		t.Fatal("nullifier not recorded after spend")
	}
	if err := set.Spend(n); err != ErrNullifierSeen {
		t.Fatalf("double spend: got %v, want ErrNullifierSeen", err)
	}
}

// TestDeriveNullifierUniqueness checks the nullifier binds to commitment, index
// and spend key.
func TestDeriveNullifierUniqueness(t *testing.T) {
	base := DeriveNullifier(leaf(1), 0, []byte("k"))
	if DeriveNullifier(leaf(2), 0, []byte("k")) == base {
		t.Fatal("nullifier independent of commitment")
	}
	if DeriveNullifier(leaf(1), 1, []byte("k")) == base {
		t.Fatal("nullifier independent of leaf index")
	}
	if DeriveNullifier(leaf(1), 0, []byte("k2")) == base {
		t.Fatal("nullifier independent of spend key")
	}
}
