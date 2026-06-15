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

package pool

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/privacy"
)

// mockBackend is an in-memory Backend keyed by storage slot. It ignores the
// address since the pool only ever uses SystemAddress.
type mockBackend struct {
	store map[common.Hash]common.Hash
}

func newMockBackend() *mockBackend {
	return &mockBackend{store: make(map[common.Hash]common.Hash)}
}

func (m *mockBackend) GetState(_ common.Address, key common.Hash) common.Hash {
	return m.store[key]
}

func (m *mockBackend) SetState(_ common.Address, key, value common.Hash) common.Hash {
	prev := m.store[key]
	m.store[key] = value
	return prev
}

func commitment(b byte) common.Hash {
	var h common.Hash
	h[0] = b
	return h
}

// TestEmptyPool checks an untouched pool reports zero leaves and accepts the empty
// anchor.
func TestEmptyPool(t *testing.T) {
	p := New(newMockBackend())
	if p.Leaves() != 0 {
		t.Fatalf("fresh pool leaves = %d, want 0", p.Leaves())
	}
	if !p.IsKnownRoot(common.Hash{}) {
		t.Fatal("fresh pool should accept the empty anchor")
	}
	if p.IsKnownRoot(commitment(9)) {
		t.Fatal("fresh pool accepted an arbitrary anchor")
	}
}

// TestAppendAdvancesRoot checks appends change the root, bump leaf count, and that
// the new root becomes a known/recent root.
func TestAppendAdvancesRoot(t *testing.T) {
	p := New(newMockBackend())
	before := p.Root()

	idx, root, err := p.AppendCommitment(commitment(1))
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if idx != 0 {
		t.Fatalf("first leaf index = %d, want 0", idx)
	}
	if root == before {
		t.Fatal("root did not advance after append")
	}
	if p.Leaves() != 1 {
		t.Fatalf("leaves = %d, want 1", p.Leaves())
	}
	if !p.IsKnownRoot(root) {
		t.Fatal("new root not recognised as known")
	}
	if p.Root() != root {
		t.Fatal("Root() disagrees with AppendCommitment result")
	}
}

// TestRootMatchesInMemoryTree cross-checks the state-backed pool against the
// in-memory privacy.IncrementalMerkleTree for a sequence of inserts: the roots
// must match at every step (interoperable construction).
func TestRootMatchesInMemoryTree(t *testing.T) {
	p := New(newMockBackend())
	ref := privacy.NewIncrementalMerkleTree()

	for i := 0; i < 20; i++ {
		c := commitment(byte(i + 1))
		if _, err := ref.Insert(c); err != nil {
			t.Fatalf("ref insert: %v", err)
		}
		_, root, err := p.AppendCommitment(c)
		if err != nil {
			t.Fatalf("pool append: %v", err)
		}
		if root != ref.Root() {
			t.Fatalf("after %d inserts: pool root %x != in-memory root %x", i+1, root, ref.Root())
		}
	}
}

// TestNullifierDoubleSpend checks the nullifier set rejects replays.
func TestNullifierDoubleSpend(t *testing.T) {
	p := New(newMockBackend())
	n := commitment(0xab)

	if p.IsNullifierSpent(n) {
		t.Fatal("fresh nullifier reported spent")
	}
	if err := p.SpendNullifier(n); err != nil {
		t.Fatalf("first spend: %v", err)
	}
	if !p.IsNullifierSpent(n) {
		t.Fatal("nullifier not recorded after spend")
	}
	if err := p.SpendNullifier(n); err != privacy.ErrNullifierSeen {
		t.Fatalf("double spend: got %v, want ErrNullifierSeen", err)
	}
}

// TestRecentRootWindow checks an anchor stays valid within the retention window
// and is evicted once enough newer roots have been appended.
func TestRecentRootWindow(t *testing.T) {
	p := New(newMockBackend())

	_, firstRoot, err := p.AppendCommitment(commitment(1))
	if err != nil {
		t.Fatal(err)
	}
	if !p.IsKnownRoot(firstRoot) {
		t.Fatal("root not known immediately after append")
	}

	// Fill exactly the window with further appends; firstRoot should still be in
	// range at the boundary, then drop out after one more.
	for i := 0; i < RecentRootsWindow-1; i++ {
		if _, _, err := p.AppendCommitment(commitment(byte(i + 2))); err != nil {
			t.Fatal(err)
		}
	}
	if !p.IsKnownRoot(firstRoot) {
		t.Fatal("root evicted before leaving the window")
	}
	if _, _, err := p.AppendCommitment(commitment(0xff)); err != nil {
		t.Fatal(err)
	}
	if p.IsKnownRoot(firstRoot) {
		t.Fatal("stale root still accepted after leaving the window")
	}
}

// TestPersistenceAcrossInstances checks pool state lives entirely in the backend:
// a fresh Pool over the same backend observes prior writes.
func TestPersistenceAcrossInstances(t *testing.T) {
	be := newMockBackend()
	_, root, err := New(be).AppendCommitment(commitment(7))
	if err != nil {
		t.Fatal(err)
	}
	reopened := New(be)
	if reopened.Leaves() != 1 || reopened.Root() != root {
		t.Fatal("pool state did not persist in the backend")
	}
}
