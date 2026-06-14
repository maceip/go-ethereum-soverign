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
	"errors"

	"github.com/ethereum/go-ethereum/common"
)

// Roadmap reference: Phase 4 — "Utilise efficient data structures like incremental
// Merkle trees for tracking committed values without revealing them" and
// "Implement robust nullifier-based double-spend prevention directly within the
// protocol logic, inspired by mature systems like Tornado Cash's implementation or
// Zcash". Also Phase 2 — "Explore Merkle-based ownership registries where users can
// prove ownership via zk-proofs of inclusion, similar to Zcash's note commitment
// tree".
//
// A shielded pool stores opaque note commitments in an append-only, fixed-depth
// incremental Merkle tree. Spending a note reveals a nullifier (a deterministic,
// unlinkable tag derived from the note) which is recorded in a set; replaying the
// same nullifier is rejected, preventing double spends. Crucially, the nullifier
// cannot be linked back to the commitment that produced it without the spending
// key, so spends remain unlinkable to deposits.

// TreeDepth is the fixed depth of the commitment tree. A depth of 32 supports
// 2^32 (~4.3 billion) notes, far exceeding the ">10,000 users" anonymity-set
// target called out in the roadmap, while keeping Merkle proofs compact.
const TreeDepth = 32

var (
	// ErrTreeFull is returned when the commitment tree has no free leaves left.
	ErrTreeFull = errors.New("privacy: commitment tree is full")

	// ErrNullifierSeen is returned when a nullifier has already been spent.
	ErrNullifierSeen = errors.New("privacy: nullifier already spent (double spend)")
)

// IncrementalMerkleTree is an append-only fixed-depth Merkle tree over note
// commitments using Keccak-256 as the hash. It keeps only O(depth) state (the
// "frontier") rather than every node, so appending a leaf and reading the root are
// both O(depth) in time and memory — the property that makes it practical at
// protocol level.
type IncrementalMerkleTree struct {
	depth     uint
	nextIndex uint64
	// filledSubtrees[i] is the hash of the most recent left-child subtree at
	// level i that is waiting for its right sibling.
	filledSubtrees []common.Hash
	// zeros[i] is the hash of an empty subtree of height i.
	zeros []common.Hash
	root  common.Hash
}

// NewIncrementalMerkleTree returns an empty tree of TreeDepth.
func NewIncrementalMerkleTree() *IncrementalMerkleTree {
	return NewIncrementalMerkleTreeDepth(TreeDepth)
}

// NewIncrementalMerkleTreeDepth returns an empty tree of the given depth. It is
// primarily useful for tests that want small, fast trees.
func NewIncrementalMerkleTreeDepth(depth uint) *IncrementalMerkleTree {
	t := &IncrementalMerkleTree{
		depth:          depth,
		filledSubtrees: make([]common.Hash, depth),
		zeros:          make([]common.Hash, depth+1),
	}
	// Precompute the hash of empty subtrees at every level.
	for i := uint(0); i < depth; i++ {
		t.filledSubtrees[i] = t.zeros[i]
		t.zeros[i+1] = hashPair(t.zeros[i], t.zeros[i])
	}
	t.root = t.zeros[depth]
	return t
}

// Insert appends a commitment as the next leaf and returns its leaf index. The
// tree root is updated incrementally.
func (t *IncrementalMerkleTree) Insert(commitment common.Hash) (uint64, error) {
	if t.nextIndex >= uint64(1)<<t.depth {
		return 0, ErrTreeFull
	}
	index := t.nextIndex
	cur := commitment
	idx := index
	for i := uint(0); i < t.depth; i++ {
		if idx%2 == 0 {
			// We are a left child; remember our hash and pair with an empty right.
			t.filledSubtrees[i] = cur
			cur = hashPair(cur, t.zeros[i])
		} else {
			// We are a right child; pair with the stored left sibling.
			cur = hashPair(t.filledSubtrees[i], cur)
		}
		idx /= 2
	}
	t.root = cur
	t.nextIndex++
	return index, nil
}

// Root returns the current Merkle root committing to all inserted leaves.
func (t *IncrementalMerkleTree) Root() common.Hash { return t.root }

// Leaves returns the number of commitments inserted so far.
func (t *IncrementalMerkleTree) Leaves() uint64 { return t.nextIndex }

// hashPair hashes two child nodes into their parent.
func hashPair(left, right common.Hash) common.Hash {
	var out common.Hash
	copy(out[:], keccak(left[:], right[:]))
	return out
}

// NullifierSet records spent nullifiers to enforce double-spend prevention. It is
// deliberately a thin wrapper around a map so that callers (e.g. a state-backed
// shielded pool contract or precompile) can choose their own persistent backing
// store while reusing the semantics.
type NullifierSet struct {
	seen map[common.Hash]struct{}
}

// NewNullifierSet returns an empty nullifier set.
func NewNullifierSet() *NullifierSet {
	return &NullifierSet{seen: make(map[common.Hash]struct{})}
}

// Spend records a nullifier as spent. It returns ErrNullifierSeen if the nullifier
// was already present, which a verifier must treat as an invalid (double-spending)
// transaction.
func (s *NullifierSet) Spend(nullifier common.Hash) error {
	if _, ok := s.seen[nullifier]; ok {
		return ErrNullifierSeen
	}
	s.seen[nullifier] = struct{}{}
	return nil
}

// Contains reports whether a nullifier has already been spent.
func (s *NullifierSet) Contains(nullifier common.Hash) bool {
	_, ok := s.seen[nullifier]
	return ok
}

// DeriveNullifier deterministically derives the nullifier for a note from the
// note's commitment, its leaf index in the tree and the owner's spending key.
// Binding the nullifier to the spending key is what keeps it unlinkable to the
// commitment for anyone who does not hold that key.
func DeriveNullifier(commitment common.Hash, leafIndex uint64, spendKey []byte) common.Hash {
	var idx [8]byte
	for i := 0; i < 8; i++ {
		idx[7-i] = byte(leafIndex >> (8 * i))
	}
	var out common.Hash
	copy(out[:], keccak([]byte("nullifier"), commitment[:], idx[:], spendKey))
	return out
}
