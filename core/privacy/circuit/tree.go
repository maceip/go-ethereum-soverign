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

import "github.com/ethereum/go-ethereum/common"

// Tree is a wallet/prover-side MiMC Merkle tree that mirrors the consensus
// shielded pool. It retains every leaf so it can produce the authentication path
// required to prove membership of a note commitment. The consensus pool itself
// keeps only the frontier (it never needs to prove membership), so this lives
// here, not in the pool.
//
// Its root is, by construction, identical to the pool's root for the same sequence
// of appended commitments.
type Tree struct {
	depth  uint
	leaves []common.Hash
	zeros  []common.Hash
}

// NewTree returns an empty tree of MerkleDepth.
func NewTree() *Tree {
	return &Tree{depth: MerkleDepth, zeros: EmptySubtreeRoots(MerkleDepth)}
}

// Append adds a commitment as the next leaf and returns its index.
func (t *Tree) Append(commitment common.Hash) uint64 {
	idx := uint64(len(t.leaves))
	t.leaves = append(t.leaves, commitment)
	return idx
}

// Leaves returns the number of appended commitments.
func (t *Tree) Leaves() uint64 { return uint64(len(t.leaves)) }

// levels recomputes every tree level from the leaves up, padding missing right
// children with the empty-subtree root for that level.
func (t *Tree) levels() [][]common.Hash {
	levels := make([][]common.Hash, t.depth+1)
	levels[0] = append([]common.Hash{}, t.leaves...)
	for d := uint(0); d < t.depth; d++ {
		cur := levels[d]
		next := make([]common.Hash, (len(cur)+1)/2)
		for i := range next {
			left := cur[2*i]
			right := t.zeros[d]
			if 2*i+1 < len(cur) {
				right = cur[2*i+1]
			}
			next[i] = HashTwo(left, right)
		}
		levels[d+1] = next
	}
	return levels
}

// Root returns the current Merkle root.
func (t *Tree) Root() common.Hash {
	if len(t.leaves) == 0 {
		return t.zeros[t.depth]
	}
	levels := t.levels()
	top := levels[t.depth]
	if len(top) == 0 {
		return t.zeros[t.depth]
	}
	return top[0]
}

// Path returns the authentication path (sibling at each level and the
// left/right index bits) for the leaf at the given index.
func (t *Tree) Path(index uint64) (siblings [MerkleDepth]common.Hash, indices [MerkleDepth]uint8) {
	levels := t.levels()
	for d := uint(0); d < t.depth; d++ {
		pos := index >> d
		sib := pos ^ 1
		s := t.zeros[d]
		if int(sib) < len(levels[d]) {
			s = levels[d][sib]
		}
		siblings[d] = s
		indices[d] = uint8(pos & 1)
	}
	return siblings, indices
}
