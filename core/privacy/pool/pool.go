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

// Package pool implements the protocol-native shielded pool described by Phase 4
// of the Ethereum Privacy roadmap ("Integrate shielded pool functionalities
// directly into the protocol [...] Utilise efficient data structures like
// incremental Merkle trees for tracking committed values [...] Implement robust
// nullifier-based double-spend prevention directly within the protocol logic").
//
// The pool persists its entire state inside the regular Ethereum state trie, under
// a reserved system address, so it inherits state commitment, syncing and rollback
// for free — no new consensus data structure is required. It stores:
//
//   - an incremental Merkle tree of note commitments (root + frontier),
//   - a ring buffer of recent roots, so a transaction may anchor to a slightly
//     stale-but-recent root without being invalidated by concurrent inserts, and
//   - a set of spent nullifiers for double-spend prevention.
//
// All reads/writes go through the small Backend interface (a subset of
// vm.StateDB), keeping the pool unit-testable against an in-memory mock.
package pool

import (
	"encoding/binary"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/privacy"
	"github.com/ethereum/go-ethereum/crypto"
)

// SystemAddress is the reserved account whose storage holds the shielded pool
// state. It is outside the range an EOA or normal contract can control.
var SystemAddress = common.HexToAddress("0x000000000000000000000000000000000050ace1")

// RecentRootsWindow is the number of historical roots retained for anchoring. A
// transaction's anchor must match the current root or one of the previous
// RecentRootsWindow-1 roots.
const RecentRootsWindow = 64

// Storage-slot domain separators. Each derives a unique keyspace within the system
// account's storage so the different sub-structures never collide.
var (
	slotMeta          = crypto.Keccak256Hash([]byte("privacy/pool/meta")) // root, leaf count, ring cursor
	prefixFrontier    = []byte("privacy/pool/frontier")                   // incremental tree frontier nodes
	prefixRecentRoots = []byte("privacy/pool/recentRoots")                // ring buffer of recent roots
	prefixNullifier   = []byte("privacy/pool/nullifier")                  // spent nullifier set
)

// Backend is the subset of vm.StateDB the shielded pool needs. *state.StateDB
// satisfies it.
type Backend interface {
	GetState(common.Address, common.Hash) common.Hash
	SetState(common.Address, common.Hash, common.Hash) common.Hash
}

// Pool is a view over the shielded-pool state held in a Backend. It is a thin
// stateless wrapper: all durable state lives in the Backend, so a Pool can be
// constructed cheaply per transaction.
type Pool struct {
	be Backend
}

// New returns a Pool backed by the given state.
func New(be Backend) *Pool {
	return &Pool{be: be}
}

// --- public API ---------------------------------------------------------------

// Root returns the current note-commitment tree root. For an empty, never-touched
// pool this is the zero hash, which callers should treat as the canonical empty
// root (privacy.NewIncrementalMerkleTree().Root() with no inserts hashes the empty
// subtree chain; see IsKnownRoot for how the empty pool is handled).
func (p *Pool) Root() common.Hash {
	return p.meta().root
}

// Leaves returns the number of commitments inserted so far.
func (p *Pool) Leaves() uint64 {
	return p.meta().leaves
}

// IsNullifierSpent reports whether a nullifier has already been consumed.
func (p *Pool) IsNullifierSpent(nullifier common.Hash) bool {
	return p.be.GetState(SystemAddress, p.nullifierSlot(nullifier)) != (common.Hash{})
}

// SpendNullifier marks a nullifier as spent. It returns privacy.ErrNullifierSeen
// if the nullifier was already spent (a double-spend attempt).
func (p *Pool) SpendNullifier(nullifier common.Hash) error {
	if p.IsNullifierSpent(nullifier) {
		return privacy.ErrNullifierSeen
	}
	p.be.SetState(SystemAddress, p.nullifierSlot(nullifier), trueHash)
	return nil
}

// IsKnownRoot reports whether anchor is the current root or one of the recent
// roots in the retention window. The empty/zero anchor is accepted only when the
// pool has never had a commitment inserted, so a transaction can shield into a
// fresh pool.
func (p *Pool) IsKnownRoot(anchor common.Hash) bool {
	m := p.meta()
	if m.leaves == 0 {
		// Fresh pool: only the empty tree root (== zero meta root) is valid.
		return anchor == m.root
	}
	window := m.leaves
	if window > RecentRootsWindow {
		window = RecentRootsWindow
	}
	for i := uint64(0); i < window; i++ {
		if p.recentRootAt((m.ringCursor-1-i)%RecentRootsWindow) == anchor {
			return true
		}
	}
	return false
}

// AppendCommitment inserts a new note commitment, advancing the tree root and
// recording it in the recent-roots ring. It returns the leaf index, the new root,
// or privacy.ErrTreeFull if the tree is at capacity.
func (p *Pool) AppendCommitment(commitment common.Hash) (uint64, common.Hash, error) {
	m := p.meta()
	if m.leaves >= uint64(1)<<privacy.TreeDepth {
		return 0, common.Hash{}, privacy.ErrTreeFull
	}

	// Walk the frontier exactly like privacy.IncrementalMerkleTree.Insert, but with
	// the frontier persisted in state rather than memory.
	index := m.leaves
	cur := commitment
	idx := index
	zeros := emptySubtreeHashes()
	for level := uint(0); level < privacy.TreeDepth; level++ {
		if idx%2 == 0 {
			p.setFrontier(level, cur)
			cur = hashPair(cur, zeros[level])
		} else {
			cur = hashPair(p.frontier(level), cur)
		}
		idx /= 2
	}

	m.root = cur
	m.leaves++
	p.setRecentRootAt(m.ringCursor, cur)
	m.ringCursor = (m.ringCursor + 1) % RecentRootsWindow
	p.setMeta(m)
	return index, cur, nil
}

// --- internal state layout ----------------------------------------------------

var trueHash = common.Hash{31: 0x01}

type metadata struct {
	root       common.Hash
	leaves     uint64
	ringCursor uint64
}

// meta encodes (leaves, ringCursor) packed into one slot and the root in another,
// both derived from slotMeta.
func (p *Pool) meta() metadata {
	root := p.be.GetState(SystemAddress, slotMeta)
	packed := p.be.GetState(SystemAddress, addOffset(slotMeta, 1))
	return metadata{
		root:       root,
		leaves:     binary.BigEndian.Uint64(packed[16:24]),
		ringCursor: binary.BigEndian.Uint64(packed[24:32]),
	}
}

func (p *Pool) setMeta(m metadata) {
	p.be.SetState(SystemAddress, slotMeta, m.root)
	var packed common.Hash
	binary.BigEndian.PutUint64(packed[16:24], m.leaves)
	binary.BigEndian.PutUint64(packed[24:32], m.ringCursor)
	p.be.SetState(SystemAddress, addOffset(slotMeta, 1), packed)
}

func (p *Pool) frontier(level uint) common.Hash {
	return p.be.GetState(SystemAddress, indexedSlot(prefixFrontier, uint64(level)))
}

func (p *Pool) setFrontier(level uint, v common.Hash) {
	p.be.SetState(SystemAddress, indexedSlot(prefixFrontier, uint64(level)), v)
}

func (p *Pool) recentRootAt(i uint64) common.Hash {
	return p.be.GetState(SystemAddress, indexedSlot(prefixRecentRoots, i))
}

func (p *Pool) setRecentRootAt(i uint64, v common.Hash) {
	p.be.SetState(SystemAddress, indexedSlot(prefixRecentRoots, i), v)
}

func (p *Pool) nullifierSlot(nullifier common.Hash) common.Hash {
	return crypto.Keccak256Hash(prefixNullifier, nullifier[:])
}

// --- slot/hash helpers ---------------------------------------------------------

func hashPair(left, right common.Hash) common.Hash {
	var out common.Hash
	copy(out[:], crypto.Keccak256(left[:], right[:]))
	return out
}

// emptySubtreeHashes returns the hash of an empty subtree at each level, matching
// privacy.IncrementalMerkleTree's zero hashes so roots are interoperable.
func emptySubtreeHashes() []common.Hash {
	zeros := make([]common.Hash, privacy.TreeDepth+1)
	for i := uint(0); i < privacy.TreeDepth; i++ {
		zeros[i+1] = hashPair(zeros[i], zeros[i])
	}
	return zeros
}

func indexedSlot(prefix []byte, i uint64) common.Hash {
	var idx [8]byte
	binary.BigEndian.PutUint64(idx[:], i)
	return crypto.Keccak256Hash(prefix, idx[:])
}

// addOffset returns a slot adjacent to base, used to pack a small fixed number of
// related values near a domain-separated anchor slot.
func addOffset(base common.Hash, off uint64) common.Hash {
	b := base.Big()
	b.Add(b, new(big.Int).SetUint64(off))
	return common.BigToHash(b)
}
