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
	"crypto/rand"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/ethereum/go-ethereum/common"
)

// This file provides the wallet/prover-side helpers for assembling a shielded
// transfer: describing the notes being spent and created, building the circuit
// witness (including Merkle authentication paths and dummy padding), and exposing
// the resulting public fields that go into a ShieldedTx.

// Note is a spendable shielded note owned by the holder of Ask.
type Note struct {
	Value *big.Int
	Ask   common.Hash // owner spending key
	Rho   common.Hash // per-note randomness
}

// RandomNote creates a fresh note of the given value with a random spending key
// and randomness. The caller is the owner.
func RandomNote(value *big.Int) Note {
	return Note{Value: new(big.Int).Set(value), Ask: RandomField(), Rho: RandomField()}
}

// Apk returns the note's address key, apk = MiMC(ask).
func (n Note) Apk() common.Hash { return DeriveApk(n.Ask) }

// Commitment returns the note commitment, cm = MiMC(value, apk, rho).
func (n Note) Commitment() common.Hash { return NoteCommitment(n.Value, n.Apk(), n.Rho) }

// Nullifier returns the note's nullifier, nf = MiMC(ask, cm).
func (n Note) Nullifier() common.Hash { return Nullifier(n.Ask, n.Commitment()) }

// Spend references a note to be consumed, together with its leaf index in the
// commitment tree (needed to build the Merkle membership path).
type Spend struct {
	Note      Note
	LeafIndex uint64
}

// Output describes a note to be created. The sender knows only the recipient's
// address key Apk and chooses the randomness Rho; the recipient learns the full
// note out-of-band (e.g. an encrypted memo) so it can spend it later.
type Output struct {
	Value *big.Int
	Apk   common.Hash
	Rho   common.Hash
}

// RandomField returns a uniformly random canonical BN254 scalar as a 32-byte hash.
func RandomField() common.Hash {
	var e fr.Element
	if _, err := e.SetRandom(); err != nil {
		panic("circuit: rng failure: " + err.Error())
	}
	return fromField(e)
}

func varOf(h common.Hash) frontend.Variable { return new(big.Int).SetBytes(h[:]) }

func randDummyKeys() (ask, rho common.Hash) {
	var a, r [32]byte
	rand.Read(a[:])
	rand.Read(r[:])
	// Reduce into the field to guarantee canonical encodings.
	return fromField(toField(common.BytesToHash(a[:]))), fromField(toField(common.BytesToHash(r[:])))
}

// BuildTransfer assembles a circuit assignment for a shielded transfer along with
// the public fields (nullifiers and output commitments) that the corresponding
// ShieldedTx must carry. It pads the spends and outputs to the circuit arity with
// dummy notes.
//
//   - tree must reflect the commitment set under anchor (used to derive membership
//     paths for the spent notes).
//   - valueBalance is the signed net transparent amount (negative = shield,
//     positive = unshield, zero = pure transfer). If the supplied notes do not
//     conserve value, the assignment will be unprovable.
//
// The returned nullifiers and commitments are in slot order and have length
// NumInputs and NumOutputs respectively.
func BuildTransfer(tree *Tree, anchor common.Hash, spends []Spend, outputs []Output, valueBalance *big.Int) (assignment *Transfer, nullifiers, commitments []common.Hash, err error) {
	if len(spends) > NumInputs || len(outputs) > NumOutputs {
		return nil, nil, nil, ErrArity
	}
	var c Transfer
	c.Anchor = varOf(anchor)

	nullifiers = make([]common.Hash, NumInputs)
	for i := 0; i < NumInputs; i++ {
		if i < len(spends) {
			s := spends[i]
			sib, bits := tree.Path(s.LeafIndex)
			in := InputNote{
				Value:   new(big.Int).Set(s.Note.Value),
				Ask:     varOf(s.Note.Ask),
				Rho:     varOf(s.Note.Rho),
				IsDummy: 0,
			}
			for d := 0; d < MerkleDepth; d++ {
				in.PathElements[d] = varOf(sib[d])
				in.PathIndices[d] = bits[d]
			}
			c.In[i] = in
			nullifiers[i] = s.Note.Nullifier()
		} else {
			ask, rho := randDummyKeys()
			in := InputNote{Value: big.NewInt(0), Ask: varOf(ask), Rho: varOf(rho), IsDummy: 1}
			for d := 0; d < MerkleDepth; d++ {
				in.PathElements[d] = big.NewInt(0)
				in.PathIndices[d] = 0
			}
			c.In[i] = in
			// The dummy's nullifier must be derived exactly as the circuit does:
			// nf = MiMC(ask, cm) with cm the dummy note's commitment.
			dummyCm := NoteCommitment(big.NewInt(0), DeriveApk(ask), rho)
			nullifiers[i] = Nullifier(ask, dummyCm)
		}
		c.Nullifiers[i] = varOf(nullifiers[i])
	}

	commitments = make([]common.Hash, NumOutputs)
	for j := 0; j < NumOutputs; j++ {
		var value *big.Int
		var apk, rho common.Hash
		if j < len(outputs) {
			value = new(big.Int).Set(outputs[j].Value)
			apk, rho = outputs[j].Apk, outputs[j].Rho
		} else {
			value = big.NewInt(0)
			dask, drho := randDummyKeys()
			apk, rho = DeriveApk(dask), drho
		}
		c.Out[j] = OutputNote{Value: value, Apk: varOf(apk), Rho: varOf(rho)}
		commitments[j] = NoteCommitment(value, apk, rho)
		c.OutCommitments[j] = varOf(commitments[j])
	}

	if valueBalance == nil {
		valueBalance = new(big.Int)
	}
	c.ValueMag = new(big.Int).Abs(valueBalance)
	if valueBalance.Sign() < 0 {
		c.ValueNeg = 1
	} else {
		c.ValueNeg = 0
	}
	return &c, nullifiers, commitments, nil
}
