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

package keyper

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"

	"github.com/ethereum/go-ethereum/core/privacy/threshold"
	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
)

// Distributed key generation (Pedersen DKG with Feldman verifiable secret sharing)
// for the keyper committee. This is the trustless replacement for the
// threshold.DealerSetup trusted dealer: the committee's master secret is the sum
// of every keyper's private polynomial constant term, so no single keyper ever
// knows it.
//
// Protocol (each keyper i in 1..n):
//  1. samples a secret degree-(t-1) polynomial f_i and broadcasts Feldman
//     commitments C_i,k = a_i,k * G1 to its coefficients;
//  2. privately sends the share s_i,j = f_i(j) to each keyper j;
//  3. every recipient j verifies s_i,j against C_i with the Feldman check
//     s_i,j * G1 == Σ_k j^k * C_i,k, rejecting a cheating dealer.
//
// The committee (eon) key is Σ_i C_i,0 = s * G1 where s = Σ_i f_i(0). Keyper j's
// final secret share is s_j = Σ_i s_i,j, a Shamir share of s at point j, with
// verification key V_j = s_j * G2. These are exactly the shapes
// threshold.Encrypt / Decrypt / Combine consume.
//
// This file is the DKG *protocol logic*. The keyper network that carries the
// broadcasts and private sends between separate keyper processes is a distinct
// service; RunDKG drives all participants in-process for tests and for a
// single-operator devnet bootstrap.

var order = bn256.Order

var (
	errDKGParams = errors.New("keyper: invalid DKG parameters")
	errDKGShare  = errors.New("keyper: invalid DKG share")
)

// Participant is one keyper's DKG state: its secret polynomial and the public
// Feldman commitments it broadcasts.
type Participant struct {
	Index       uint32
	t, n        int
	coeffs      []*big.Int  // secret polynomial coefficients a_0..a_{t-1}
	commitments []*bn256.G1 // C_k = a_k * G1
}

// NewParticipant creates keyper `index` (1..n) for a t-of-n committee, sampling
// its secret polynomial and computing its Feldman commitments.
func NewParticipant(index uint32, t, n int, r io.Reader) (*Participant, error) {
	if t < 1 || n < 1 || t > n || index < 1 || int(index) > n {
		return nil, errDKGParams
	}
	coeffs := make([]*big.Int, t)
	commitments := make([]*bn256.G1, t)
	for k := 0; k < t; k++ {
		c, err := randScalar(r)
		if err != nil {
			return nil, err
		}
		coeffs[k] = c
		commitments[k] = new(bn256.G1).ScalarBaseMult(c)
	}
	return &Participant{Index: index, t: t, n: n, coeffs: coeffs, commitments: commitments}, nil
}

// Commitments returns the Feldman commitments this keyper broadcasts.
func (p *Participant) Commitments() []*bn256.G1 { return p.commitments }

// Share returns the secret share f_i(j) this keyper privately sends to keyper j.
func (p *Participant) Share(j uint32) *big.Int {
	return evalPoly(p.coeffs, new(big.Int).SetUint64(uint64(j)))
}

// VerifyShare checks a received share s_i,j against keyper i's broadcast
// commitments using the Feldman relation s*G1 == Σ_k j^k * C_k. A false result
// means the dealer cheated (or the share was corrupted).
func VerifyShare(commitments []*bn256.G1, j uint32, share *big.Int) bool {
	if len(commitments) == 0 {
		return false
	}
	lhs := new(bn256.G1).ScalarBaseMult(new(big.Int).Mod(share, order))
	rhs := new(bn256.G1).ScalarBaseMult(big.NewInt(0)) // identity
	jb := new(big.Int).SetUint64(uint64(j))
	jpow := big.NewInt(1)
	for _, ck := range commitments {
		term := new(bn256.G1).ScalarMult(ck, new(big.Int).Set(jpow))
		rhs.Add(rhs, term)
		jpow.Mul(jpow, jb)
		jpow.Mod(jpow, order)
	}
	return equalG1(lhs, rhs)
}

// AggregateEonKey computes the committee public key Σ_i C_i,0 from every keyper's
// broadcast commitments.
func AggregateEonKey(allCommitments [][]*bn256.G1) (*threshold.PublicKey, error) {
	if len(allCommitments) == 0 {
		return nil, errDKGParams
	}
	sum := new(bn256.G1).ScalarBaseMult(big.NewInt(0)) // identity
	for _, comms := range allCommitments {
		if len(comms) == 0 {
			return nil, errDKGParams
		}
		sum.Add(sum, comms[0])
	}
	return &threshold.PublicKey{P: sum}, nil
}

// FinalShare combines the shares keyper j received from all keypers (including
// itself) into its Shamir secret share s_j = Σ_i s_i,j and the matching
// verification key V_j = s_j * G2.
func FinalShare(j uint32, received []*big.Int) (*threshold.KeyShare, *threshold.VerificationKey, error) {
	if len(received) == 0 {
		return nil, nil, errDKGShare
	}
	s := new(big.Int)
	for _, sij := range received {
		s.Add(s, sij)
	}
	s.Mod(s, order)
	share := &threshold.KeyShare{Index: j, Secret: s}
	g2 := new(bn256.G2).ScalarBaseMult(big.NewInt(1))
	vk := &threshold.VerificationKey{Index: j, Point: new(bn256.G2).ScalarMult(g2, s)}
	return share, vk, nil
}

// RunDKG drives a full t-of-n distributed key generation among n participants
// in-process, verifying every dealt share, and returns the committee public key,
// the per-keyper secret shares, and verification keys. In a real deployment the
// keyper network performs the same steps across separate processes; running it
// in-process is appropriate for tests and for a single-operator devnet bootstrap
// (which is still a real DKG, just not distributed across operators).
func RunDKG(t, n int, r io.Reader) (*threshold.PublicKey, []*threshold.KeyShare, []*threshold.VerificationKey, error) {
	if t < 1 || n < 1 || t > n {
		return nil, nil, nil, errDKGParams
	}
	parts := make([]*Participant, n)
	for i := 0; i < n; i++ {
		p, err := NewParticipant(uint32(i+1), t, n, r)
		if err != nil {
			return nil, nil, nil, err
		}
		parts[i] = p
	}

	// Broadcast commitments and verify every private share.
	allCommitments := make([][]*bn256.G1, n)
	for i, p := range parts {
		allCommitments[i] = p.Commitments()
	}
	// received[j-1] collects the shares keyper j got from every dealer i.
	received := make([][]*big.Int, n)
	for j := 1; j <= n; j++ {
		shares := make([]*big.Int, 0, n)
		for i := 0; i < n; i++ {
			sij := parts[i].Share(uint32(j))
			if !VerifyShare(allCommitments[i], uint32(j), sij) {
				return nil, nil, nil, errDKGShare
			}
			shares = append(shares, sij)
		}
		received[j-1] = shares
	}

	eon, err := AggregateEonKey(allCommitments)
	if err != nil {
		return nil, nil, nil, err
	}
	shares := make([]*threshold.KeyShare, n)
	vks := make([]*threshold.VerificationKey, n)
	for j := 1; j <= n; j++ {
		share, vk, err := FinalShare(uint32(j), received[j-1])
		if err != nil {
			return nil, nil, nil, err
		}
		shares[j-1] = share
		vks[j-1] = vk
	}
	return eon, shares, vks, nil
}

// evalPoly evaluates Σ coeffs[k]*x^k mod order (Horner).
func evalPoly(coeffs []*big.Int, x *big.Int) *big.Int {
	acc := new(big.Int)
	for k := len(coeffs) - 1; k >= 0; k-- {
		acc.Mul(acc, x)
		acc.Add(acc, coeffs[k])
		acc.Mod(acc, order)
	}
	return acc
}

// randScalar samples a uniform non-zero scalar in [1, order).
func randScalar(r io.Reader) (*big.Int, error) {
	for {
		k, err := rand.Int(r, order)
		if err != nil {
			return nil, err
		}
		if k.Sign() != 0 {
			return k, nil
		}
	}
}

func equalG1(a, b *bn256.G1) bool {
	return string(a.Marshal()) == string(b.Marshal())
}
