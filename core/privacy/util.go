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
	"crypto/rand"
	"math/big"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	"golang.org/x/crypto/sha3"
)

// keccak returns the Keccak-256 digest of the concatenated inputs. It is kept
// local to the package (rather than importing crypto) so that this package can be
// imported by low-level callers without pulling in the wider crypto dependency
// graph.
func keccak(data ...[]byte) []byte {
	h := sha3.NewLegacyKeccak256()
	for _, b := range data {
		h.Write(b)
	}
	return h.Sum(nil)
}

// RandomScalar samples a uniformly random non-zero scalar in [1, Order) suitable
// for use as a Pedersen blinding factor. Blinding factors must never be reused or
// made predictable, otherwise the hiding property of the commitment is lost.
func RandomScalar() (*big.Int, error) {
	for {
		k, err := rand.Int(rand.Reader, bn256.Order)
		if err != nil {
			return nil, err
		}
		if k.Sign() != 0 {
			return k, nil
		}
	}
}
