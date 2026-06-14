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

// Package privacy implements the foundational cryptographic primitives described
// in the "Ethereum Privacy: The Road to Self-Sovereignty" roadmap
// (https://ethresear.ch/t/ethereum-privacy-the-road-to-self-sovereignty/22115).
//
// The package is intentionally self-contained so that it can be consumed both by
// the EVM (via the privacy precompiles defined in package vm) and by node-side
// wallet/RPC tooling. It currently provides the building blocks for:
//
//   - Phase 1 "Sealed amounts": additively-homomorphic Pedersen commitments used
//     to hide transaction values while preserving the ability to prove balance
//     consistency (inputs == outputs + fee).
//   - Phase 1 "native stealth addresses": EIP-5564 stealth-address generation and
//     detection so that a fresh, unlinkable one-time address can be derived for
//     every payment.
//   - Phase 2/4 shielded pools: an incremental Merkle tree of note commitments and
//     a nullifier set providing double-spend prevention, mirroring the designs used
//     by Zcash Sapling and Tornado Cash referenced throughout the roadmap.
//
// None of these primitives change Ethereum's consensus rules on their own; they
// are the reusable cryptographic substrate on top of which the privacy
// transaction format, encrypted mempool and shielded pool described in the
// roadmap are built.
package privacy
