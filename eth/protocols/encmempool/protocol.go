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

// Package encmempool implements the `enc` devp2p sub-protocol that propagates
// threshold-encrypted transaction envelopes between peers, making the encrypted
// mempool (core/privacy/encmempool) a network-level facility rather than a
// local-only buffer — the property shape.md requires of the encrypted mempool.
//
// The protocol carries only opaque ciphertext envelopes; it never sees plaintext.
// Envelopes are flooded with content-hash deduplication so they reach the whole
// `enc`-capable subgraph. Decryption and block inclusion are handled separately by
// the committee at inclusion time, not by this propagation layer.
package encmempool

import (
	"errors"
)

// ProtocolName is the devp2p capability name for the encrypted-mempool protocol.
const ProtocolName = "enc"

// ENC1 is the first version of the `enc` protocol.
const ENC1 = 1

// ProtocolVersions are the supported versions of the `enc` protocol.
var ProtocolVersions = []uint{ENC1}

// protocolLengths is the number of message codes per version.
var protocolLengths = map[uint]uint64{ENC1: 1}

// maxMessageSize caps an `enc` message; it accommodates a batch of envelopes, each
// bounded by core/privacy/encmempool.MaxEnvelopeSize.
const maxMessageSize = 16 * 1024 * 1024

const (
	// EnvelopesMsg carries a batch of encrypted-transaction envelope ciphertexts.
	EnvelopesMsg = 0x00
)

var (
	errMsgTooLarge    = errors.New("message too long")
	errDecode         = errors.New("invalid message")
	errInvalidMsgCode = errors.New("invalid message code")
)

// EnvelopesPacket is the network packet for encrypted-mempool envelopes: a batch
// of opaque ciphertext blobs (each a marshalled threshold ciphertext).
type EnvelopesPacket [][]byte

// Name implements the packet naming convention.
func (*EnvelopesPacket) Name() string { return "Envelopes" }

// Kind returns the message code.
func (*EnvelopesPacket) Kind() byte { return EnvelopesMsg }
