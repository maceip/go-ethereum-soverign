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

// Package dandelion implements the `dle` devp2p sub-protocol, the explicit
// stem-relay signal for Dandelion++ network-origin privacy (Phase 1).
//
// Ordinary `eth` transaction gossip cannot express "this transaction is in the
// stem phase": a directly-sent transaction is indistinguishable from a normal
// square-root broadcast, so a receiving node cannot tell it should continue
// stemming rather than diffuse. Without that signal a stem can only ever be one
// hop long, which collapses the anonymity to the originator's immediate neighbour.
//
// The `dle` protocol carries stem-phase transactions between peers that both
// advertise it. A node that receives a `StemTransactions` message knows the
// transaction arrived in the stem phase and runs it through its own Dandelion++
// router: it either forwards it to its own stem successor (continuing the stem) or
// transitions it to fluff via normal `eth` diffusion. Peers that do not advertise
// `dle` simply never receive stem messages, so the feature degrades cleanly to
// ordinary gossip. The protocol is non-consensus and carries no block data.
package dandelion

import (
	"errors"

	"github.com/ethereum/go-ethereum/core/types"
)

// ProtocolName is the official short name of the Dandelion++ stem protocol used
// during devp2p capability negotiation.
const ProtocolName = "dle"

// DLE1 is the first version of the `dle` protocol.
const DLE1 = 1

// ProtocolVersions are the supported versions of the `dle` protocol (first is
// primary).
var ProtocolVersions = []uint{DLE1}

// protocolLengths are the number of implemented messages corresponding to
// different protocol versions.
var protocolLengths = map[uint]uint64{DLE1: 1}

// maxMessageSize is the maximum cap on the size of a protocol message.
const maxMessageSize = 10 * 1024 * 1024

const (
	// StemTransactionsMsg carries a batch of full transactions that are in the
	// Dandelion++ stem phase and must be routed, not diffused, by the receiver.
	StemTransactionsMsg = 0x00
)

var (
	errMsgTooLarge    = errors.New("message too long")
	errDecode         = errors.New("invalid message")
	errInvalidMsgCode = errors.New("invalid message code")
)

// Packet represents a p2p message in the `dle` protocol.
type Packet interface {
	Name() string // Name returns a string corresponding to the message type.
	Kind() byte   // Kind returns the message type.
}

// StemTransactionsPacket is the network packet for stem-phase transactions.
type StemTransactionsPacket []*types.Transaction

// Name implements Packet.
func (*StemTransactionsPacket) Name() string { return "StemTransactions" }

// Kind implements Packet.
func (*StemTransactionsPacket) Kind() byte { return StemTransactionsMsg }
