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

package encmempool

import (
	"fmt"

	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

// Backend is the host hook set for the `enc` protocol.
type Backend interface {
	// RunPeer is invoked when a peer joins on `enc`; it should register the peer
	// and hand control to the supplied handler until the connection is torn down.
	RunPeer(peer *Peer, handler Handler) error

	// PeerInfo retrieves protocol metadata about a peer.
	PeerInfo(id enode.ID) interface{}

	// HandleEnvelopes is invoked when a batch of encrypted envelopes arrives.
	HandleEnvelopes(peer *Peer, envelopes [][]byte) error
}

// Handler processes inbound messages for a peer after connection setup.
type Handler func(peer *Peer) error

// MakeProtocols constructs the p2p protocol definitions for `enc`.
func MakeProtocols(backend Backend) []p2p.Protocol {
	protocols := make([]p2p.Protocol, len(ProtocolVersions))
	for i, version := range ProtocolVersions {
		protocols[i] = p2p.Protocol{
			Name:    ProtocolName,
			Version: version,
			Length:  protocolLengths[version],
			Run: func(p *p2p.Peer, rw p2p.MsgReadWriter) error {
				return backend.RunPeer(NewPeer(version, p, rw), func(peer *Peer) error {
					defer peer.Close()
					return Handle(backend, peer)
				})
			},
			PeerInfo: func(id enode.ID) interface{} {
				return backend.PeerInfo(id)
			},
		}
	}
	return protocols
}

// Handle runs the message loop for an `enc` peer until the connection drops.
func Handle(backend Backend, peer *Peer) error {
	for {
		if err := handleMessage(backend, peer); err != nil {
			peer.Log().Debug("Message handling failed in `enc`", "err", err)
			return err
		}
	}
}

// handleMessage reads and dispatches a single inbound `enc` message.
func handleMessage(backend Backend, peer *Peer) error {
	msg, err := peer.rw.ReadMsg()
	if err != nil {
		return err
	}
	if msg.Size > maxMessageSize {
		return fmt.Errorf("%w: %v > %v", errMsgTooLarge, msg.Size, maxMessageSize)
	}
	defer msg.Discard()

	switch msg.Code {
	case EnvelopesMsg:
		var envelopes EnvelopesPacket
		if err := msg.Decode(&envelopes); err != nil {
			return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
		}
		return backend.HandleEnvelopes(peer, envelopes)

	default:
		return fmt.Errorf("%w: %v", errInvalidMsgCode, msg.Code)
	}
}
