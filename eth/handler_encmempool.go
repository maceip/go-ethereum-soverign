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

package eth

import (
	"github.com/ethereum/go-ethereum/common"
	encbuf "github.com/ethereum/go-ethereum/core/privacy/encmempool"
	"github.com/ethereum/go-ethereum/crypto"
	encproto "github.com/ethereum/go-ethereum/eth/protocols/encmempool"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

// This file wires the `enc` encrypted-mempool propagation sub-protocol
// (eth/protocols/encmempool) into the eth handler. It floods opaque
// threshold-encrypted envelopes across `enc`-capable peers with content-hash
// deduplication, so the encrypted mempool is a network-level facility. It never
// handles plaintext; committee decryption and block inclusion are a later stage.

const encPoolMax = 8192

var encEnvelopeMeter = metrics.NewRegisteredMeter("eth/encmempool/envelopes", nil)

// encmempoolHandler implements the `enc` sub-protocol Backend on the eth handler.
type encmempoolHandler handler

// RunPeer registers an `enc` peer for the duration of its connection.
func (h *encmempoolHandler) RunPeer(peer *encproto.Peer, hand encproto.Handler) error {
	(*handler)(h).registerEncPeer(peer)
	defer (*handler)(h).unregisterEncPeer(peer.ID())
	return hand(peer)
}

// PeerInfo implements the `enc` Backend; the protocol exposes no extra peer info.
func (h *encmempoolHandler) PeerInfo(id enode.ID) interface{} { return nil }

// HandleEnvelopes implements the `enc` Backend: buffer and re-flood new envelopes.
func (h *encmempoolHandler) HandleEnvelopes(peer *encproto.Peer, envelopes [][]byte) error {
	return (*handler)(h).handleEnvelopes(peer.ID(), envelopes)
}

// encPeer returns the connected `enc` peer with the given id, or nil.
func (h *handler) encPeer(id enode.ID) *encproto.Peer {
	h.encPeerLock.RLock()
	defer h.encPeerLock.RUnlock()
	return h.encPeers[id]
}

// registerEncPeer adds an `enc` peer and syncs the current envelope buffer to it.
func (h *handler) registerEncPeer(peer *encproto.Peer) {
	h.encPeerLock.Lock()
	h.encPeers[peer.ID()] = peer
	h.encPeerLock.Unlock()
	h.syncEnvelopes(peer)
}

// unregisterEncPeer drops an `enc` peer.
func (h *handler) unregisterEncPeer(id enode.ID) {
	h.encPeerLock.Lock()
	delete(h.encPeers, id)
	h.encPeerLock.Unlock()
}

// handleEnvelopes buffers inbound envelopes and re-floods the newly-seen ones to
// other `enc` peers. Malformed or oversized envelopes are dropped.
func (h *handler) handleEnvelopes(from enode.ID, blobs [][]byte) error {
	if h.encPool == nil {
		return nil
	}
	var fresh [][]byte
	for _, blob := range blobs {
		env, err := encbuf.NewEnvelope(blob)
		if err != nil {
			continue // ignore malformed/oversized envelopes
		}
		if p := h.encPeer(from); p != nil {
			p.MarkKnown(env.ID())
		}
		if h.encPool.Add(env) {
			fresh = append(fresh, blob)
			encEnvelopeMeter.Mark(1)
		}
	}
	if len(fresh) > 0 {
		h.floodEnvelopes(from, fresh)
	}
	return nil
}

// submitEncryptedEnvelope buffers a locally-produced envelope and floods it to all
// `enc` peers. It is the local-origin entry point for the encrypted mempool.
func (h *handler) submitEncryptedEnvelope(env *encbuf.Envelope) bool {
	if h.encPool == nil {
		return false
	}
	if !h.encPool.Add(env) {
		return false
	}
	encEnvelopeMeter.Mark(1)
	h.floodEnvelopes(enode.ID{}, [][]byte{env.Ciphertext})
	return true
}

// floodEnvelopes sends the given envelope blobs to every `enc` peer except the
// sender and any peer already known to hold them.
func (h *handler) floodEnvelopes(except enode.ID, blobs [][]byte) {
	ids := make([]common.Hash, len(blobs))
	for i, b := range blobs {
		ids[i] = crypto.Keccak256Hash(b)
	}
	h.encPeerLock.RLock()
	peers := make([]*encproto.Peer, 0, len(h.encPeers))
	for id, p := range h.encPeers {
		if id == except {
			continue
		}
		peers = append(peers, p)
	}
	h.encPeerLock.RUnlock()

	for _, p := range peers {
		var send [][]byte
		for i, b := range blobs {
			if p.Knows(ids[i]) {
				continue
			}
			p.MarkKnown(ids[i])
			send = append(send, b)
		}
		if len(send) > 0 {
			p.SendEnvelopes(send)
		}
	}
}

// syncEnvelopes sends the current buffered envelopes to a freshly-connected peer
// so it catches up on the encrypted mempool.
func (h *handler) syncEnvelopes(peer *encproto.Peer) {
	if h.encPool == nil {
		return
	}
	pending := h.encPool.Pending()
	if len(pending) == 0 {
		return
	}
	var blobs [][]byte
	for _, e := range pending {
		if peer.Knows(e.ID()) {
			continue
		}
		peer.MarkKnown(e.ID())
		blobs = append(blobs, e.Ciphertext)
	}
	if len(blobs) > 0 {
		peer.SendEnvelopes(blobs)
	}
}
