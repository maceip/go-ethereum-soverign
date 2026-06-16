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

// Package keypernet is the keyper network for the encrypted mempool: the service
// that generates the committee key by distributed key generation and releases
// threshold decryption shares so a block proposer can decrypt encrypted-mempool
// transactions at inclusion time.
//
// It ties together the cryptographic pieces built elsewhere in this fork:
//
//   - core/privacy/keyper (DKG) generates each keyper's secret share and the
//     committee (eon) public key, with no single party holding the master secret;
//   - core/privacy/threshold provides encryption, per-share decryption, share
//     verification, and Lagrange combination;
//   - core/privacy/encmempool consumes the released shares (this package provides a
//     ShareProvider) to decrypt envelopes during block building.
//
// A Keyper holds one DKG share and answers decryption-share requests. A Transport
// collects a threshold of verified shares for a ciphertext from the keyper set; an
// in-process transport is used for tests and single-operator devnets, and an HTTP
// transport (http.go) connects independently-run keyper processes. Provider adapts
// a Transport to the encmempool.ShareProvider the block builder expects.
package keypernet

import (
	"errors"
	"io"

	"github.com/ethereum/go-ethereum/core/privacy/encmempool"
	"github.com/ethereum/go-ethereum/core/privacy/keyper"
	"github.com/ethereum/go-ethereum/core/privacy/threshold"
	"github.com/ethereum/go-ethereum/log"
)

// ErrInsufficientShares is returned when fewer than the threshold of valid shares
// could be collected from the keyper set.
var ErrInsufficientShares = errors.New("keypernet: insufficient decryption shares")

// Keyper is a single committee member. It holds one DKG secret share and the
// matching public verification key, and produces a verifiable decryption share for
// any ciphertext on request.
//
// In production a Keyper runs in its own process and only releases shares once the
// decryption trigger for the relevant epoch has fired (so it cannot be coerced into
// decrypting transactions before they are due for inclusion). The proposer requests
// shares at block-build time, which is the trigger in this fork.
type Keyper struct {
	share *threshold.KeyShare
	vk    *threshold.VerificationKey
}

// NewKeyper builds a keyper from its DKG secret share and verification key.
func NewKeyper(share *threshold.KeyShare, vk *threshold.VerificationKey) *Keyper {
	return &Keyper{share: share, vk: vk}
}

// Index returns the keyper's committee index.
func (k *Keyper) Index() uint32 { return k.share.Index }

// VerificationKey returns the keyper's public verification key.
func (k *Keyper) VerificationKey() *threshold.VerificationKey { return k.vk }

// DecryptionShare produces this keyper's decryption share for ct.
func (k *Keyper) DecryptionShare(ct *threshold.Ciphertext) *threshold.DecryptionShare {
	return k.share.Decrypt(ct)
}

// Transport collects decryption shares for a ciphertext from the keyper network.
// Implementations must return only shares that verify against the committee's
// verification keys, and at most as many as requested.
type Transport interface {
	Collect(ct *threshold.Ciphertext, need int) ([]*threshold.DecryptionShare, error)
}

// Provider adapts a Transport to the encmempool.ShareProvider interface the block
// builder uses, so decrypt-at-inclusion runs against the live keyper network.
type Provider struct {
	transport Transport
}

// NewProvider returns an encmempool.ShareProvider backed by the keyper network.
func NewProvider(transport Transport) *Provider {
	return &Provider{transport: transport}
}

// Shares implements encmempool.ShareProvider. It returns nil when the keyper
// network has not released a threshold of shares, which leaves the transaction
// encrypted (the committee-unavailable fallback).
func (p *Provider) Shares(ct *threshold.Ciphertext, t int) []*threshold.DecryptionShare {
	shares, err := p.transport.Collect(ct, t)
	if err != nil || len(shares) < t {
		return nil
	}
	return shares
}

// verify keeps only shares that verify against the supplied committee verification
// keys, returning at most t of them.
func verify(vks map[uint32]*threshold.VerificationKey, ct *threshold.Ciphertext, shares []*threshold.DecryptionShare, t int) []*threshold.DecryptionShare {
	out := make([]*threshold.DecryptionShare, 0, t)
	seen := make(map[uint32]struct{}, t)
	for _, s := range shares {
		if s == nil {
			continue
		}
		if _, dup := seen[s.Index]; dup {
			continue
		}
		vk := vks[s.Index]
		if vk == nil || !threshold.VerifyShare(vk, ct, s) {
			log.Debug("keypernet: rejecting invalid decryption share", "index", s.Index)
			continue
		}
		seen[s.Index] = struct{}{}
		out = append(out, s)
		if len(out) >= t {
			break
		}
	}
	return out
}

// InmemTransport collects shares directly from in-process keypers. It is used for
// tests and single-operator devnets; a production deployment uses HTTPTransport (or
// another networked transport) across independent keyper processes.
type InmemTransport struct {
	keypers []*Keyper
	vks     map[uint32]*threshold.VerificationKey
}

// NewInmemTransport wires a transport to the given in-process keypers.
func NewInmemTransport(keypers []*Keyper) *InmemTransport {
	vks := make(map[uint32]*threshold.VerificationKey, len(keypers))
	for _, k := range keypers {
		vks[k.Index()] = k.VerificationKey()
	}
	return &InmemTransport{keypers: keypers, vks: vks}
}

// Collect gathers and verifies up to t decryption shares from the in-process
// keypers.
func (t *InmemTransport) Collect(ct *threshold.Ciphertext, need int) ([]*threshold.DecryptionShare, error) {
	shares := make([]*threshold.DecryptionShare, 0, len(t.keypers))
	for _, k := range t.keypers {
		shares = append(shares, k.DecryptionShare(ct))
	}
	verified := verify(t.vks, ct, shares, need)
	if len(verified) < need {
		return nil, ErrInsufficientShares
	}
	return verified, nil
}

// Bootstrap runs a t-of-n distributed key generation in-process and returns the
// keypers, the committee (eon) public key, and the committee verification keys.
//
// DEVNET ONLY when run in one process: a single operator running every keyper holds
// the whole committee and so provides no threshold trust. A production committee
// runs the per-party DKG in core/privacy/keyper across independent keyper processes
// and only the resulting eon key is published. Bootstrap exists for tests and for
// standing up a single-operator devnet.
func Bootstrap(t, n int, rand io.Reader) ([]*Keyper, *threshold.PublicKey, []*threshold.VerificationKey, error) {
	eon, shares, vks, err := keyper.RunDKG(t, n, rand)
	if err != nil {
		return nil, nil, nil, err
	}
	keypers := make([]*Keyper, n)
	for i := 0; i < n; i++ {
		keypers[i] = NewKeyper(shares[i], vks[i])
	}
	return keypers, eon, vks, nil
}

// Ensure Provider satisfies the block builder's expectation.
var _ encmempool.ShareProvider = (*Provider)(nil)
