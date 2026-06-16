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
// per-epoch decryption keys so a block proposer can decrypt encrypted-mempool
// transactions at inclusion time.
//
// Decryption uses threshold identity-based encryption (core/privacy/ibe) with the
// epoch as the identity. Each keyper holds one DKG share and releases its epoch-key
// share sigma_i = s_i*H(epoch) only once the decryption trigger for that epoch has
// fired; a threshold of shares combine to the epoch key SK_E = s*H(epoch) that
// decrypts every transaction encrypted for that epoch. Because SK_E does not exist
// until the keypers release it, transactions for a future epoch are
// cryptographically undecryptable — the per-epoch trigger is enforced by the
// cryptography, not only by keyper policy.
//
// The committee shares (s_i) and verification keys (V_i = s_i*G2) are those produced
// by core/privacy/keyper's DKG. A Keyper releases epoch-key shares; a Transport
// collects a threshold of verified shares for an epoch (in-process for tests and
// single-operator devnets, HTTP for independent keyper processes); and Provider
// adapts a Transport to the block builder's epoch-key provider.
package keypernet

import (
	"errors"
	"io"

	"github.com/ethereum/go-ethereum/core/privacy/ibe"
	"github.com/ethereum/go-ethereum/core/privacy/keyper"
	"github.com/ethereum/go-ethereum/core/privacy/threshold"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
)

// ErrInsufficientShares is returned when fewer than the threshold of valid epoch-key
// shares could be collected from the keyper set.
var ErrInsufficientShares = errors.New("keypernet: insufficient epoch-key shares")

// rejectedShareMeter counts epoch-key shares rejected by verification — evidence of
// a malformed or dishonest keyper, surfaced for accountability.
var rejectedShareMeter = metrics.NewRegisteredMeter("keyper/rejected_shares", nil)

// Keyper is a single committee member. It holds one DKG secret share and the
// matching public verification key, and releases a verifiable epoch-key share for a
// requested epoch.
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

// EpochShare produces this keyper's epoch-key share sigma_i = s_i*H(epoch).
func (k *Keyper) EpochShare(epoch uint64) (*ibe.EpochKeyShare, error) {
	return ibe.EpochShare(k.share, epoch)
}

// Transport collects epoch-key shares for an epoch from the keyper network.
type Transport interface {
	Collect(epoch uint64) []*ibe.EpochKeyShare
}

// Provider combines epoch-key shares collected from a Transport into the epoch key,
// verifying every share against the committee verification keys. It implements the
// block builder's epoch-key provider (encmempool.EpochKeyProvider).
type Provider struct {
	transport Transport
	vks       map[uint32]*threshold.VerificationKey
}

// NewInmemProvider builds an epoch-key provider backed by an in-process keyper set
// (the keypers' own verification keys are used to verify their shares). It is for
// single-operator devnets and tests, where one process holds the whole committee
// and therefore provides no threshold trust.
func NewInmemProvider(keypers []*Keyper, triggerEpoch uint64) *Provider {
	vks := make([]*threshold.VerificationKey, len(keypers))
	for i, k := range keypers {
		vks[i] = k.VerificationKey()
	}
	return NewProvider(NewInmemTransport(keypers, triggerEpoch), vks)
}

// NewProvider builds an epoch-key provider over a transport, verifying shares
// against the given committee verification keys.
func NewProvider(transport Transport, vks []*threshold.VerificationKey) *Provider {
	m := make(map[uint32]*threshold.VerificationKey, len(vks))
	for _, vk := range vks {
		if vk != nil {
			m[vk.Index] = vk
		}
	}
	return &Provider{transport: transport, vks: m}
}

// EpochKey collects, verifies, and combines a threshold of epoch-key shares for the
// epoch. It returns nil when the keypers have not released enough valid shares
// (the trigger has not fired, or too few keypers are available) — the
// committee-unavailable fallback that leaves the transaction encrypted.
func (p *Provider) EpochKey(epoch uint64, t int) *ibe.EpochKey {
	if t < 1 {
		return nil
	}
	verified := verifyEpochShares(p.vks, epoch, p.transport.Collect(epoch), t)
	if len(verified) < t {
		return nil
	}
	sk, err := ibe.CombineEpochKey(t, epoch, verified)
	if err != nil {
		return nil
	}
	return sk
}

// verifyEpochShares keeps only shares that verify against the committee
// verification keys, returning at most t of them.
func verifyEpochShares(vks map[uint32]*threshold.VerificationKey, epoch uint64, shares []*ibe.EpochKeyShare, t int) []*ibe.EpochKeyShare {
	out := make([]*ibe.EpochKeyShare, 0, t)
	seen := make(map[uint32]struct{}, t)
	for _, s := range shares {
		if s == nil {
			continue
		}
		if _, dup := seen[s.Index]; dup {
			continue
		}
		vk := vks[s.Index]
		if vk == nil || !ibe.VerifyEpochShare(vk, epoch, s) {
			// Accountability: a share that does not verify is evidence of a
			// malformed or dishonest keyper. Record it loudly and attributably.
			rejectedShareMeter.Mark(1)
			log.Warn("keypernet: rejecting invalid epoch-key share from keyper", "keyper", s.Index, "epoch", epoch)
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

// InmemTransport collects epoch-key shares directly from in-process keypers, gated
// by a trigger epoch: a keyper releases a share only for epochs at or below the
// current trigger. It is used for tests and single-operator devnets.
type InmemTransport struct {
	keypers []*Keyper
	trigger uint64
}

// NewInmemTransport wires a transport to the given in-process keypers. triggerEpoch
// is the highest epoch for which shares may be released.
func NewInmemTransport(keypers []*Keyper, triggerEpoch uint64) *InmemTransport {
	return &InmemTransport{keypers: keypers, trigger: triggerEpoch}
}

// Collect gathers epoch-key shares from the in-process keypers, honoring the
// trigger.
func (t *InmemTransport) Collect(epoch uint64) []*ibe.EpochKeyShare {
	if epoch > t.trigger {
		return nil // epoch's decryption trigger has not fired
	}
	shares := make([]*ibe.EpochKeyShare, 0, len(t.keypers))
	for _, k := range t.keypers {
		s, err := k.EpochShare(epoch)
		if err != nil {
			continue
		}
		shares = append(shares, s)
	}
	return shares
}

// Bootstrap runs a t-of-n distributed key generation in-process and returns the
// keypers, the IBE master public key (derived from the committee), and the
// committee verification keys.
//
// DEVNET ONLY when run in one process: a single operator running every keyper holds
// the whole committee and so provides no threshold trust. A production committee
// runs the per-party DKG in core/privacy/keyper across independent keyper processes.
func Bootstrap(t, n int, rand io.Reader) ([]*Keyper, *ibe.MasterPublicKey, []*threshold.VerificationKey, error) {
	_, shares, vks, err := keyper.RunDKG(t, n, rand)
	if err != nil {
		return nil, nil, nil, err
	}
	mpk, err := ibe.DeriveMasterPublicKey(vks, t)
	if err != nil {
		return nil, nil, nil, err
	}
	keypers := make([]*Keyper, n)
	for i := 0; i < n; i++ {
		keypers[i] = NewKeyper(shares[i], vks[i])
	}
	return keypers, mpk, vks, nil
}
