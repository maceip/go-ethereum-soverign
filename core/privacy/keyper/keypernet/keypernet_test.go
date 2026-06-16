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

package keypernet

import (
	"bytes"
	"crypto/rand"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/core/privacy/ibe"
)

const maxEpoch = ^uint64(0)

// roundTrip encrypts msg for epoch, obtains the epoch key from the provider, and
// returns the recovered plaintext.
func roundTrip(t *testing.T, mpk *ibe.MasterPublicKey, provider *Provider, need int, epoch uint64, msg []byte) []byte {
	t.Helper()
	ct, err := ibe.Encrypt(mpk, epoch, msg, rand.Reader)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	sk := provider.EpochKey(epoch, need)
	if sk == nil {
		t.Fatalf("provider returned no epoch key for epoch %d", epoch)
	}
	got, err := ibe.Decrypt(sk, ct)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	return got
}

// TestInmemNetworkEndToEnd bootstraps a committee and recovers a message using the
// epoch key collected from the in-process keyper network.
func TestInmemNetworkEndToEnd(t *testing.T) {
	const tt, n = 3, 5
	keypers, mpk, vks, err := Bootstrap(tt, n, rand.Reader)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	provider := NewProvider(NewInmemTransport(keypers, maxEpoch), vks)

	msg := []byte("decrypted by the keyper network at inclusion")
	if got := roundTrip(t, mpk, provider, tt, 42, msg); !bytes.Equal(got, msg) {
		t.Fatalf("got %q, want %q", got, msg)
	}
}

// TestInmemBelowThreshold checks the provider yields no key when fewer than the
// threshold of keypers are available.
func TestInmemBelowThreshold(t *testing.T) {
	const tt, n = 3, 5
	keypers, _, vks, err := Bootstrap(tt, n, rand.Reader)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	provider := NewProvider(NewInmemTransport(keypers[:tt-1], maxEpoch), vks)
	if sk := provider.EpochKey(1, tt); sk != nil {
		t.Fatal("got an epoch key with too few keypers")
	}
}

// TestInmemTriggerGating checks a keyper releases no share for an epoch beyond the
// trigger, so a future epoch's key cannot be assembled.
func TestInmemTriggerGating(t *testing.T) {
	const tt, n = 3, 5
	keypers, _, vks, err := Bootstrap(tt, n, rand.Reader)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	// Trigger only up to epoch 10.
	provider := NewProvider(NewInmemTransport(keypers, 10), vks)
	if sk := provider.EpochKey(11, tt); sk != nil {
		t.Fatal("released a key for an epoch beyond the trigger")
	}
	if sk := provider.EpochKey(10, tt); sk == nil {
		t.Fatal("did not release a key for a triggered epoch")
	}
}

// TestHTTPNetworkEndToEnd runs each keyper behind its own HTTP server and collects
// the epoch key over the network.
func TestHTTPNetworkEndToEnd(t *testing.T) {
	const tt, n = 3, 5
	keypers, mpk, vks, err := Bootstrap(tt, n, rand.Reader)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	urls := serveKeypers(t, keypers, "", true, maxEpoch)
	provider := NewProvider(NewHTTPTransport(urls, 2*time.Second, ""), vks)

	msg := []byte("recovered over HTTP from the keyper network")
	if got := roundTrip(t, mpk, provider, tt, 7, msg); !bytes.Equal(got, msg) {
		t.Fatalf("got %q, want %q", got, msg)
	}
}

// TestHTTPToleratesDownKeypers checks the epoch key is still assembled when some
// keypers are unreachable, and fails closed when too many are down.
func TestHTTPToleratesDownKeypers(t *testing.T) {
	const tt, n = 3, 5
	keypers, mpk, vks, err := Bootstrap(tt, n, rand.Reader)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	urls := make([]string, 0, n)
	for i, k := range keypers {
		if i < 3 {
			srv := httptest.NewServer(k.ServeMux())
			defer srv.Close()
			urls = append(urls, srv.URL)
		} else {
			urls = append(urls, "http://127.0.0.1:1")
		}
	}
	provider := NewProvider(NewHTTPTransport(urls, 500*time.Millisecond, ""), vks)
	msg := []byte("threshold met despite down keypers")
	if got := roundTrip(t, mpk, provider, tt, 3, msg); !bytes.Equal(got, msg) {
		t.Fatalf("got %q, want %q", got, msg)
	}
}

// TestHTTPAuthAndTrigger checks the server enforces the auth token and the enable
// trigger.
func TestHTTPAuthAndTrigger(t *testing.T) {
	const tt, n = 2, 3
	keypers, mpk, vks, err := Bootstrap(tt, n, rand.Reader)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	const token = "proposer-token"
	servers := make([]*Server, n)
	urls := make([]string, n)
	for i, k := range keypers {
		servers[i] = NewServer(k, token)
		srv := httptest.NewServer(servers[i].Handler())
		defer srv.Close()
		urls[i] = srv.URL
	}

	// Disabled: no key even with the right token.
	authed := NewProvider(NewHTTPTransport(urls, time.Second, token), vks)
	if sk := authed.EpochKey(1, tt); sk != nil {
		t.Fatal("disabled keypers released a key")
	}
	for _, s := range servers {
		s.SetEnabled(true)
		s.SetTriggerEpoch(maxEpoch)
	}
	// Wrong token: rejected.
	noAuth := NewProvider(NewHTTPTransport(urls, time.Second, "wrong"), vks)
	if sk := noAuth.EpochKey(1, tt); sk != nil {
		t.Fatal("released a key to an unauthorized requester")
	}
	// Correct token and enabled: works.
	msg := []byte("authorized and enabled")
	if got := roundTrip(t, mpk, authed, tt, 1, msg); !bytes.Equal(got, msg) {
		t.Fatalf("got %q, want %q", got, msg)
	}
}

// TestRejectsForgedShare checks a keyper serving shares from an unrelated committee
// is excluded by share verification, while honest keypers still meet the threshold.
func TestRejectsForgedShare(t *testing.T) {
	const tt, n = 2, 3
	keypers, mpk, vks, err := Bootstrap(tt, n, rand.Reader)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	// Forge keyper index 2 with a share from another committee.
	foreign, _, _, err := Bootstrap(tt, n, rand.Reader)
	if err != nil {
		t.Fatalf("foreign bootstrap: %v", err)
	}
	// A keyper holding a foreign committee's secret share at the same index: its
	// epoch-key shares will not verify against this committee's verification key.
	forged := NewKeyper(foreign[1].share, vks[1])

	honest0 := httptest.NewServer(keypers[0].ServeMux())
	defer honest0.Close()
	forgedSrv := httptest.NewServer(forged.ServeMux())
	defer forgedSrv.Close()
	honest2 := httptest.NewServer(keypers[2].ServeMux())
	defer honest2.Close()

	urls := []string{honest0.URL, forgedSrv.URL, honest2.URL}
	provider := NewProvider(NewHTTPTransport(urls, time.Second, ""), vks)

	msg := []byte("forged share excluded, honest threshold met")
	if got := roundTrip(t, mpk, provider, tt, 9, msg); !bytes.Equal(got, msg) {
		t.Fatalf("got %q, want %q", got, msg)
	}
}

// serveKeypers starts an HTTP server per keyper and returns their base URLs.
func serveKeypers(t *testing.T, keypers []*Keyper, token string, enabled bool, trigger uint64) []string {
	t.Helper()
	urls := make([]string, len(keypers))
	for i, k := range keypers {
		s := NewServer(k, token)
		s.SetEnabled(enabled)
		s.SetTriggerEpoch(trigger)
		srv := httptest.NewServer(s.Handler())
		t.Cleanup(srv.Close)
		urls[i] = srv.URL
	}
	return urls
}
