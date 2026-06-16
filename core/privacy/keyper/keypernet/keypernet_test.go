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

	"github.com/ethereum/go-ethereum/core/privacy/threshold"
)

// roundTrip encrypts msg to eon, collects shares via the provider, and returns the
// recovered plaintext.
func roundTrip(t *testing.T, eon *threshold.PublicKey, provider *Provider, need int, msg []byte) []byte {
	t.Helper()
	ct, err := threshold.Encrypt(eon, msg, rand.Reader)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	shares := provider.Shares(ct, need)
	if len(shares) < need {
		t.Fatalf("provider returned %d shares, want >= %d", len(shares), need)
	}
	got, err := threshold.Combine(need, ct, shares)
	if err != nil {
		t.Fatalf("combine: %v", err)
	}
	return got
}

// TestInmemNetworkEndToEnd bootstraps a committee, then encrypts and recovers a
// message using shares collected from the in-process keyper network.
func TestInmemNetworkEndToEnd(t *testing.T) {
	const tt, n = 3, 5
	keypers, eon, _, err := Bootstrap(tt, n, rand.Reader)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	provider := NewProvider(NewInmemTransport(keypers))

	msg := []byte("decrypted by the keyper network at inclusion")
	if got := roundTrip(t, eon, provider, tt, msg); !bytes.Equal(got, msg) {
		t.Fatalf("got %q, want %q", got, msg)
	}
}

// TestInmemBelowThreshold checks the provider yields nothing when fewer than the
// threshold of keypers are available (committee-unavailable fallback).
func TestInmemBelowThreshold(t *testing.T) {
	const tt, n = 3, 5
	keypers, eon, _, err := Bootstrap(tt, n, rand.Reader)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	// Only t-1 keypers online.
	provider := NewProvider(NewInmemTransport(keypers[:tt-1]))
	ct, _ := threshold.Encrypt(eon, []byte("secret"), rand.Reader)
	if shares := provider.Shares(ct, tt); shares != nil {
		t.Fatalf("got %d shares with too few keypers, want none", len(shares))
	}
}

// TestHTTPNetworkEndToEnd runs each keyper behind its own HTTP server and collects
// shares over the network, exactly as independent keyper processes would.
func TestHTTPNetworkEndToEnd(t *testing.T) {
	const tt, n = 3, 5
	keypers, eon, _, err := Bootstrap(tt, n, rand.Reader)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	endpoints := make([]KeyperEndpoint, n)
	for i, k := range keypers {
		srv := httptest.NewServer(k.ServeMux())
		defer srv.Close()
		endpoints[i] = KeyperEndpoint{URL: srv.URL, VK: k.VerificationKey()}
	}
	provider := NewProvider(NewHTTPTransport(endpoints, 2*time.Second, ""))

	msg := []byte("recovered over HTTP from the keyper network")
	if got := roundTrip(t, eon, provider, tt, msg); !bytes.Equal(got, msg) {
		t.Fatalf("got %q, want %q", got, msg)
	}
}

// TestHTTPNetworkToleratesDownKeypers checks share collection still reaches the
// threshold when some keyper endpoints are unreachable, but fails closed when too
// many are down.
func TestHTTPNetworkToleratesDownKeypers(t *testing.T) {
	const tt, n = 3, 5
	keypers, eon, _, err := Bootstrap(tt, n, rand.Reader)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	endpoints := make([]KeyperEndpoint, 0, n)
	live := 0
	for i, k := range keypers {
		if i < 3 { // only 3 of 5 keypers are up
			srv := httptest.NewServer(k.ServeMux())
			defer srv.Close()
			endpoints = append(endpoints, KeyperEndpoint{URL: srv.URL, VK: k.VerificationKey()})
			live++
		} else {
			// Unreachable endpoint.
			endpoints = append(endpoints, KeyperEndpoint{URL: "http://127.0.0.1:1", VK: k.VerificationKey()})
		}
	}
	provider := NewProvider(NewHTTPTransport(endpoints, 500*time.Millisecond, ""))

	msg := []byte("threshold met despite down keypers")
	if got := roundTrip(t, eon, provider, tt, msg); !bytes.Equal(got, msg) {
		t.Fatalf("got %q, want %q", got, msg)
	}
}

// TestRejectsForgedShare checks the transport rejects a share that does not verify
// against the keyper's verification key (a dishonest keyper), so a forged share is
// excluded while honest keypers still meet the threshold.
func TestRejectsForgedShare(t *testing.T) {
	const tt, n = 2, 3
	keypers, eon, _, err := Bootstrap(tt, n, rand.Reader)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	// A keyper from an unrelated committee, re-labelled with index 2: its shares are
	// well-formed but do not verify against this committee's verification key.
	_, foreignShares, foreignVKs, err := threshold.DealerSetup(tt, n, rand.Reader)
	if err != nil {
		t.Fatalf("foreign committee: %v", err)
	}
	forgedKeyper := NewKeyper(
		&threshold.KeyShare{Index: keypers[1].Index(), Secret: foreignShares[1].Secret},
		&threshold.VerificationKey{Index: keypers[1].Index(), Point: foreignVKs[1].Point},
	)

	honest0 := httptest.NewServer(keypers[0].ServeMux())
	defer honest0.Close()
	forged := httptest.NewServer(forgedKeyper.ServeMux())
	defer forged.Close()
	honest2 := httptest.NewServer(keypers[2].ServeMux())
	defer honest2.Close()

	endpoints := []KeyperEndpoint{
		{URL: honest0.URL, VK: keypers[0].VerificationKey()},
		{URL: forged.URL, VK: keypers[1].VerificationKey()}, // forged shares fail this VK
		{URL: honest2.URL, VK: keypers[2].VerificationKey()},
	}
	provider := NewProvider(NewHTTPTransport(endpoints, time.Second, ""))

	// Honest keypers 0 and 2 meet the threshold of 2; the forged share is excluded.
	msg := []byte("forged share excluded, honest threshold still met")
	if got := roundTrip(t, eon, provider, tt, msg); !bytes.Equal(got, msg) {
		t.Fatalf("got %q, want %q", got, msg)
	}

	// A transport over only the forged endpoint must yield no usable share.
	forgedOnly := NewProvider(NewHTTPTransport([]KeyperEndpoint{
		{URL: forged.URL, VK: keypers[1].VerificationKey()},
	}, time.Second, ""))
	ct, _ := threshold.Encrypt(eon, msg, rand.Reader)
	if shares := forgedOnly.Shares(ct, 1); shares != nil {
		t.Fatal("forged share passed verification")
	}
}

// TestServerAuthAndTrigger checks the keyper Server enforces the authorization
// token and the enable trigger, so shares are not released to arbitrary parties or
// before the keyper is enabled.
func TestServerAuthAndTrigger(t *testing.T) {
	const tt, n = 2, 3
	keypers, eon, _, err := Bootstrap(tt, n, rand.Reader)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	const token = "s3cr3t-proposer-token"

	servers := make([]*Server, n)
	endpoints := make([]KeyperEndpoint, n)
	for i, k := range keypers {
		servers[i] = NewServer(k, token)
		srv := httptest.NewServer(servers[i].Handler())
		defer srv.Close()
		endpoints[i] = KeyperEndpoint{URL: srv.URL, VK: k.VerificationKey()}
	}

	ct, _ := threshold.Encrypt(eon, []byte("trigger me"), rand.Reader)

	// Disabled keypers (trigger off): no shares even with the right token.
	authed := NewProvider(NewHTTPTransport(endpoints, time.Second, token))
	if shares := authed.Shares(ct, tt); shares != nil {
		t.Fatal("disabled keypers released shares")
	}

	// Enable release.
	for _, s := range servers {
		s.SetEnabled(true)
	}

	// Wrong/empty token: rejected even though enabled.
	noAuth := NewProvider(NewHTTPTransport(endpoints, time.Second, "wrong-token"))
	if shares := noAuth.Shares(ct, tt); shares != nil {
		t.Fatal("keypers released shares to an unauthorized requester")
	}

	// Correct token and enabled: shares released.
	got := authed.Shares(ct, tt)
	if len(got) < tt {
		t.Fatalf("authorized+enabled request got %d shares, want >= %d", len(got), tt)
	}
	plain, err := threshold.Combine(tt, ct, got)
	if err != nil || string(plain) != "trigger me" {
		t.Fatalf("combine after authorized release failed: %v", err)
	}
}
