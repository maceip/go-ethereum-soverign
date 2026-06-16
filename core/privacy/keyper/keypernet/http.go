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
	"crypto/subtle"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/core/privacy/threshold"
)

// SharePath is the HTTP endpoint a keyper serves its decryption shares on. The
// request body is a marshalled threshold.Ciphertext; the response body is a
// marshalled threshold.DecryptionShare.
const SharePath = "/keyper/decryption-share"

// AuthHeader is the HTTP header carrying the shared-secret authorization token a
// requester must present to a keyper.
const AuthHeader = "X-Keyper-Auth"

// maxShareRequestSize bounds an inbound ciphertext request.
const maxShareRequestSize = 1 << 20

// Server exposes a keyper's decryption-share endpoint over HTTP with two release
// controls that together stop arbitrary parties from decrypting the encrypted
// mempool at will:
//
//   - authorization: a requester must present the shared-secret token (so only the
//     block proposers the keyper serves can request shares); and
//   - a trigger: the operator must enable release, and can pause it, so a keyper
//     does not serve shares outside legitimate block production.
//
// These are operational controls appropriate to this fork's threshold-ElGamal
// scheme, in which a decryption share does not by itself bind to an epoch. Binding
// decryption to a per-epoch key so that ciphertexts are cryptographically
// undecryptable before their epoch (Boneh-Franklin-style threshold IBE) is the
// stronger design and is tracked as a follow-up; until then these controls are what
// prevent out-of-band decryption.
type Server struct {
	keyper    *Keyper
	authToken string
	enabled   atomic.Bool
}

// NewServer wraps a keyper for HTTP serving. authToken is the shared secret a
// requester must present; an empty token disables the auth check (devnet only).
// The server starts disabled; call SetEnabled(true) once the keyper is ready to
// release shares.
func NewServer(k *Keyper, authToken string) *Server {
	return &Server{keyper: k, authToken: authToken}
}

// SetEnabled turns share release on or off (the operator trigger).
func (s *Server) SetEnabled(enabled bool) { s.enabled.Store(enabled) }

// Enabled reports whether the server is currently releasing shares.
func (s *Server) Enabled() bool { return s.enabled.Load() }

// authorized reports whether the request carries the required auth token.
func (s *Server) authorized(r *http.Request) bool {
	if s.authToken == "" {
		return true
	}
	got := r.Header.Get(AuthHeader)
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.authToken)) == 1
}

// Handler returns the http.Handler serving the keyper's shares, subject to the
// authorization and trigger controls.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(SharePath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		if !s.authorized(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !s.enabled.Load() {
			http.Error(w, "share release disabled", http.StatusServiceUnavailable)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxShareRequestSize))
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
		ct, err := threshold.UnmarshalCiphertext(body)
		if err != nil {
			http.Error(w, "bad ciphertext", http.StatusBadRequest)
			return
		}
		share, err := s.keyper.DecryptionShare(ct).Marshal()
		if err != nil {
			http.Error(w, "share error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(share)
	})
	return mux
}

// ServeMux returns an open, always-enabled handler for the keyper's shares. It is a
// convenience for tests and single-operator devnets; production keypers use Server
// for authorization and trigger control.
func (k *Keyper) ServeMux() http.Handler {
	s := NewServer(k, "")
	s.SetEnabled(true)
	return s.Handler()
}

// KeyperEndpoint is a networked keyper: its share-serving base URL and its public
// verification key (used to verify the shares it returns).
type KeyperEndpoint struct {
	URL string
	VK  *threshold.VerificationKey
}

// HTTPTransport collects decryption shares from independently-run keyper processes
// over HTTP, verifying each share against the keyper's verification key.
type HTTPTransport struct {
	endpoints []KeyperEndpoint
	client    *http.Client
	vks       map[uint32]*threshold.VerificationKey
	authToken string
}

// NewHTTPTransport builds a transport over the given keyper endpoints. authToken is
// the shared secret presented to each keyper (empty for open devnet keypers).
func NewHTTPTransport(endpoints []KeyperEndpoint, timeout time.Duration, authToken string) *HTTPTransport {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	vks := make(map[uint32]*threshold.VerificationKey, len(endpoints))
	for _, e := range endpoints {
		if e.VK != nil {
			vks[e.VK.Index] = e.VK
		}
	}
	return &HTTPTransport{
		endpoints: endpoints,
		client:    &http.Client{Timeout: timeout},
		vks:       vks,
		authToken: authToken,
	}
}

// Collect requests decryption shares from each keyper endpoint until it has a
// threshold of verified shares.
func (t *HTTPTransport) Collect(ct *threshold.Ciphertext, need int) ([]*threshold.DecryptionShare, error) {
	body, err := ct.Marshal()
	if err != nil {
		return nil, err
	}
	shares := make([]*threshold.DecryptionShare, 0, len(t.endpoints))
	for _, e := range t.endpoints {
		share, err := t.fetch(e.URL, body)
		if err != nil {
			continue // skip unreachable/erroring keypers; fallback handles shortfall
		}
		shares = append(shares, share)
	}
	verified := verify(t.vks, ct, shares, need)
	if len(verified) < need {
		return nil, ErrInsufficientShares
	}
	return verified, nil
}

func (t *HTTPTransport) fetch(baseURL string, body []byte) (*threshold.DecryptionShare, error) {
	req, err := http.NewRequest(http.MethodPost, baseURL+SharePath, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if t.authToken != "" {
		req.Header.Set(AuthHeader, t.authToken)
	}
	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("keyper returned status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxShareRequestSize))
	if err != nil {
		return nil, err
	}
	return threshold.UnmarshalDecryptionShare(raw)
}
