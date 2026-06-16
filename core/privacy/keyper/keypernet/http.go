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
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/core/privacy/ibe"
)

// EpochSharePath is the HTTP endpoint a keyper serves epoch-key shares on. The
// request body is the 8-byte big-endian epoch; the response body is a marshalled
// ibe.EpochKeyShare.
const EpochSharePath = "/keyper/epoch-key-share"

// AuthHeader is the HTTP header carrying the shared-secret authorization token a
// requester must present to a keyper.
const AuthHeader = "X-Keyper-Auth"

const maxShareRequestSize = 1 << 20

// Server exposes a keyper's epoch-key-share endpoint over HTTP with three release
// controls that, together with the cryptographic per-epoch binding, stop arbitrary
// parties from decrypting the encrypted mempool:
//
//   - authorization: a requester must present the shared-secret token;
//   - an enable trigger: the operator must enable release and can pause it; and
//   - an epoch trigger: a keyper releases a share for epoch E only when E is at or
//     below the current trigger epoch (advanced as blocks/epochs become due).
//
// Even without these controls a future epoch's transactions are cryptographically
// undecryptable (the epoch key does not yet exist); the controls additionally stop
// a keyper from being induced to release a current epoch's key out of band.
type Server struct {
	keyper    *Keyper
	authToken string
	enabled   atomic.Bool
	trigger   atomic.Uint64
}

// NewServer wraps a keyper for HTTP serving. authToken is the shared secret a
// requester must present (empty disables the check; devnet only). The server starts
// disabled with trigger epoch 0; call SetEnabled and SetTriggerEpoch as the node
// becomes ready and epochs become due.
func NewServer(k *Keyper, authToken string) *Server {
	return &Server{keyper: k, authToken: authToken}
}

// SetEnabled turns epoch-key-share release on or off.
func (s *Server) SetEnabled(enabled bool) { s.enabled.Store(enabled) }

// Enabled reports whether release is currently on.
func (s *Server) Enabled() bool { return s.enabled.Load() }

// SetTriggerEpoch advances the highest epoch for which shares may be released.
func (s *Server) SetTriggerEpoch(epoch uint64) { s.trigger.Store(epoch) }

// TriggerEpoch returns the current trigger epoch.
func (s *Server) TriggerEpoch() uint64 { return s.trigger.Load() }

func (s *Server) authorized(r *http.Request) bool {
	if s.authToken == "" {
		return true
	}
	return subtleConstantTimeEqual(r.Header.Get(AuthHeader), s.authToken)
}

// Handler returns the http.Handler serving the keyper's epoch-key shares subject to
// the authorization, enable, and epoch-trigger controls.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(EpochSharePath, func(w http.ResponseWriter, r *http.Request) {
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
		if err != nil || len(body) < 8 {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		epoch := binary.BigEndian.Uint64(body[:8])
		if epoch > s.trigger.Load() {
			http.Error(w, "epoch not yet triggered", http.StatusServiceUnavailable)
			return
		}
		share, err := s.keyper.EpochShare(epoch)
		if err != nil {
			http.Error(w, "share error", http.StatusInternalServerError)
			return
		}
		raw, err := share.Marshal()
		if err != nil {
			http.Error(w, "encode error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(raw)
	})
	return mux
}

// ServeMux returns an open, always-enabled handler with the trigger raised to the
// maximum, for tests and single-operator devnets. Production keypers use Server.
func (k *Keyper) ServeMux() http.Handler {
	s := NewServer(k, "")
	s.SetEnabled(true)
	s.SetTriggerEpoch(^uint64(0))
	return s.Handler()
}

// HTTPTransport collects epoch-key shares from independently-run keyper processes
// over HTTP. Share verification is done by the Provider against committee
// verification keys.
type HTTPTransport struct {
	urls      []string
	client    *http.Client
	authToken string
}

// NewHTTPTransport builds a transport over the given keyper base URLs. authToken is
// the shared secret presented to each keyper (empty for open devnet keypers).
func NewHTTPTransport(urls []string, timeout time.Duration, authToken string) *HTTPTransport {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &HTTPTransport{
		urls:      urls,
		client:    &http.Client{Timeout: timeout},
		authToken: authToken,
	}
}

// Collect requests an epoch-key share from each keyper endpoint.
func (t *HTTPTransport) Collect(epoch uint64) []*ibe.EpochKeyShare {
	var body [8]byte
	binary.BigEndian.PutUint64(body[:], epoch)
	shares := make([]*ibe.EpochKeyShare, 0, len(t.urls))
	for _, url := range t.urls {
		share, err := t.fetch(url, body[:])
		if err != nil {
			continue // unreachable/disabled/not-triggered keyper; provider handles shortfall
		}
		shares = append(shares, share)
	}
	return shares
}

func (t *HTTPTransport) fetch(baseURL string, body []byte) (*ibe.EpochKeyShare, error) {
	req, err := http.NewRequest(http.MethodPost, baseURL+EpochSharePath, bytes.NewReader(body))
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
	return ibe.UnmarshalEpochKeyShare(raw)
}

// subtleConstantTimeEqual compares two strings in constant time.
func subtleConstantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
