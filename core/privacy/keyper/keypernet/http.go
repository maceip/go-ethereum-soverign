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
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/core/privacy/threshold"
)

// SharePath is the HTTP endpoint a keyper serves its decryption shares on. The
// request body is a marshalled threshold.Ciphertext; the response body is a
// marshalled threshold.DecryptionShare.
const SharePath = "/keyper/decryption-share"

// maxShareRequestSize bounds an inbound ciphertext request.
const maxShareRequestSize = 1 << 20

// ServeMux returns an http.Handler that serves the keyper's decryption shares.
// A keyper process mounts this on its HTTP server.
func (k *Keyper) ServeMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(SharePath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
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
		share, err := k.DecryptionShare(ct).Marshal()
		if err != nil {
			http.Error(w, "share error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(share)
	})
	return mux
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
}

// NewHTTPTransport builds a transport over the given keyper endpoints.
func NewHTTPTransport(endpoints []KeyperEndpoint, timeout time.Duration) *HTTPTransport {
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
	resp, err := t.client.Post(baseURL+SharePath, "application/octet-stream", bytes.NewReader(body))
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
