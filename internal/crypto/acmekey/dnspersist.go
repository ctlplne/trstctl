// SPDX-License-Identifier: BUSL-1.1

package acmekey

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"sync"
)

// dns-persist-01 on the upstream client (P1). The authority's challenge
// object names the issuer domain names a standing record may use
// ("issuer-domain-names"); golang.org/x/crypto/acme drops fields it does not
// know, so the driver reads them from the authority's own responses as they
// pass through its HTTP client. The solver then publishes
// "<issuer-domain-name>; accounturi=<this account>" once and never retracts
// it: later orders reuse it with no DNS change.

// ChallengeDNSPersist01 is the persistent DNS validation challenge.
const ChallengeDNSPersist01 = "dns-persist-01"

// maxCapturedBody bounds the authority response the capture parses; larger
// bodies pass through unread.
const maxCapturedBody = 1 << 20

// persistCapture records, per challenge URL, the issuer domain names an
// authority named for dns-persist-01.
type persistCapture struct {
	base  http.RoundTripper
	mu    sync.Mutex
	names map[string][]string
}

// wrap returns a copy of hc whose transport records the names. Without a
// client there is nothing to wrap, and dns-persist-01 then fails closed for
// want of issuer names.
func (c *persistCapture) wrap(hc *http.Client) *http.Client {
	if hc == nil {
		return nil
	}
	wrapped := *hc
	c.base = wrapped.Transport
	wrapped.Transport = c
	return &wrapped
}

// RoundTrip passes the request through and reads the issuer domain names
// from a JSON response, leaving the body intact for the ACME client.
func (c *persistCapture) RoundTrip(req *http.Request) (*http.Response, error) {
	base := c.base
	if base == nil {
		base = http.DefaultTransport
	}
	resp, err := base.RoundTrip(req)
	if err != nil || resp.StatusCode != http.StatusOK || resp.Body == nil {
		return resp, err
	}
	if mediaType, _, perr := mime.ParseMediaType(resp.Header.Get("Content-Type")); perr != nil || mediaType != "application/json" {
		return resp, nil
	}
	original := resp.Body
	prefix, rerr := io.ReadAll(io.LimitReader(original, maxCapturedBody+1))
	if rerr != nil {
		_ = original.Close()
		return nil, rerr
	}
	resp.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(prefix), original), original}
	if len(prefix) <= maxCapturedBody {
		c.record(prefix)
	}
	return resp, nil
}

type persistChallenge struct {
	Type              string   `json:"type"`
	URL               string   `json:"url"`
	IssuerDomainNames []string `json:"issuer-domain-names"`
}

func (c *persistCapture) record(body []byte) {
	var doc struct {
		persistChallenge
		Challenges []persistChallenge `json:"challenges"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, ch := range append(doc.Challenges, doc.persistChallenge) {
		if ch.Type == ChallengeDNSPersist01 && ch.URL != "" && len(ch.IssuerDomainNames) > 0 {
			c.names[ch.URL] = append([]string(nil), ch.IssuerDomainNames...)
		}
	}
}

// issuerDomainNames returns what the authority named for a challenge.
func (c *persistCapture) issuerDomainNames(challengeURL string) []string {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.names[challengeURL]...)
}
