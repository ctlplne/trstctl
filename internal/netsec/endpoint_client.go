// SPDX-License-Identifier: BUSL-1.1

package netsec

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/crypto/trust"
)

// HardenedDefaultTransport is the process default transport, cloned, with the
// runtime distrust list installed: the builder for an operator-configured
// endpoint that may legitimately be private (an identity provider, a
// Kubernetes API server, a collector, a model server) and so cannot take the
// SSRF guard, but must never trust a distrusted chain (eMudhra, Part 2).
func HardenedDefaultTransport() *http.Transport {
	return trust.HardenTransport(http.DefaultTransport.(*http.Transport).Clone())
}

var hardenProcessDefaultsOnce sync.Once

// HardenProcessDefaults installs the runtime distrust check on the process's
// http.DefaultTransport, once, so third-party code that uses the default client
// (an SDK that builds no client of its own, a library helper) is covered as
// well. Every trstctl binary calls it first thing in main.
func HardenProcessDefaults() {
	hardenProcessDefaultsOnce.Do(func() {
		if t, ok := http.DefaultTransport.(*http.Transport); ok {
			trust.HardenTransport(t)
		}
	})
}

// HardenedClient is an http.Client over HardenedDefaultTransport.
func HardenedClient(timeout time.Duration) *http.Client {
	return &http.Client{Transport: HardenedDefaultTransport(), Timeout: timeout}
}

// ClientFor wraps a transport a caller built through a reviewed path (an
// mTLS or CA-pinned transport from the crypto boundary, a guarded or
// origin-bound round tripper) in an http.Client, so the caller does not
// construct the client ambiently. A plain *http.Transport is hardened with the
// runtime distrust list; a pinned transport keeps its own verification and
// gets the check as well. checkRedirect may be nil.
func ClientFor(transport http.RoundTripper, timeout time.Duration, checkRedirect func(*http.Request, []*http.Request) error) *http.Client {
	if transport == nil {
		transport = HardenedDefaultTransport()
	}
	if t, ok := transport.(*http.Transport); ok {
		transport = trust.HardenTransport(t)
	}
	return &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: checkRedirect}
}

// OutboundClientForEndpoint returns the client an operator-configured
// endpoint may be dialed with: SafeClient for an absolute https URL, the
// loopback-only client for a plain-http loopback URL (local fixtures and labs),
// and an error for anything else. It is the one rule behind every "http is
// allowed only for a loopback host" configuration check, so the client used
// at runtime cannot be looser than the check that admitted the URL.
func OutboundClientForEndpoint(endpoint string, timeout time.Duration) (*http.Client, error) {
	u, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("netsec: endpoint %q must be an absolute URL", endpoint)
	}
	switch {
	case strings.EqualFold(u.Scheme, "https"):
		return SafeClient(timeout), nil
	case IsInsecureLoopbackHTTPURL(endpoint):
		return InsecureLoopbackClient(timeout), nil
	}
	return nil, fmt.Errorf("netsec: endpoint %q must be an https URL (http is allowed only for a loopback host)", endpoint)
}
