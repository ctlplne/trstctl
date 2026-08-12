// SPDX-License-Identifier: MPL-2.0

// Package enrollproxy serves ACME, EST and SCEP inside a dark segment (epic A4).
//
// A host or device with no route to the control plane cannot enrol. That is the
// ordinary condition in the segments that matter most — an OT network, a PCI
// zone, a lab behind a one-way firewall — and the usual answer is a per-segment
// exception in somebody's firewall, which is the thing those segments exist to
// avoid.
//
// The relay already has the one outbound pipe those segments allow. This lets a
// stock certbot, sscep or estclient point at the relay and enrol through it.
//
// IT DECIDES NOTHING. That is the whole design and the reason this package is
// small. The relay sits inside the customer's network, which is precisely where
// an attacker who has got a foothold already is — so a proxy that interpreted a
// challenge, cached an authorization, or spoke with its own agent identity would
// be handing that attacker the ability to mint certificates. Every request is
// forwarded as received, and the control plane's validators and policy decide
// exactly as they would for a client that reached them directly.
package enrollproxy

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync/atomic"
	"time"

	"trstctl.com/trstctl/internal/netsec"
)

// proxiedPrefixes are the protocol paths this proxy forwards.
//
// An allowlist, not a catch-all. The relay must not become a general tunnel into
// the control plane's API: a segment that can reach /api/v1 through a relay has
// the control plane's whole administrative surface, which is a different and
// much larger grant than "devices here can enrol".
var proxiedPrefixes = []string{
	"/directory", // ACME directory
	"/acme/",
	"/.well-known/est/",
	"/scep",
	"/cmp",
}

// Proxy forwards enrolment protocol traffic to the control plane.
type Proxy struct {
	upstream  *url.URL
	publicURL *url.URL
	client    *http.Client
	// forwarded counts requests passed upstream, for the agent's heartbeat.
	forwarded atomic.Int64
	// refused counts requests rejected because their path is not a protocol
	// path. Reported separately because a non-zero value means something in the
	// segment is trying to reach the control plane's API through this relay,
	// which an operator should know about.
	refused atomic.Int64
	// lastForwardedUnixNano makes "which relay most recently carried an
	// enrollment request?" evidence, not an inference from a process being up.
	lastForwardedUnixNano atomic.Int64
}

// New builds a proxy forwarding to the control plane at upstream.
func New(upstream string, client *http.Client) (*Proxy, error) {
	return newProxy(upstream, "", client)
}

// NewWithPublicURL builds a proxy whose clients reach one stable HTTPS URL.
//
// The socket still dials upstream. Only the HTTP authority presented to the
// control plane is publicURL. ACME responses contain absolute URLs and ACME
// account IDs are URLs, so without this split a /directory request through a
// relay returns control-plane addresses and a stock client immediately leaves
// the dark-segment path.
func NewWithPublicURL(upstream, publicURL string, client *http.Client) (*Proxy, error) {
	if strings.TrimSpace(publicURL) == "" {
		return nil, errors.New("enrollproxy: public URL is required")
	}
	return newProxy(upstream, publicURL, client)
}

func newProxy(upstream, publicURL string, client *http.Client) (*Proxy, error) {
	u, err := url.Parse(strings.TrimSpace(upstream))
	if err != nil {
		return nil, fmt.Errorf("enrollproxy: parse upstream: %w", err)
	}
	if u.Scheme != "https" {
		// The proxied traffic includes CSRs and, for SCEP, the challenge
		// password. A plaintext hop from the relay to the control plane would
		// put both on the wire inside a network the relay exists because nobody
		// trusts.
		return nil, errors.New("enrollproxy: upstream must be https")
	}
	if u.Host == "" {
		return nil, errors.New("enrollproxy: upstream names no host")
	}
	if u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		// A userinfo component would make net/http synthesize Basic
		// Authorization. That would violate the relay's most important rule:
		// it forwards the enrollment client's credential and adds none of its
		// own. Paths and queries are rejected because the request supplies those
		// components and the configured authority must not silently rewrite them.
		return nil, errors.New("enrollproxy: upstream must be one HTTPS authority with no credentials, path, query, or fragment")
	}
	u.Path = ""
	var public *url.URL
	if strings.TrimSpace(publicURL) != "" {
		public, err = url.Parse(strings.TrimSpace(publicURL))
		if err != nil {
			return nil, fmt.Errorf("enrollproxy: parse public URL: %w", err)
		}
		if public.Scheme != "https" || public.Host == "" || public.User != nil ||
			(public.Path != "" && public.Path != "/") || public.RawQuery != "" || public.Fragment != "" {
			return nil, errors.New("enrollproxy: public URL must be one HTTPS authority with no credentials, path, query, or fragment")
		}
		public.Path = ""
	}
	if client == nil {
		// SSRF-checked, like every other outbound surface in this tree (SEC-005).
		//
		// It matters more here than usual, not less: this proxy forwards
		// attacker-influenced paths from inside a segment nobody trusts, so an
		// ambient client would let a device in that segment steer the relay's
		// outbound connection. The upstream is operator-configured, and the
		// check is what keeps a configuration mistake from becoming a pivot.
		//
		// An on-prem control plane on a private address is the ordinary case
		// for a dark segment, so callers that need it pass their own client
		// built with netsec.SafeClientWithOptions and the operator's explicit
		// CIDR allowance — the same mechanism the rest of the tree uses, rather
		// than a second one invented here.
		client = netsec.SafeClient(60 * time.Second)
	}
	return &Proxy{upstream: u, publicURL: public, client: client}, nil
}

// Proxied reports whether a path is one this proxy forwards.
func Proxied(path string) bool {
	for _, prefix := range proxiedPrefixes {
		if path == prefix || strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// ServeHTTP forwards one enrolment request.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Normalise BEFORE the allowlist check. "/../api/v1/certificates" is a path
	// a Go client happens to resolve on the way out, but relying on that would
	// make the confinement somebody else's property; cleaning here means the
	// string the allowlist sees is the string that gets sent.
	cleanPath := path.Clean(r.URL.Path)
	if !strings.HasPrefix(cleanPath, "/") {
		cleanPath = "/" + cleanPath
	}
	if !Proxied(cleanPath) {
		p.refused.Add(1)
		// A closed refusal. Naming what IS proxied would help somebody probing
		// for a way through, and the operator who configured this already knows.
		http.Error(w, "not an enrolment protocol path", http.StatusNotFound)
		return
	}

	// The scheme and host come from the OPERATOR's configured upstream and are
	// never taken from the request; only the path and query travel, and the path
	// has just been cleaned and allowlisted. So a device in the segment can
	// choose which enrolment endpoint it reaches and cannot choose the host the
	// relay connects to.
	outURL := *p.upstream
	outURL.Path = cleanPath
	outURL.RawQuery = r.URL.RawQuery

	// The body is streamed rather than read: an EST/SCEP payload can be large,
	// and buffering it here would put a client's CSR in the relay's memory for
	// no reason.
	out, err := http.NewRequestWithContext(r.Context(), r.Method, outURL.String(), r.Body)
	if err != nil {
		http.Error(w, "upstream request could not be built", http.StatusBadGateway)
		return
	}
	copyProxiedHeaders(out.Header, r.Header)
	if p.publicURL != nil {
		// Host is deliberately NOT a dial target here. net/http dials out.URL,
		// which still names the operator-configured control plane. Host is the
		// stable relay authority ACME uses to construct absolute response URLs
		// and to name the account/order resources a stock client signs.
		out.Host = p.publicURL.Host
		out.Header.Set("X-Forwarded-Proto", p.publicURL.Scheme)
	} else {
		out.Header.Set("X-Forwarded-Proto", schemeOf(r))
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		// The client's address, so the control plane's audit records who
		// actually enrolled rather than recording every device in a segment as
		// the relay. It is INFORMATIONAL: nothing upstream authorizes on it,
		// because a relay could set it to anything.
		out.Header.Set("X-Forwarded-For", host)
	}

	// #nosec G704 -- the destination host is the operator-configured upstream,
	// never the request's; the only request-derived component is a path that was
	// cleaned and matched against the enrolment allowlist above, and the client
	// is netsec-checked. A device in the segment can choose which enrolment
	// endpoint it reaches and cannot redirect the relay (CWE-918).
	resp, err := p.client.Do(out)
	if err != nil {
		if marker, ok := w.(interface{ markTransportFailure() }); ok {
			// The pool needs an out-of-band fact here. Guessing from HTTP 502
			// would turn a real 502 response from the control plane into a fake
			// transport outage and hide that response from the client.
			marker.markTransportFailure()
			return
		}
		http.Error(w, "the control plane could not be reached", http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if marker, ok := w.(interface{ markUpstreamResponse() }); ok {
		marker.markUpstreamResponse()
	}

	copyProxiedHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
	p.forwarded.Add(1)
	p.lastForwardedUnixNano.Store(time.Now().UTC().UnixNano())
}

// hopByHopHeaders are stripped in both directions per RFC 7230.
var hopByHopHeaders = map[string]bool{
	"connection": true, "keep-alive": true, "proxy-authenticate": true,
	"proxy-authorization": true, "te": true, "trailer": true,
	"transfer-encoding": true, "upgrade": true,
}

// copyProxiedHeaders copies headers, dropping hop-by-hop ones.
//
// It does NOT add an agent credential, and that omission is the load-bearing
// line of this file. The relay holds an mTLS identity the control plane trusts;
// attaching it here would make every device in the segment speak with the
// relay's authority, so a device that should only be able to request its own
// certificate could request any. The proxied client authenticates as itself —
// through EST's TLS client certificate, SCEP's challenge password, or ACME's
// account key — exactly as it would reaching the control plane directly.
func copyProxiedHeaders(dst, src http.Header) {
	for key, values := range src {
		if hopByHopHeaders[strings.ToLower(key)] {
			continue
		}
		for _, v := range values {
			dst.Add(key, v)
		}
	}
}

func schemeOf(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

// Stats reports what this proxy has forwarded and refused.
func (p *Proxy) Stats() (forwarded, refused int64) {
	if p == nil {
		return 0, 0
	}
	return p.forwarded.Load(), p.refused.Load()
}

// LastForwardedAt reports when this process last completed a proxied response.
func (p *Proxy) LastForwardedAt() time.Time {
	if p == nil {
		return time.Time{}
	}
	ns := p.lastForwardedUnixNano.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns).UTC()
}
