// SPDX-License-Identifier: MPL-2.0

package netsec

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// BindTransportToOrigin wraps next so every request must use the exact
// scheme+host configured by the operator. Redirect checks alone are not enough:
// protocols such as ACME read fresh request URLs from a directory document, so
// those requests have no redirect chain to inspect. The wrapper runs before next
// and therefore refuses an origin escape before DNS, dialing, or credential I/O.
func BindTransportToOrigin(endpoint string, next http.RoundTripper) (http.RoundTripper, error) {
	origin, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || origin == nil || origin.Host == "" || origin.Hostname() == "" ||
		(!strings.EqualFold(origin.Scheme, "https") && !strings.EqualFold(origin.Scheme, "http")) {
		return nil, fmt.Errorf("%w: origin binding requires an absolute HTTP(S) endpoint", ErrSSRFBlocked)
	}
	if origin.User != nil {
		return nil, fmt.Errorf("%w: origin binding endpoint must not contain userinfo", ErrSSRFBlocked)
	}
	if next == nil {
		next = http.DefaultTransport
	}
	return &originBoundTransport{scheme: origin.Scheme, host: origin.Host, next: next}, nil
}

type originBoundTransport struct {
	scheme string
	host   string
	next   http.RoundTripper
}

func (t *originBoundTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil || req.URL == nil || req.URL.User != nil || req.URL.Host == "" ||
		!strings.EqualFold(req.URL.Scheme, t.scheme) || !strings.EqualFold(req.URL.Host, t.host) {
		return nil, fmt.Errorf("%w: outbound request escaped configured origin", ErrSSRFBlocked)
	}
	return t.next.RoundTrip(req)
}

func (t *originBoundTransport) CloseIdleConnections() {
	if closer, ok := t.next.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}
