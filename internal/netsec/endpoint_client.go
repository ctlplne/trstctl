// SPDX-License-Identifier: BUSL-1.1

package netsec

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

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
