// SPDX-License-Identifier: BUSL-1.1

package accessgateway

import (
	"net/http"
	"net/url"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
)

type tunnelClientKind uint8

const (
	tunnelBrowser tunnelClientKind = iota
	tunnelKubernetes
	tunnelAWS
	tunnelHTTPHeader
)

const tunnelCookieName = "trstctl_tunnel"
const tunnelKubernetesPrefix = "/.trstctl/"

func localTunnelCapability(ticket string) string { return crypto.LocalTunnelCapability([]byte(ticket)) }

// A local port is reachable by every page in the user's browser. The ticket
// digest is a separate capability: it cannot be used as the gateway preface's
// ticket, and only the CLI session's 0600 client file or bootstrap URL carries
// it. Check it before attaching any upstream credential or evaluating commands.
func refuseUntrustedTunnelRequest(w http.ResponseWriter, r *http.Request, capability string, kind tunnelClientKind) bool {
	refuse := func() bool {
		w.Header().Set("Cache-Control", "no-store")
		http.Error(w, "request is outside this local session", http.StatusForbidden)
		return true
	}
	if !trustedTunnelOrigin(r) || len(capability) != 64 {
		return refuse()
	}
	if kind == tunnelBrowser && browserTunnelBootstrap(w, r, capability) {
		return true
	}
	if kind == tunnelBrowser && r.URL.Query().Has(tunnelCookieName) {
		return refuse()
	}
	if !trustedTunnelCapability(r, capability, kind) {
		return refuse()
	}
	stripTunnelCapability(r, capability, kind)
	return false
}

func trustedTunnelOrigin(r *http.Request) bool {
	if !consoleLocalHost(r.Host) {
		return false
	}
	localOrigin := "http://" + r.Host
	if values, present := r.Header["Origin"]; present && (len(values) != 1 || values[0] != localOrigin) {
		return false
	}
	if values, present := r.Header["Sec-Fetch-Site"]; present {
		if len(values) != 1 ||
			(values[0] != "same-origin" &&
				(values[0] != "none" || r.Method != http.MethodGet && r.Method != http.MethodHead)) {
			return false
		}
	}
	if values, present := r.Header["Referer"]; present {
		if len(values) != 1 {
			return false
		}
		referer, err := url.Parse(values[0])
		if err != nil || referer.Scheme != "http" || referer.Host != r.Host || referer.User != nil ||
			!strings.HasPrefix(values[0], localOrigin+"/") {
			return false
		}
	}
	return r.Header.Get("Sec-Fetch-Mode") != "websocket" || r.Header.Get("Origin") != ""
}

func tunnelCapabilityMatches(got, expected string) bool {
	return len(expected) == 64 && len(got) == len(expected) && crypto.ConstantTimeEqual([]byte(got), []byte(expected))
}

func trustedTunnelCapability(r *http.Request, expected string, kind tunnelClientKind) bool {
	switch kind {
	case tunnelBrowser:
		var got string
		for _, c := range r.Cookies() {
			if c.Name == tunnelCookieName {
				if got != "" {
					return false
				}
				got = c.Value
			}
		}
		return tunnelCapabilityMatches(got, expected)
	case tunnelKubernetes:
		if r.URL.RawPath != "" {
			return false
		}
		prefix := tunnelKubernetesPrefix + expected
		return strings.HasPrefix(r.URL.Path, prefix+"/") || r.URL.Path == prefix
	case tunnelAWS:
		values := r.Header.Values("X-Amz-Security-Token")
		return len(values) == 1 && tunnelCapabilityMatches(values[0], expected)
	case tunnelHTTPHeader:
		values := r.Header.Values("X-Trstctl-Tunnel-Token")
		return len(values) == 1 && tunnelCapabilityMatches(values[0], expected)
	default:
		return false
	}
}

func stripTunnelCapability(r *http.Request, expected string, kind tunnelClientKind) {
	switch kind {
	case tunnelKubernetes:
		r.URL.Path = strings.TrimPrefix(r.URL.Path, tunnelKubernetesPrefix+expected)
		if r.URL.Path == "" {
			r.URL.Path = "/"
		}
		r.URL.RawPath = ""
	case tunnelAWS:
		r.Header.Del("X-Amz-Security-Token")
	case tunnelHTTPHeader:
		r.Header.Del("X-Trstctl-Tunnel-Token")
	}
}

// The operator opens the CLI's capability URL once. A 303 drops its query
// before any console request; the cookie stays on this loopback origin and is
// never forwarded to the upstream console.
func browserTunnelBootstrap(w http.ResponseWriter, r *http.Request, expected string) bool {
	if r.Method != http.MethodGet || r.URL.Path != "/" || r.URL.RawQuery == "" {
		return false
	}
	query := r.URL.Query()
	values := query[tunnelCookieName]
	if len(query) != 1 || len(values) != 1 || !tunnelCapabilityMatches(values[0], expected) {
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.SetCookie(w, &http.Cookie{Name: tunnelCookieName, Value: expected, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode}) // #nosec G124 -- CLI loopback uses plain HTTP, so Secure would prevent the required cookie (CWE-614)
	http.Redirect(w, r, "/", http.StatusSeeOther)
	return true
}
