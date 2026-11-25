// SPDX-License-Identifier: BUSL-1.1

package accessgateway

import (
	"net/http"
	"net/url"
	"strings"
)

// refuseUntrustedTunnelRequest runs before a local HTTP tunnel attaches the
// session's upstream credential. Browsers can send forms and WebSockets to a
// known loopback port without knowing the session ticket; a rebound DNS name
// can also make the response readable to an attacker's page.
func refuseUntrustedTunnelRequest(w http.ResponseWriter, r *http.Request) bool {
	refuse := func() bool {
		w.Header().Set("Cache-Control", "no-store")
		http.Error(w, "request is outside this local session", http.StatusForbidden)
		return true
	}
	if !consoleLocalHost(r.Host) {
		return refuse()
	}
	localOrigin := "http://" + r.Host
	if values, present := r.Header["Origin"]; present {
		if len(values) != 1 || values[0] != localOrigin {
			return refuse()
		}
	}
	if values, present := r.Header["Sec-Fetch-Site"]; present {
		if len(values) != 1 ||
			(values[0] != "same-origin" &&
				(values[0] != "none" || r.Method != http.MethodGet && r.Method != http.MethodHead)) {
			return refuse()
		}
	}
	// Older browsers can omit Fetch Metadata on a GET, including an AWS
	// query-API mutation. A browser page cannot set User-Agent itself; refuse
	// browser-shaped requests with neither browser origin signal. Stock CLI
	// clients remain usable without browser headers.
	if r.Header.Get("Origin") == "" && r.Header.Get("Sec-Fetch-Site") == "" {
		ua := strings.ToLower(strings.TrimSpace(r.UserAgent()))
		if ua == "" || strings.Contains(ua, "mozilla/") || strings.Contains(ua, "chrome/") ||
			strings.Contains(ua, "safari/") || strings.Contains(ua, "firefox/") {
			return refuse()
		}
	}
	if values, present := r.Header["Referer"]; present {
		if len(values) != 1 {
			return refuse()
		}
		referer, err := url.Parse(values[0])
		if err != nil || referer.Scheme != "http" || referer.Host != r.Host || referer.User != nil ||
			!strings.HasPrefix(values[0], localOrigin+"/") {
			return refuse()
		}
	}
	if r.Header.Get("Sec-Fetch-Mode") == "websocket" && r.Header.Get("Origin") == "" {
		return refuse()
	}
	return false
}
