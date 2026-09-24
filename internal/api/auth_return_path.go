// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"net/http"
	"net/url"
	"path"
	"strings"
)

// safeLoginReturnPath accepts only bounded local UI destinations. The result is
// bound to the login attempt; callback query parameters cannot replace it.
// OIDC retains it server-side; SAML authenticates its browser context. Invalid input leaves
// the deployment's existing post-login destination in control.
func safeLoginReturnPath(raw string) string {
	u := localLoginReturnURL(raw)
	if u == nil {
		return ""
	}
	return u.String()
}

func localLoginReturnURL(raw string) *url.URL {
	if raw == "" || len(raw) > 4096 || !strings.HasPrefix(raw, "/") {
		return nil
	}
	decoded, err := url.PathUnescape(raw)
	if err != nil || strings.ContainsFunc(decoded, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.IsAbs() || u.Host != "" || u.Opaque != "" || !strings.HasPrefix(u.Path, "/") || strings.HasPrefix(u.Path, "//") || strings.Contains(u.Path, "\\") {
		return nil
	}
	normalized := strings.ToLower(path.Clean(u.Path))
	if normalized == "/login" || normalized == "/auth" || strings.HasPrefix(normalized, "/auth/") {
		return nil
	}
	return u
}

// redirectLoginReturn constructs and sends a local redirect in one boundary.
// Escape each data component at the sink; never turn decoded data into URL syntax.
func redirectLoginReturn(w http.ResponseWriter, r *http.Request, raw string) bool {
	u := localLoginReturnURL(raw)
	if u == nil {
		return false
	}
	// Build only a local path from escaped components. Validation rejects unsafe
	// inputs; construction also prevents any component becoming a scheme, host,
	// separator or header. Keep query order, repeated keys and bare parameters.
	result := "/"
	for i, segment := range strings.Split(strings.TrimPrefix(u.EscapedPath(), "/"), "/") {
		value, err := url.PathUnescape(segment)
		if err != nil {
			return false
		}
		if i > 0 {
			result += "/"
		}
		result += url.PathEscape(value)
	}
	if u.RawQuery != "" || u.ForceQuery {
		result += "?"
		for i, field := range strings.Split(u.RawQuery, "&") {
			key, value, hasValue := strings.Cut(field, "=")
			decodedKey, err := url.QueryUnescape(key)
			if err != nil {
				return false
			}
			decodedValue, err := url.QueryUnescape(value)
			if err != nil {
				return false
			}
			if i > 0 {
				result += "&"
			}
			result += strings.ReplaceAll(url.QueryEscape(decodedKey), "+", "%20")
			if hasValue {
				result += "=" + strings.ReplaceAll(url.QueryEscape(decodedValue), "+", "%20")
			}
		}
	}
	if u.Fragment != "" {
		result += "#" + strings.ReplaceAll(url.QueryEscape(u.Fragment), "+", "%20")
	}
	http.Redirect(w, r, result, http.StatusFound)
	return true
}
