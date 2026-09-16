// SPDX-License-Identifier: MPL-2.0

package api

import (
	"net/url"
	"path"
	"strings"
)

// safeLoginReturnPath accepts only bounded local UI destinations. The result is
// retained in the one-use server-side pre-login entry, alongside state, nonce
// and PKCE; callback query parameters cannot replace it. Invalid input leaves
// the deployment's existing post-login destination in control.
func safeLoginReturnPath(raw string) string {
	if raw == "" || len(raw) > 4096 || !strings.HasPrefix(raw, "/") {
		return ""
	}
	decoded, err := url.PathUnescape(raw)
	if err != nil || strings.ContainsFunc(decoded, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.IsAbs() || u.Host != "" || u.Opaque != "" || !strings.HasPrefix(u.Path, "/") || strings.HasPrefix(u.Path, "//") || strings.Contains(u.Path, "\\") {
		return ""
	}
	normalized := strings.ToLower(path.Clean(u.Path))
	if normalized == "/login" || normalized == "/auth" || strings.HasPrefix(normalized, "/auth/") {
		return ""
	}
	return u.String()
}
