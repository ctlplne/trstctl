// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"errors"
	"net/url"
	"strings"
)

var errInvalidURIPrefix = errors.New("URI prefix requires a scheme, host, no userinfo, query or fragment, and a canonical path")

// ValidateURIPrefix checks an author-supplied URI SAN policy before it is saved.
// A prefix identifies one authority and zero or more complete path segments.
func ValidateURIPrefix(prefix string) error {
	_, err := parseConstrainedURI(strings.TrimSpace(prefix))
	if err != nil {
		return errInvalidURIPrefix
	}
	return nil
}

// URIPrefixPermitted is shared by profile preview and the final signer guard.
// It compares the parsed authority, then complete escaped path segments. A
// textual prefix must not cross from /ns/prod into /ns/production or from one
// host into userinfo or another host.
func URIPrefixPermitted(raw string, prefixes []string) bool {
	requested, err := parseConstrainedURI(raw)
	if err != nil {
		return false
	}
	for _, prefix := range prefixes {
		allowed, err := parseConstrainedURI(strings.TrimSpace(prefix))
		if err != nil || !strings.EqualFold(requested.Scheme, allowed.Scheme) ||
			!strings.EqualFold(requested.Hostname(), allowed.Hostname()) || requested.Port() != allowed.Port() {
			continue
		}
		want, got := allowed.EscapedPath(), requested.EscapedPath()
		if want == "" || got == want || strings.HasSuffix(want, "/") && strings.HasPrefix(got, want) ||
			strings.HasPrefix(got, want+"/") {
			return true
		}
	}
	return false
}

func parseConstrainedURI(raw string) (*url.URL, error) {
	if raw == "" || strings.Contains(raw, "#") {
		return nil, errInvalidURIPrefix
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || u.Hostname() == "" || u.Opaque != "" ||
		u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, errInvalidURIPrefix
	}
	for _, segment := range strings.Split(u.EscapedPath(), "/") {
		decoded, err := url.PathUnescape(segment)
		if err != nil || decoded == "." || decoded == ".." || strings.ContainsAny(decoded, "/\\\x00") {
			return nil, errInvalidURIPrefix
		}
	}
	return u, nil
}
