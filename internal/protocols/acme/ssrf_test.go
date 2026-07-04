// SPDX-License-Identifier: MPL-2.0

package acme

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestBlockedIPClassification pins the SSRF denylist (SEC-006): loopback,
// link-local incl. the 169.254.169.254 cloud-metadata address, private RFC-1918,
// carrier-grade NAT, IPv6 unique-local, the IPv6 metadata alias, and the
// unspecified address are blocked; ordinary public addresses are allowed.
func TestBlockedIPClassification(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "127.0.0.53", "::1",
		"169.254.169.254", // the canonical cloud metadata service
		"169.254.1.1", "fe80::1",
		"10.0.0.5", "172.16.0.1", "192.168.1.1",
		"100.64.0.1", // CGNAT (RFC 6598)
		"fc00::1", "fd00:ec2::254",
		"0.0.0.0", "::",
	}
	for _, s := range blocked {
		if !blockedIP(net.ParseIP(s)) {
			t.Errorf("blockedIP(%s) = false, want true (must be blocked)", s)
		}
	}
	allowed := []string{"1.1.1.1", "8.8.8.8", "203.0.113.10", "2606:4700:4700::1111"}
	for _, s := range allowed {
		if blockedIP(net.ParseIP(s)) {
			t.Errorf("blockedIP(%s) = true, want false (a public address must be allowed)", s)
		}
	}
	// An unparseable/nil address fails closed.
	if !blockedIP(nil) {
		t.Error("blockedIP(nil) = false, want true (fail closed)")
	}
}

// TestHTTP01SSRFBlocksMetadataAndLoopback is the SEC-006 acceptance: the default
// (guarded) HTTP-01 validator refuses to fetch a challenge from the cloud
// metadata address and from loopback, failing closed with the SSRF error. It
// fails on the pre-fix tree (the validator dialed any address) and passes with
// the guard.
func TestHTTP01SSRFBlocksMetadataAndLoopback(t *testing.T) {
	v := HTTP01Validator{} // default => SSRF-guarded
	for _, target := range []string{
		"169.254.169.254", // metadata service
		"169.254.169.254:80",
		"127.0.0.1:80",
		"[::1]:80",
		"10.1.2.3",
	} {
		err := v.Validate(context.Background(), ChallengeHTTP01, target, "tok", "tok.thumb")
		if err == nil {
			t.Errorf("HTTP-01 fetch to %s was allowed; SSRF guard must block it", target)
			continue
		}
		if !errors.Is(err, ErrSSRFBlocked) {
			t.Errorf("HTTP-01 fetch to %s failed with %v; want an SSRF-blocked error", target, err)
		}
	}
}

// TestHTTP01SSRFBlocksRebindViaResolvedIP proves the guard validates the RESOLVED
// address, not the textual host: a hostname is rejected when it resolves to a
// blocked IP. We use a name we resolve to 127.0.0.1 implicitly via the literal
// loopback host "localhost", which DNS resolves to a loopback address — so the
// dial Control (which sees the resolved IP) must reject it.
func TestHTTP01SSRFBlocksRebindViaResolvedIP(t *testing.T) {
	v := HTTP01Validator{} // guarded
	err := v.Validate(context.Background(), ChallengeHTTP01, "localhost", "tok", "tok.thumb")
	if err == nil {
		t.Fatal("HTTP-01 fetch to localhost (resolves to loopback) was allowed; the guard must reject the resolved IP")
	}
	if !errors.Is(err, ErrSSRFBlocked) {
		t.Fatalf("localhost fetch failed with %v; want SSRF-blocked (resolved-IP check)", err)
	}
}

// TestHTTP01AllowPrivateTargetsReachesLoopback confirms the test-only escape hatch
// still works: with AllowPrivateTargets the default client reaches a loopback
// server, so legitimate loopback conformance tests are unaffected by the guard.
func TestHTTP01AllowPrivateTargetsReachesLoopback(t *testing.T) {
	const token, keyAuth = "tok-xyz", "tok-xyz.thumb"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/acme-challenge/"+token {
			_, _ = w.Write([]byte(keyAuth))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(ts.Close)
	domain := strings.TrimPrefix(ts.URL, "http://")

	v := HTTP01Validator{AllowPrivateTargets: true}
	if err := v.Validate(context.Background(), ChallengeHTTP01, domain, token, keyAuth); err != nil {
		t.Errorf("AllowPrivateTargets validator could not reach loopback: %v", err)
	}
}

// TestSSRFRedirectSchemeRejected: the guarded client refuses a redirect to a
// non-http(s) scheme (e.g. file://), closing a redirect-based SSRF bypass.
func TestSSRFRedirectSchemeRejected(t *testing.T) {
	c := ssrfSafeClient(0)
	// Drive the CheckRedirect directly with a file:// target.
	req := httptest.NewRequest(http.MethodGet, "file:///etc/passwd", nil)
	if err := c.CheckRedirect(req, nil); err == nil {
		t.Error("redirect to file:// was permitted; non-http(s) redirects must be refused")
	}
}
