// SPDX-License-Identifier: MPL-2.0

package netsec_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/netsec"
)

func TestBlockedIPDenylist(t *testing.T) {
	for _, s := range []string{
		"127.0.0.1", "::1", // loopback
		"169.254.169.254", "fe80::1", // link-local incl. cloud metadata
		"10.1.2.3", "192.168.1.1", "172.16.0.1", // RFC-1918
		"100.64.0.1",       // carrier-grade NAT
		"0.0.0.0",          // unspecified
		"224.0.0.1",        // multicast
		"fd00:ec2::254",    // IPv6 metadata alias
		"::ffff:127.0.0.1", // v4-in-v6 loopback
	} {
		if !netsec.BlockedIP(net.ParseIP(s)) {
			t.Errorf("BlockedIP(%s) = false, want true (must be blocked)", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "93.184.216.34"} {
		if netsec.BlockedIP(net.ParseIP(s)) {
			t.Errorf("BlockedIP(%s) = true, want false (a public address must be allowed)", s)
		}
	}
	if !netsec.BlockedIP(nil) {
		t.Error("BlockedIP(nil) = false, want true (fail closed)")
	}
}

func TestSafeClientOptionsHonorExplicitCIDRGrants(t *testing.T) {
	opts := netsec.SafeClientOptions{AllowPrivateCIDRs: []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("127.0.0.1/32"),
	}}
	if err := netsec.ValidatePublicHTTPSURLWithOptions("https://10.1.2.3/hook", opts); err != nil {
		t.Fatalf("explicit RFC1918 grant was rejected: %v", err)
	}
	if err := netsec.ValidatePublicHTTPSURLWithOptions("https://127.0.0.1/hook", opts); err != nil {
		t.Fatalf("explicit loopback grant was rejected: %v", err)
	}
	if err := netsec.ValidatePublicHTTPSURLWithOptions("https://169.254.169.254/latest/meta-data/", netsec.SafeClientOptions{
		AllowPrivateCIDRs: []netip.Prefix{netip.MustParsePrefix("169.254.0.0/16")},
	}); err == nil {
		t.Fatal("metadata/link-local grant was allowed; it must stay hard-blocked")
	}
}

func TestSafeClientRefusesInternalTargets(t *testing.T) {
	c := netsec.SafeClient(2 * time.Second)
	for _, url := range []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://127.0.0.1:1/",
		"http://10.0.0.1/",
	} {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
		if _, err := c.Do(req); err == nil {
			t.Errorf("SafeClient reached %s; it must refuse non-public addresses", url)
		} else if !errors.Is(err, netsec.ErrSSRFBlocked) {
			// The dial Control wraps ErrSSRFBlocked; url.Error should carry it.
			t.Logf("note: %s blocked with non-sentinel error: %v", url, err)
		}
	}
}

func TestValidatePublicHTTPSURLRejectsUnsafeEndpoints(t *testing.T) {
	for _, raw := range []string{
		"://bad",
		"http://example.com/hook",
		"https:///missing-host",
		"https://127.0.0.1/hook",
		"https://[::1]/hook",
		"https://169.254.169.254/latest/meta-data/",
		"https://10.0.0.1/hook",
		"https://100.64.0.1/hook",
		"https://[fd00:ec2::254]/hook",
	} {
		err := netsec.ValidatePublicHTTPSURL(raw)
		if err == nil {
			t.Errorf("ValidatePublicHTTPSURL(%q) = nil, want SSRF-blocked error", raw)
			continue
		}
		if !errors.Is(err, netsec.ErrSSRFBlocked) {
			t.Errorf("ValidatePublicHTTPSURL(%q) = %v, want ErrSSRFBlocked", raw, err)
		}
	}

	for _, raw := range []string{
		"https://example.com/hook",
		"https://api.example.test/v1/events",
	} {
		if err := netsec.ValidatePublicHTTPSURL(raw); err != nil {
			t.Errorf("ValidatePublicHTTPSURL(%q) = %v, want allowed", raw, err)
		}
	}
}

func TestSafeClientRejectsCredentialBearingCrossOriginRedirects(t *testing.T) {
	client := netsec.SafeClient(time.Second)
	origin, _ := http.NewRequest(http.MethodGet, "https://api.example.test/start", nil)
	sameOrigin, _ := http.NewRequest(http.MethodGet, "https://api.example.test/next", nil)
	if err := client.CheckRedirect(sameOrigin, []*http.Request{origin}); err != nil {
		t.Fatalf("same-origin HTTPS redirect rejected: %v", err)
	}
	for _, target := range []string{
		"http://api.example.test/plaintext",
		"https://attacker.example.test/steal",
		"https://api.example.test:8443/other-origin",
	} {
		redirect, _ := http.NewRequest(http.MethodGet, target, nil)
		redirect.Header.Set("Authorization", "Bearer must-not-cross-origin")
		if err := client.CheckRedirect(redirect, []*http.Request{origin}); !errors.Is(err, netsec.ErrSSRFBlocked) {
			t.Fatalf("redirect to %s error = %v, want ErrSSRFBlocked", target, err)
		}
	}
}

// TestParseEgressAllowPrefixIsTheOneGate pins the shared J1/V23 helper: every
// config surface routes allowlist entries through it, so a host-bits or
// wildcard entry is a loud config-load error naming the value instead of a
// silent dial-time skip.
func TestParseEgressAllowPrefixIsTheOneGate(t *testing.T) {
	if _, err := netsec.ParseEgressAllowPrefix(" 10.0.0.0/8 "); err != nil {
		t.Fatalf("a valid (trimmed) network prefix was refused: %v", err)
	}
	for _, bad := range []string{"10.1.2.3/8", "0.0.0.0/0", "::/0", "not-a-cidr", "2001:db8::1/32"} {
		if _, err := netsec.ParseEgressAllowPrefix(bad); err == nil {
			t.Fatalf("%q was accepted; it would grant something other than what it reads as", bad)
		} else if bad != "not-a-cidr" && !strings.Contains(err.Error(), bad) {
			t.Fatalf("refusal of %q does not name the value: %v", bad, err)
		}
	}
}

// TestDialTimeSkipIsObservable pins the defence-in-depth half: an invalid
// prefix that still reaches the dialer (only possible from an unvalidated
// path) is skipped AND counted, never silently ignored.
func TestDialTimeSkipIsObservable(t *testing.T) {
	before := netsec.EgressAllowSkips()
	hostBits := netip.PrefixFrom(netip.MustParseAddr("10.1.2.3"), 8) // 10.1.2.3/8, host bits set
	opts := netsec.SafeClientOptions{AllowPrivateCIDRs: []netip.Prefix{hostBits}}
	if err := netsec.ValidatePublicHTTPSURLWithOptions("https://10.9.9.9/hook", opts); err == nil {
		t.Fatal("an invalid host-bits grant admitted a private target")
	}
	if got := netsec.EgressAllowSkips() - before; got < 1 {
		t.Fatalf("the dial-time skip was silent (counter moved by %d); J1/V23 stayed hidden precisely because nothing recorded it", got)
	}
}

// TestIsLoopbackHostChosenSemantics pins the ONE loopback predicate's contract
// (AUD-201 follow-up J4/V26) — this gate decides when plaintext HTTP is
// allowed, so the choice is security-relevant and deliberate:
//   - the whole loopback RANGE counts (127.0.0.2 as much as 127.0.0.1): every
//     127/8 address is equally without a network path, and the one copy that
//     string-compared exact addresses was the outlier;
//   - "localhost" matches case-insensitively (DNS names are case-insensitive,
//     so LOCALHOST is the same name);
//   - one layer of URL brackets is stripped, so "[::1]" is recognized;
//   - anything that is not localhost or a parseable loopback IP is NOT
//     loopback — names, private ranges, empty strings.
func TestIsLoopbackHostChosenSemantics(t *testing.T) {
	for _, host := range []string{"localhost", "LOCALHOST", " localhost ", "127.0.0.1", "127.0.0.2", "::1", "[::1]"} {
		if !netsec.IsLoopbackHost(host) {
			t.Errorf("IsLoopbackHost(%q) = false, want true", host)
		}
	}
	for _, host := range []string{"", "example.com", "10.0.0.1", "192.168.1.1", "127.0.0.1.evil.test", "fd00::1", "localhost.example.com"} {
		if netsec.IsLoopbackHost(host) {
			t.Errorf("IsLoopbackHost(%q) = true, want false — this gate admits plaintext HTTP", host)
		}
	}
}
