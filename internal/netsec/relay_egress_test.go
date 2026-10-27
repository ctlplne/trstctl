// SPDX-License-Identifier: BUSL-1.1

package netsec

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

// A190: a relay's job connections always refuse link-local, cloud metadata,
// unspecified and multicast addresses, even when an allowlist names them; an
// operator allowlist then refuses everything it does not name.
func TestRelayEgressRefusesMetadataAlwaysAndHonorsTheAllowlist(t *testing.T) {
	open, err := ParseRelayEgress(nil)
	if err != nil {
		t.Fatal(err)
	}
	listed, err := ParseRelayEgress([]string{"10.20.0.0/16", "192.0.2.7", "198.51.100.9:8443", "[fd00::5]:443", "169.254.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	var none *RelayEgress
	for _, refused := range []string{"169.254.169.254:80", "[fe80::1]:443", "0.0.0.0:443", "224.0.0.1:80",
		"100.100.100.200:80", "[fd00:ec2::254]:80", "[::ffff:169.254.169.254]:80"} {
		dest := netip.MustParseAddrPort(refused)
		for name, policy := range map[string]*RelayEgress{"open": open, "listed": listed, "nil": none} {
			if err := policy.Allow(dest); !errors.Is(err, ErrRelayEgressBlocked) {
				t.Errorf("%s policy allowed %s: %v", name, refused, err)
			}
		}
	}
	for _, allowed := range []string{"10.0.0.5:443", "127.0.0.1:80", "8.8.8.8:443"} {
		if err := open.Allow(netip.MustParseAddrPort(allowed)); err != nil {
			t.Errorf("a policy without an allowlist refused %s: %v", allowed, err)
		}
	}
	for dest, want := range map[string]bool{
		"10.20.3.4:22": true, "10.21.0.1:443": false, "192.0.2.7:1": true, "198.51.100.9:8443": true,
		"198.51.100.9:443": false, "[fd00::5]:443": true, "[fd00::5]:80": false, "127.0.0.1:80": false,
	} {
		err := listed.Allow(netip.MustParseAddrPort(dest))
		if got := err == nil; got != want {
			t.Errorf("allowlist decision for %s = %v (%v), want %v", dest, got, err, want)
		}
	}
	if err := listed.Control("tcp", "169.254.169.254:80", nil); !errors.Is(err, ErrRelayEgressBlocked) {
		t.Fatalf("Control allowed instance metadata: %v", err)
	}
	if !strings.Contains(listed.String(), "allowlist 10.20.0.0/16, 169.254.0.0/16, 192.0.2.7, 198.51.100.9:8443, [fd00::5]:443") || open.String() == listed.String() {
		t.Fatalf("policy descriptions = %q / %q", listed.String(), open.String())
	}
	for _, bad := range []string{"appliance.example.com", "0.0.0.0/0", "10.1.2.3/8", "10.0.0.5:0"} {
		if _, err := ParseRelayEgress([]string{bad}); err == nil {
			t.Errorf("allowlist entry %q was accepted", bad)
		}
	}
}

// The request check runs before the transport sends anything, so a request a
// proxy would carry is refused too; the dial check refuses on the address.
func TestRelayEgressGuardsRequestsAndDials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	t.Cleanup(server.Close)
	addr := strings.TrimPrefix(server.URL, "http://")

	sent := 0
	next := roundTripFunc(func(*http.Request) (*http.Response, error) {
		sent++
		return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody}, nil
	})
	listed, err := ParseRelayEgress([]string{"10.20.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: listed.RoundTripper(next)}
	for _, target := range []string{"http://169.254.169.254/latest/meta-data/", server.URL} {
		if _, err := client.Get(target); !errors.Is(err, ErrRelayEgressBlocked) {
			t.Errorf("request to %s = %v, want refused", target, err)
		}
	}
	if sent != 0 {
		t.Fatalf("%d refused requests reached the transport", sent)
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	listed.GuardTransport(transport)
	if _, err := (&http.Client{Transport: transport}).Get(server.URL); !errors.Is(err, ErrRelayEgressBlocked) {
		t.Fatalf("a dial to an unlisted address = %v, want refused", err)
	}
	local, err := ParseRelayEgress([]string{strings.Split(addr, ":")[0]})
	if err != nil {
		t.Fatal(err)
	}
	allowed := http.DefaultTransport.(*http.Transport).Clone()
	local.GuardTransport(allowed)
	resp, err := (&http.Client{Transport: local.RoundTripper(allowed)}).Get(server.URL)
	if err != nil || resp.StatusCode != http.StatusNoContent {
		t.Fatalf("a listed destination = %v", err)
	}
	_ = resp.Body.Close()
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
