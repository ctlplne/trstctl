// SPDX-License-Identifier: MPL-2.0

package server

import (
	"encoding/hex"
	"strings"
	"testing"
	"testing/quick"

	"trstctl.com/trstctl/internal/crypto"
)

func TestWorkloadSPIFFEIdentityNaming(t *testing.T) {
	for _, tc := range []struct{ subject, path string }{
		{"agent-7", "agent-7"},
		{"ns/qa/sa/revocation-reader", "ns/qa/sa/revocation-reader"},
		{"Agent_7/v1.0", "Agent_7/v1.0"},
		{"a:b", "trstctl-hex-613a62"},
		{"a%2Fb", "trstctl-hex-6125324662"},
		{"repo:org/project:ref:refs/heads/main", "trstctl-hex-7265706f3a6f7267/trstctl-hex-70726f6a6563743a7265663a72656673/heads/main"},
		{"trstctl-hex-613a62", "trstctl-hex-" + hex.EncodeToString([]byte("trstctl-hex-613a62"))},
	} {
		for _, route := range []string{"broker", "attested"} {
			want := "spiffe://served.test/" + tc.path
			got, err := attestedSPIFFEID("served.test", tc.subject)
			if route == "broker" {
				want = "spiffe://served.test/agent/" + tc.path
				got, err = brokerSPIFFEID("served.test", tc.subject)
			}
			if err != nil || got != want {
				t.Errorf("%s subject=%q: got %q error=%v, want %q", route, tc.subject, got, err, want)
			}
		}
	}
}

func TestWorkloadSPIFFEIdentityRejectsAmbiguityAndOversize(t *testing.T) {
	for _, makeID := range []func(string, string) (string, error){brokerSPIFFEID, attestedSPIFFEID} {
		for _, subject := range []string{"", "/a", "a/", "a//b", ".", "..", "a/../b", "a/./b", strings.Repeat("a", 2048)} {
			if _, err := makeID("served.test", subject); err == nil {
				t.Errorf("accepted ambiguous/oversized subject: %q", subject)
			}
		}
		for _, domain := range []string{"", "served.test:443", "served.test/path", "user@served.test", "SERVED.test"} {
			if _, err := makeID(domain, "a"); err == nil {
				t.Errorf("accepted invalid trust domain: %q", domain)
			}
		}
	}
}

func TestWorkloadSPIFFEIdentityMappingIsInjective(t *testing.T) {
	// A subject that resembles an encoded name must never impersonate it.
	for _, subject := range []string{"a:b", "repo:org/project", "a%2Fb", "é", "trstctl-hex-a"} {
		id, err := attestedSPIFFEID("served.test", subject)
		if err != nil {
			t.Fatal(err)
		}
		path := strings.TrimPrefix(id, "spiffe://served.test/")
		alias, err := attestedSPIFFEID("served.test", path)
		if err != nil || id == alias {
			t.Fatalf("encoded subject can be impersonated by literal path: %q", subject)
		}
	}
	property := func(a, b string) bool {
		for _, makeID := range []func(string, string) (string, error){brokerSPIFFEID, attestedSPIFFEID} {
			x, ex := makeID("served.test", a)
			y, ey := makeID("served.test", b)
			if ex != nil || ey != nil {
				continue
			}
			if (a == b) != (x == y) {
				return false
			}
			u, err := crypto.ParseSPIFFEID(x)
			if err != nil || u.String() != x {
				return false
			}
		}
		return true
	}
	if err := quick.Check(property, &quick.Config{MaxCount: 1000}); err != nil {
		t.Fatal(err)
	}
}

func TestWorkloadSPIFFEIdentityKeepsBrokerNamespaceSeparate(t *testing.T) {
	broker, err := brokerSPIFFEID("served.test", "ns/qa/sa/web")
	if err != nil {
		t.Fatal(err)
	}
	attested, err := attestedSPIFFEID("served.test", "agent/ns/qa/sa/web")
	if err != nil {
		t.Fatal(err)
	}
	if broker == attested {
		t.Fatal("an attested subject can claim the broker namespace")
	}
	if attested != "spiffe://served.test/trstctl-hex-6167656e74/ns/qa/sa/web" {
		t.Fatalf("reserved broker namespace must use the documented encoding: %q", attested)
	}
}

func TestWorkloadSPIFFEIdentitySupportsMaximumWireLength(t *testing.T) {
	for _, tc := range []struct {
		prefix string
		makeID func(string, string) (string, error)
	}{
		{"spiffe://t/", attestedSPIFFEID}, {"spiffe://t/agent/", brokerSPIFFEID},
	} {
		subject := strings.Repeat("a", 2048-len(tc.prefix))
		id, err := tc.makeID("t", subject)
		if err != nil || id != tc.prefix+subject {
			t.Fatalf("maximum supported identity rejected: %v", err)
		}
		if _, err := tc.makeID("t", subject+"a"); err == nil {
			t.Fatal("oversized identity accepted")
		}
	}
}
