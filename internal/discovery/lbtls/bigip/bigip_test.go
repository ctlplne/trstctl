// SPDX-License-Identifier: BUSL-1.1

package bigip

import (
	"reflect"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/discovery/lbtls/bigip/bigiptest"
)

func seeded(t *testing.T) *bigiptest.Server {
	t.Helper()
	stand := bigiptest.New("x4-reader", "x4-reader-password", "x4-token")
	t.Cleanup(stand.Close)
	stand.Seed(
		[]bigiptest.Profile{
			{FullPath: "/Common/clientssl-legacy", TMOptions: "{ dont-insert-empty-fragments no-tlsv1.3 }", Ciphers: "DEFAULT"},
			{FullPath: "/Common/clientssl-modern", TMOptions: "{ dont-insert-empty-fragments no-tlsv1 no-tlsv1.1 }", Ciphers: "ECDHE+AES-GCM"},
		},
		[]bigiptest.Virtual{
			{FullPath: "/Common/vs_legacy", Destination: "/Common/10.0.0.10:443", Profiles: []string{"/Common/http", "/Common/clientssl-legacy"}},
			{FullPath: "/Common/vs_modern", Destination: "/Common/2001:db8::20.8443", Profiles: []string{"/Common/clientssl-modern"}},
			{FullPath: "/Common/vs_plain", Destination: "/Common/10.0.0.30%2:80", Profiles: []string{"/Common/http"}},
		},
	)
	return stand
}

// X4: each virtual server presenting a client SSL profile comes back with the
// versions the profile's options leave enabled, by token or by user; profile
// pages are followed against the configured base even though BIG-IP writes
// them against localhost; a virtual server with no client SSL profile is left
// out; nothing but GETs are sent.
func TestListenersReadClientSSLProfilesX4(t *testing.T) {
	stand := seeded(t)
	for name, cfg := range map[string]Config{
		"token": {BaseURL: stand.URL(), Token: "x4-token", HTTPClient: stand.Client()},
		"basic": {BaseURL: stand.URL(), Username: "x4-reader", Password: "x4-reader-password", HTTPClient: stand.Client()}, // #nosec G101 -- fabricated fixture credential; no value is real (CWE-798)
	} {
		r, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		ls, err := r.Listeners(t.Context())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(ls) != 2 {
			t.Fatalf("%s: listeners = %+v", name, ls)
		}
		legacy, modern := ls[0], ls[1]
		if legacy.Ref != "/Common/vs_legacy@/Common/clientssl-legacy" || legacy.Port != 443 || legacy.Policy != "/Common/clientssl-legacy" ||
			!reflect.DeepEqual(legacy.Protocols, []string{"TLSv1.0", "TLSv1.1", "TLSv1.2"}) || !reflect.DeepEqual(legacy.Ciphers, []string{"DEFAULT"}) {
			t.Fatalf("%s: legacy = %+v", name, legacy)
		}
		if modern.Ref != "/Common/vs_modern@/Common/clientssl-modern" || modern.Port != 8443 || !reflect.DeepEqual(modern.Protocols, []string{"TLSv1.2", "TLSv1.3"}) {
			t.Fatalf("%s: modern = %+v", name, modern)
		}
	}
	if stand.Mutations() != 0 || stand.Refused() != 0 || stand.Gets() != 6 {
		t.Fatalf("mutations=%d refused=%d gets=%d", stand.Mutations(), stand.Refused(), stand.Gets())
	}
	wrong, _ := New(Config{BaseURL: stand.URL(), Username: "x4-reader", Password: "wrong", HTTPClient: stand.Client()})
	if _, err := wrong.Listeners(t.Context()); err == nil || !strings.Contains(err.Error(), "status 401") || strings.Contains(err.Error(), "Authorization failed") {
		t.Fatalf("wrong password: err = %v", err)
	}
	if _, err := New(Config{BaseURL: "https://user:pw@bigip.example.test", Token: "t"}); err == nil { // #nosec G101 -- a URL carrying credentials, built to prove it is refused; no value is real (CWE-798)
		t.Fatal("a base URL carrying credentials was accepted")
	}
	if _, err := New(Config{BaseURL: stand.URL()}); err == nil {
		t.Fatal("a reader without credentials was built")
	}
}

func TestAllowedProtocolsAndDestinationPortX4(t *testing.T) {
	for opts, want := range map[string][]string{
		"{ dont-insert-empty-fragments }":                 {"TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"},
		"{ dont-insert-empty-fragments no-tlsv1.3 }":      {"TLSv1.0", "TLSv1.1", "TLSv1.2"},
		"{ no-tlsv1 no-tlsv1.1 no-tlsv1.2 }":              {"TLSv1.3"},
		"none":                                            {"TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"},
		"{ NO-TLSV1 no-ssl dont-insert-empty-fragments }": {"TLSv1.1", "TLSv1.2", "TLSv1.3"},
	} {
		if got := AllowedProtocols(opts); !reflect.DeepEqual(got, want) {
			t.Fatalf("%q = %v, want %v", opts, got, want)
		}
	}
	for dest, want := range map[string]int{"/Common/10.0.0.10:443": 443, "/Common/10.0.0.10%2:8443": 8443, "/Common/2001:db8::1.443": 443, "/Common/any:any": 0} {
		if got := destinationPort(dest); got != want {
			t.Fatalf("%s = %d, want %d", dest, got, want)
		}
	}
}
