// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestProtocolAuthzManifestEnumeratesMountedProtocolSurfaces(t *testing.T) {
	entries := ProtocolAuthzManifest()
	if len(entries) == 0 {
		t.Fatal("protocol authz manifest is empty")
	}

	seen := map[string]ProtocolAuthzEntry{}
	for _, e := range entries {
		if e.Protocol == "" {
			t.Error("protocol authz entry has empty protocol")
		}
		if len(e.FeatureIDs) == 0 {
			t.Errorf("%s has no feature IDs", e.Protocol)
		}
		if len(e.RoutePatterns) == 0 {
			t.Errorf("%s has no route/RPC patterns", e.Protocol)
		}
		if e.Permission == "" && e.PublicRationale == "" {
			t.Errorf("%s has neither permission nor explicit public rationale", e.Protocol)
		}
		if e.Permission != "" && e.PublicRationale != "" {
			t.Errorf("%s declares both permission %q and public rationale %q", e.Protocol, e.Permission, e.PublicRationale)
		}
		if e.TenantMapping == "" {
			t.Errorf("%s has no tenant mapping", e.Protocol)
		}
		if e.PrincipalMapping == "" {
			t.Errorf("%s has no principal mapping", e.Protocol)
		}
		if e.EnablementAuthority == "" {
			t.Errorf("%s has no admin enablement authority", e.Protocol)
		}
		if e.DefaultDenyTest == "" {
			t.Errorf("%s has no default-deny/conformance test reference", e.Protocol)
		}
		placeholder := "TO" + "DO"
		if strings.Contains(e.PublicRationale, placeholder) || strings.Contains(e.TenantMapping, placeholder) || strings.Contains(e.PrincipalMapping, placeholder) {
			t.Errorf("%s contains placeholder authz rationale: %+v", e.Protocol, e)
		}
		seen[e.Protocol] = e
	}

	for _, protocol := range []string{"acme", "est", "scep", "cmp", "ssh", "tsa", "spiffe"} {
		e, ok := seen[protocol]
		if !ok {
			t.Errorf("protocol authz manifest missing %s", protocol)
			continue
		}
		got := append([]string(nil), e.RoutePatterns...)
		want := protocolAuthzRoutePatterns(protocol)
		sort.Strings(got)
		sort.Strings(want)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s route/RPC patterns = %v, want %v", protocol, got, want)
		}
	}
}

func TestProtocolHTTPNamespaceRegistryCoversEveryMountAUD75(t *testing.T) {
	want := map[string][]string{
		"acme": {"/directory", "/directory/", "/acme/"},
		"est":  {"/.well-known/est/"},
		"scep": {"/scep", "/scep/"},
		"cmp":  {"/cmp", "/cmp/"},
		"ssh":  {"/ssh/"},
		"tsa":  {"/tsa", "/tsa/"},
	}
	if len(httpProtocolNames) != len(want) {
		t.Fatalf("HTTP protocol registry has %d names, want %d: %v", len(httpProtocolNames), len(want), httpProtocolNames)
	}
	seen := make(map[string]struct{}, len(httpProtocolNames))
	for _, protocol := range httpProtocolNames {
		if _, duplicate := seen[protocol]; duplicate {
			t.Fatalf("duplicate HTTP protocol registry name %q", protocol)
		}
		seen[protocol] = struct{}{}
		if got := protocolHTTPNamespacePatterns(protocol); !reflect.DeepEqual(got, want[protocol]) {
			t.Errorf("%s namespace patterns=%v, want %v", protocol, got, want[protocol])
		}
		reserved := make(map[string]struct{}, len(want[protocol]))
		for _, pattern := range want[protocol] {
			reserved[pattern] = struct{}{}
		}
		for _, pattern := range protocolHTTPMountPatterns(protocol) {
			if _, ok := reserved[pattern]; !ok {
				t.Errorf("%s enabled mount %q is not reserved from the SPA fallback", protocol, pattern)
			}
		}
	}
}
