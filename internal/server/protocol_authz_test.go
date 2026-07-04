// SPDX-License-Identifier: MPL-2.0

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
