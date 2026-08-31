// SPDX-License-Identifier: MPL-2.0

package server

import (
	"encoding/hex"
	"strings"
	"testing"
	"testing/quick"

	"trstctl.com/trstctl/internal/crypto"
)

const workloadIdentityTestTenant = "11111111-1111-4111-8111-111111111111"

func testWorkloadIdentityPrefix(domain, surface string) string {
	prefix := "spiffe://" + domain + "/_trstctl/v1/tenant/" + workloadIdentityTestTenant + "/" + surface
	if surface == "broker" {
		prefix += "/agent/agent-7"
	}
	return prefix + "/method/k8s_sat/subject/"
}

func testBrokerSPIFFEID(domain, subject string) (string, error) {
	return brokerSPIFFEID(domain, workloadIdentityTestTenant, "agent-7", "k8s_sat", subject)
}

func testAttestedSPIFFEID(domain, subject string) (string, error) {
	return attestedSPIFFEID(domain, workloadIdentityTestTenant, "k8s_sat", subject)
}

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
			want := testWorkloadIdentityPrefix("served.test", "attested") + tc.path
			got, err := testAttestedSPIFFEID("served.test", tc.subject)
			if route == "broker" {
				want = testWorkloadIdentityPrefix("served.test", "broker") + tc.path
				got, err = testBrokerSPIFFEID("served.test", tc.subject)
			}
			if err != nil || got != want {
				t.Errorf("%s subject=%q: got %q error=%v, want %q", route, tc.subject, got, err, want)
			}
		}
	}
}

func TestWorkloadSPIFFEIdentityRejectsAmbiguityAndOversize(t *testing.T) {
	for _, makeID := range []func(string, string) (string, error){testBrokerSPIFFEID, testAttestedSPIFFEID} {
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
		id, err := testAttestedSPIFFEID("served.test", subject)
		if err != nil {
			t.Fatal(err)
		}
		path := strings.TrimPrefix(id, testWorkloadIdentityPrefix("served.test", "attested"))
		alias, err := testAttestedSPIFFEID("served.test", path)
		if err != nil || id == alias {
			t.Fatalf("encoded subject can be impersonated by literal path: %q", subject)
		}
	}
	property := func(a, b string) bool {
		for _, makeID := range []func(string, string) (string, error){testBrokerSPIFFEID, testAttestedSPIFFEID} {
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
	broker, err := testBrokerSPIFFEID("served.test", "ns/qa/sa/web")
	if err != nil {
		t.Fatal(err)
	}
	attested, err := testAttestedSPIFFEID("served.test", "agent/ns/qa/sa/web")
	if err != nil {
		t.Fatal(err)
	}
	if broker == attested {
		t.Fatal("an attested subject can claim the broker namespace")
	}
	if attested != testWorkloadIdentityPrefix("served.test", "attested")+"agent/ns/qa/sa/web" {
		t.Fatalf("attested identity must remain in its separate authenticated namespace: %q", attested)
	}
}

func TestWorkloadSPIFFEIdentitySupportsMaximumWireLength(t *testing.T) {
	for _, tc := range []struct {
		prefix string
		makeID func(string, string) (string, error)
	}{
		{testWorkloadIdentityPrefix("t", "attested"), testAttestedSPIFFEID}, {testWorkloadIdentityPrefix("t", "broker"), testBrokerSPIFFEID},
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

func TestWorkloadSPIFFEIdentityRequiresAuthorityContext(t *testing.T) {
	base := workloadIdentityScope{TenantID: workloadIdentityTestTenant, Method: "k8s_sat", Kind: "attested"}
	for _, edit := range []func(*workloadIdentityScope){
		func(s *workloadIdentityScope) { s.TenantID = "" },
		func(s *workloadIdentityScope) { s.TenantID = "../../other" },
		func(s *workloadIdentityScope) { s.TenantID = "00000000-0000-0000-0000-000000000000" },
		func(s *workloadIdentityScope) { s.Method = "" },
		func(s *workloadIdentityScope) { s.Kind = "" },
		func(s *workloadIdentityScope) { s.Kind = "broker"; s.AgentID = "" },
		func(s *workloadIdentityScope) { s.AgentID = "unexpected" },
	} {
		scope := base
		edit(&scope)
		if _, err := workloadSPIFFEID("served.test", scope, "ns/qa/sa/web"); err == nil {
			t.Fatal("missing/invalid authority context accepted")
		}
	}
}

func TestWorkloadSPIFFEIdentitySeparatesAuthorityDimensions(t *testing.T) {
	scopes := []workloadIdentityScope{
		{TenantID: workloadIdentityTestTenant, Method: "k8s_sat", Kind: "attested"},
		{TenantID: "22222222-2222-4222-8222-222222222222", Method: "k8s_sat", Kind: "attested"},
		{TenantID: workloadIdentityTestTenant, Method: "github_oidc", Kind: "attested"},
		{TenantID: workloadIdentityTestTenant, Method: "k8s_sat", Kind: "ephemeral"},
		{TenantID: workloadIdentityTestTenant, Method: "k8s_sat", Kind: "broker", AgentID: "agent-7"},
		{TenantID: workloadIdentityTestTenant, Method: "k8s_sat", Kind: "broker", AgentID: "agent-8"},
		{TenantID: workloadIdentityTestTenant, Method: "k8s_sat", Kind: "broker", AgentID: "agent-7/method/k8s_sat/subject/admin"},
	}
	seen := map[string]bool{}
	for _, scope := range scopes {
		id, err := workloadSPIFFEID("served.test", scope, "ns/qa/sa/web")
		if err != nil || seen[id] {
			t.Fatalf("authority contexts collided or were rejected: %v", err)
		}
		seen[id] = true
		if _, err := crypto.ParseSPIFFEID(id); err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(id, "spiffe://served.test/_trstctl/v1/tenant/"+scope.TenantID+"/") {
			t.Fatal("name escaped the authenticated tenant")
		}
	}
}
