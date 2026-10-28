// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/store"
)

// A212: addresses trstctl's own sources saw outside every declared segment are
// listed as candidates, an excluded segment counting as declared; the coverage
// register names them; declaring a segment that covers them clears them.
func TestServedCoverageCandidatesListAddressesOutsideEveryDeclaredSegment(t *testing.T) {
	ctx := t.Context()
	h := newServedHarness(t, config.Protocols{})
	tenant := uuid.NewString()
	registerServedTenantID(t, h, tenant, "A212 coverage tenant")
	token := seedScopedToken(t, h.store, tenant, "discovery:read", "discovery:write")
	for _, segment := range []store.DiscoverySegment{
		{Name: "a212-core", Ranges: []string{"10.0.0.0/24"}, StalenessHours: 24},
		{Name: "a212-lab", Ranges: []string{"10.9.0.0/24"}, StalenessHours: 24, Excluded: true, ExclusionReason: "lab bench"},
	} {
		if _, err := h.srv.orch.UpsertDiscoverySegment(ctx, tenant, segment); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	notAfter := now.Add(24 * time.Hour)
	for i, location := range []string{"10.0.0.5:443", "10.9.0.7:443", "198.51.100.20:8443", "/etc/nginx/a212.crt"} {
		if _, err := h.srv.orch.RecordCertificate(ctx, tenant, store.Certificate{
			Subject: "CN=a212-" + strconv.Itoa(i), Issuer: "CN=A212 Issuer", Serial: strconv.Itoa(i + 10),
			Fingerprint: crypto.SHA256Hex([]byte("a212 " + location)), KeyAlgorithm: "ECDSA-P256",
			NotBefore: &now, NotAfter: &notAfter, DeploymentLocation: location, Source: "a212-fixture", Status: "active",
		}); err != nil {
			t.Fatalf("record certificate at %s: %v", location, err)
		}
	}
	type candidates struct {
		Items []struct {
			Address string   `json:"address"`
			Sources []string `json:"sources"`
		} `json:"items"`
		Complete bool `json:"complete"`
	}
	read := func() candidates {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/coverage/candidates", token, nil)
		if status != http.StatusOK {
			t.Fatalf("candidates = %d %s", status, body)
		}
		var out candidates
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	got := read()
	if got.Complete || len(got.Items) != 1 || got.Items[0].Address != "198.51.100.20:8443" ||
		len(got.Items[0].Sources) != 1 || got.Items[0].Sources[0] != "certificate_location" {
		t.Fatalf("candidates = %+v; want only the address outside both declared segments, never complete", got)
	}
	unknowns := func() map[string]string {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/coverage", token, nil)
		if status != http.StatusOK {
			t.Fatalf("coverage = %d %s", status, body)
		}
		var coverage struct {
			Unknowns []struct {
				Kind    string `json:"kind"`
				Subject string `json:"subject"`
			} `json:"unknowns"`
		}
		if err := json.Unmarshal(body, &coverage); err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, unknown := range coverage.Unknowns {
			out[unknown.Kind] = unknown.Subject
		}
		return out
	}
	if subject := unknowns()["addresses_outside_segments"]; subject != "1 address" {
		t.Fatalf("coverage register names %q for addresses outside segments; want 1 address", subject)
	}
	if _, err := h.srv.orch.UpsertDiscoverySegment(ctx, tenant, store.DiscoverySegment{
		Name: "a212-partner", Ranges: []string{"198.51.100.0/24"}, StalenessHours: 24,
	}); err != nil {
		t.Fatal(err)
	}
	if got := read(); len(got.Items) != 0 {
		t.Fatalf("a declared address is still a candidate: %+v", got)
	}
	if _, listed := unknowns()["addresses_outside_segments"]; listed {
		t.Fatal("the coverage register still names addresses outside segments after declaring them")
	}
}
