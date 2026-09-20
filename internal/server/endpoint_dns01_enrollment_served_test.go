// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/ca/digicert"
	"trstctl.com/trstctl/internal/ca/digicert/digicertfake"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/projections"
)

// Exercise the durable HTTP review/prepare boundary. The CA double advertises
// the DNS-01 prerequisite to isolate enrollment; no upstream issuance is drained
// here. Real ACME and host activation are covered by the installed journey.
func TestEndpointDNS01EnrollmentSurvivesDurableReviewAndRechecksConsent(t *testing.T) {
	ca, err := digicertfake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ca.Close)
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.ExternalCAs = []ExternalCA{{ID: "dns01-authority", Type: "digicert", Name: "DNS-01 enrollment authority", UpstreamDNS01: true,
			CA: digicert.New("dns01-authority", ca.URL(), []byte(ca.APIKey()))}}
	})
	token := seedScopedToken(t, h.store, h.tenant, "owners:write", "connectors:write", "certs:issue", "issuers:write")
	request := func(method, path, key string, payload any, want int) map[string]json.RawMessage {
		t.Helper()
		code, body := secretsReqKey(t, h, method, path, token, key, payload)
		if code != want {
			t.Fatalf("%s %s: status=%d want=%d body=%s", method, path, code, want, body)
		}
		var result map[string]json.RawMessage
		if err := json.Unmarshal(body, &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	text := func(value json.RawMessage) string {
		t.Helper()
		var result string
		if err := json.Unmarshal(value, &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	owner := request(http.MethodPost, "/api/v1/owners", "dns01-owner", map[string]any{"kind": "workload", "name": "DNS-01 enrollment owner"}, http.StatusCreated)
	target := request(http.MethodPost, "/api/v1/connectors/targets", "dns01-target", map[string]any{
		"name": "dns01-enrollment", "connector": "aws-acm", "enabled": true,
		"config": map[string]any{"region": "us-east-1", "access_key_id": "AKIDTESTONLY", "secret_access_key_ref": "secret://connectors/dns01-test"},
	}, http.StatusCreated)
	dns := map[string]any{"name": "DNS-01 enrollment zone", "provider": "webhook", "zone": "dns01-enrollment.test", "config": map[string]any{"endpoint": "http://127.0.0.1:8056"}, "allowed_methods": []string{"dns-01"}, "allow_upstream_dv": true}
	provider := request(http.MethodPost, "/api/v1/acme/dns-01/provider-configs", "dns01-provider", dns, http.StatusCreated)
	body := map[string]any{"owner_id": text(owner["id"]), "identity_name": "first.dns01-enrollment.test", "target_id": text(target["id"]), "reason": "exercise durable DNS-01 review", "issuer": map[string]any{"source": "external", "id": "dns01-authority"}}
	const endpoint = "/api/v1/lifecycle/endpoint-bindings"
	preview := request(http.MethodPost, endpoint+"/preview", "dns01-preview", body, http.StatusOK)
	body["preview_fingerprint"] = text(preview["request_fingerprint"])
	before := eventCount(t, h.log, h.tenant, projections.EventIdentityCreated)
	created := request(http.MethodPost, endpoint, "dns01-enroll", body, http.StatusCreated)
	replayed := request(http.MethodPost, endpoint, "dns01-enroll", body, http.StatusCreated)
	if string(created["identity"]) != string(replayed["identity"]) || eventCount(t, h.log, h.tenant, projections.EventIdentityCreated) != before+1 {
		t.Fatal("durable enrollment replay changed its identity or created a duplicate")
	}
	var issuer map[string]string
	if err := json.Unmarshal(created["issuer"], &issuer); err != nil || issuer["source"] != "external" || issuer["id"] != "dns01-authority" {
		t.Fatalf("enrollment lost its exact external CA: %s (%v)", created["issuer"], err)
	}
	// Runtime-only metadata must still enforce current DNS consent after review.
	body["identity_name"] = "second.dns01-enrollment.test"
	delete(body, "preview_fingerprint")
	preview = request(http.MethodPost, endpoint+"/preview", "dns01-preview-second", body, http.StatusOK)
	body["preview_fingerprint"] = text(preview["request_fingerprint"])
	dns["allow_upstream_dv"] = false
	request(http.MethodPut, "/api/v1/acme/dns-01/provider-configs/"+text(provider["id"]), "dns01-remove-consent", dns, http.StatusOK)
	before = eventCount(t, h.log, h.tenant, projections.EventIdentityCreated)
	beforeOutbox := connectorTargetOutboxRows(t, h)
	request(http.MethodPost, endpoint, "dns01-refuse-without-consent", body, http.StatusUnprocessableEntity)
	if eventCount(t, h.log, h.tenant, projections.EventIdentityCreated) != before || connectorTargetOutboxRows(t, h) != beforeOutbox {
		t.Fatal("lost DNS consent created an identity or queued lifecycle work")
	}
}
