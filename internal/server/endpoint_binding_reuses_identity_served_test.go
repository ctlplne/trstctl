// SPDX-License-Identifier: MPL-2.0

package server

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/ca/digicert"
	"trstctl.com/trstctl/internal/ca/digicert/digicertfake"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/projections"
)

// Discovery claimed a listener's certificate into an identity named after its DNS
// name; the endpoint wizard for the same DNS name must enroll that identity, not
// mint a twin. The preview names the existing identity, the create binds it, and
// exactly one identity carries the name afterwards (DP2-019).
func TestEndpointBindingReusesTheIdentityClaimedForTheSameName(t *testing.T) {
	dc, err := digicertfake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dc.Close)
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.LifecycleRenewBefore = 31 * 24 * time.Hour
		d.ExternalCAs = []ExternalCA{{
			ID: "corporate-digicert", Type: "digicert", Name: "Corporate DigiCert",
			CA: digicert.New("corporate-digicert", dc.URL(), []byte(dc.APIKey()), digicert.WithHTTPClient(&http.Client{Timeout: 5 * time.Second})),
		}}
	})
	tok := seedScopedToken(t, h.store, h.tenant,
		"owners:read", "owners:write", "identities:read", "identities:write",
		"certs:read", "certs:issue", "connectors:read", "connectors:write", "lifecycle:read",
	)
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/owners", tok, map[string]any{"kind": "workload", "name": "dp2-019-owner"})
	if status != http.StatusCreated {
		t.Fatalf("create owner: status %d body %s", status, body)
	}
	var owner struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &owner); err != nil {
		t.Fatal(err)
	}
	// The identity the claim flow creates for the discovered listener.
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities", tok, map[string]any{
		"owner_id": owner.ID, "kind": "x509", "name": "apache.partner-lab.example.com",
	})
	if status != http.StatusCreated {
		t.Fatalf("create claimed identity: status %d body %s", status, body)
	}
	var claimed struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &claimed); err != nil {
		t.Fatal(err)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/connectors/targets", tok, map[string]any{
		"name": "cloud/acm/dp2-019", "connector": "aws-acm", "enabled": true,
		"config": map[string]any{"region": "us-east-1", "access_key_id": "AKIDTESTONLY", "secret_access_key_ref": "secret://connectors/aws-acm/dp2-019"},
	})
	if status != http.StatusCreated {
		t.Fatalf("create target: status %d body %s", status, body)
	}
	var target struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &target); err != nil {
		t.Fatal(err)
	}
	request := map[string]any{
		"owner_id": owner.ID, "identity_name": "apache.partner-lab.example.com", "target_id": target.ID,
		"issuer": map[string]any{"source": "external", "id": "corporate-digicert"},
		"reason": "take the discovered listener under management",
	}
	before := eventCount(t, h.log, h.tenant, projections.EventIdentityCreated)

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/lifecycle/endpoint-bindings/preview", tok, request)
	if status != http.StatusOK {
		t.Fatalf("preview: status %d body %s", status, body)
	}
	var preview struct {
		RequestFingerprint string `json:"request_fingerprint"`
		ExistingIdentity   *struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"existing_identity"`
	}
	if err := json.Unmarshal(body, &preview); err != nil {
		t.Fatal(err)
	}
	if preview.ExistingIdentity == nil || preview.ExistingIdentity.ID != claimed.ID {
		t.Fatalf("preview did not name the identity already claimed for this DNS name: %s", body)
	}

	request["preview_fingerprint"] = preview.RequestFingerprint
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/lifecycle/endpoint-bindings", tok, request)
	if status != http.StatusCreated {
		t.Fatalf("create binding: status %d body %s", status, body)
	}
	var created struct {
		Identity struct {
			ID string `json:"id"`
		} `json:"identity"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	if created.Identity.ID != claimed.ID {
		t.Fatalf("binding enrolled identity %s, want the claimed identity %s", created.Identity.ID, claimed.ID)
	}
	if got := eventCount(t, h.log, h.tenant, projections.EventIdentityCreated) - before; got != 0 {
		t.Fatalf("the wizard created %d new identit(y/ies) for a DNS name that already had one", got)
	}
}
