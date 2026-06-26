package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/egress"
)

// COMP-03 acceptance: an air-gapped/no-phone-home served install can still issue a
// certificate and manage a secret while the product-wide outbound egress guard is
// armed. The guard is verified first against a synthetic public endpoint, then reset;
// the real served work below must leave the trip counter at zero.
func TestServedAirGapIssuesCertificateAndManagesSecretWithZeroOutboundEgress(t *testing.T) {
	guard, err := egress.NewGuard(egress.Config{Enabled: true, AllowPrivate: true})
	if err != nil {
		t.Fatalf("build egress guard: %v", err)
	}
	if err := guard.CheckURL("https://telemetry.trstctl.com/v1/usage"); !errors.Is(err, egress.ErrBlocked) {
		t.Fatalf("egress guard probe err = %v, want ErrBlocked", err)
	}
	if guard.Trips() != 1 {
		t.Fatalf("egress tripwire probe trips = %d, want 1", guard.Trips())
	}
	guard.ResetTrips()

	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.EgressGuard = guard
	})
	if !h.srv.AirGapEnabled() {
		t.Fatal("served control plane did not retain the product-wide egress guard")
	}

	token := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "airgap-operator", []string{
		string(authz.OwnersWrite),
		string(authz.IdentitiesWrite),
		string(authz.CertsIssue),
		string(authz.CertsRead),
		string(authz.SecretsRead),
		string(authz.SecretsWrite),
	})
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/owners", token, map[string]any{
		"kind": "workload",
		"name": "airgap-payments",
	})
	if status != http.StatusCreated {
		t.Fatalf("create owner: status %d body %s", status, body)
	}
	var owner struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &owner); err != nil {
		t.Fatalf("decode owner: %v", err)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities", token, map[string]any{
		"kind":     "x509_certificate",
		"name":     "offline-api.internal",
		"owner_id": owner.ID,
	})
	if status != http.StatusCreated {
		t.Fatalf("create identity: status %d body %s", status, body)
	}
	var ident struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &ident); err != nil {
		t.Fatalf("decode identity: %v", err)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities/"+ident.ID+"/transitions", token, map[string]any{
		"to":     "issued",
		"reason": "COMP-03 offline issuance",
	})
	if status != http.StatusOK {
		t.Fatalf("issue identity: status %d body %s", status, body)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain issuance outbox: %v", err)
	}
	if !h.hasEvent(t, "certificate.recorded") {
		t.Fatal("offline served issuance did not record a certificate")
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", token, map[string]any{
		"name":  "offline/db/password",
		"value": "offline-secret-v1",
	})
	if status != http.StatusCreated {
		t.Fatalf("create secret: status %d body %s", status, body)
	}
	status, body = secretsReq(t, h, http.MethodPut, "/api/v1/secrets/store/offline/db/password", token, map[string]any{
		"value": "offline-secret-v2",
	})
	if status != http.StatusOK {
		t.Fatalf("rotate secret: status %d body %s", status, body)
	}
	if !h.hasEvent(t, "secret.created") || !h.hasEvent(t, "secret.rotated") {
		t.Fatal("offline secret management did not emit the expected events")
	}
	if trips := guard.Trips(); trips != 0 {
		t.Fatalf("offline issue+secret path attempted %d outbound egress call(s); want 0", trips)
	}
}
