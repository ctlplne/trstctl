// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/ca/digicert"
	"trstctl.com/trstctl/internal/ca/digicert/digicertfake"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/acm"
	"trstctl.com/trstctl/internal/connector/acm/acmtest"
)

// TestServedDestinationIsVerifiedWithoutAPriorObservationA244L1 is A244-L1. A
// cloud certificate store reads nothing back, so a certificate delivered there
// read delivered until something observed an endpoint presenting it, and the
// verification scheduler only re-probed endpoints already observed. Now:
//   - a destination whose target names its endpoint (verify_address) gets a
//     first probe, expecting the certificate delivered there, with the
//     target's connector and server name; a destination naming none gets no
//     probe (no address is guessed), and its application view says nothing
//     checks it;
//   - when the probe observes the certificate, the identity reads served,
//     and the destination is no longer awaiting a first probe (the normal loop
//     re-verifies it from then on).
func TestServedDestinationIsVerifiedWithoutAPriorObservationA244L1(t *testing.T) {
	const (
		awsAccessKey  = "AKIDA244L1"
		awsSecretKey  = "A244L1SecretKeyForSigV4Only" // #nosec G101 -- fabricated test-only credential (CWE-798)
		checkedARN    = "arn:aws:acm:us-east-1:123456789012:certificate/a244l1-checked"
		uncheckedARN  = "arn:aws:acm:us-east-1:123456789012:certificate/a244l1-unchecked"
		checkedHost   = "a244l1-checked.served.test"
		uncheckedHost = "a244l1-unchecked.served.test"
		listener      = "10.20.30.40:443"
	)
	provider := acmtest.New(awsAccessKey, awsSecretKey)
	t.Cleanup(provider.Close)
	registry := connector.NewRegistry(func(string) connector.Ops { return connector.NewHTTPOps(provider.Client()) })
	registry.Register(acm.New("us-east-1", acm.Credentials{AccessKeyID: awsAccessKey, SecretAccessKey: []byte(awsSecretKey)},
		acm.WithEndpoint(provider.URL())))
	dc, err := digicertfake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dc.Close)
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.LifecycleRenewBefore = 31 * 24 * time.Hour
		d.ConnectorRegistry = registry
		d.ExternalCAs = []ExternalCA{{
			ID: "a244l1-digicert", Type: "digicert", Name: "Corporate DigiCert (A244-L1)",
			CA: digicert.New("a244l1-digicert", dc.URL(), []byte(dc.APIKey()), digicert.WithHTTPClient(&http.Client{Timeout: 5 * time.Second})),
		}}
	})
	tok := seedScopedToken(t, h.store, h.tenant, "owners:read", "owners:write", "identities:read", "identities:write",
		"certs:read", "certs:write", "certs:issue", "connectors:read", "connectors:write", "lifecycle:read")
	post := func(path, key string, body any) map[string]any {
		t.Helper()
		status, raw := secretsReqKey(t, h, http.MethodPost, path, tok, key, body)
		if status != http.StatusCreated && status != http.StatusOK {
			t.Fatalf("POST %s: %d %s", path, status, raw)
		}
		var out map[string]any
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
		return out
	}
	owner := post("/api/v1/owners", "a244l1-owner", map[string]any{"kind": "workload", "name": "a244l1-orders-app"})
	bind := func(name, arn, host string, verify map[string]any) (targetID, identityID string) {
		t.Helper()
		cfg := map[string]any{"region": "us-east-1", "access_key_id": awsAccessKey, "secret_access_key_ref": "secret://connectors/aws-acm/a244l1"}
		for k, v := range verify {
			cfg[k] = v
		}
		target := post("/api/v1/connectors/targets", "a244l1-target-"+name, map[string]any{"name": arn, "connector": "aws-acm", "enabled": true, "config": cfg})
		request := map[string]any{
			"owner_id": owner["id"], "identity_name": host, "target_id": target["id"],
			"issuer": map[string]any{"source": "external", "id": "a244l1-digicert"}, "reason": "A244-L1 first verification",
		}
		preview := post("/api/v1/lifecycle/endpoint-bindings/preview", "", request)
		request["preview_fingerprint"] = preview["request_fingerprint"]
		binding := post("/api/v1/lifecycle/endpoint-bindings", "a244l1-bind-"+name, request)
		return target["id"].(string), binding["identity"].(map[string]any)["id"].(string)
	}
	checkedTarget, checkedIdentity := bind("checked", checkedARN, checkedHost, map[string]any{"verify_address": listener, "verify_server_name": checkedHost})
	_, uncheckedIdentity := bind("unchecked", uncheckedARN, uncheckedHost, nil)
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain issue and deploy: %v", err)
	}
	view := func(identityID string) map[string]any {
		t.Helper()
		status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/identities/"+identityID+"/application", tok, nil)
		if status != http.StatusOK {
			t.Fatalf("application view %d %s", status, raw)
		}
		var out map[string]any
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	checked, unchecked := view(checkedIdentity), view(uncheckedIdentity)
	for name, v := range map[string]map[string]any{"checked": checked, "unchecked": unchecked} {
		if v["inventory_state"] != "delivered" || v["served"] != nil {
			t.Fatalf("%s after the deploy reads %v (served %v)", name, v["inventory_state"], v["served"])
		}
	}
	fingerprint := checked["certificate"].(map[string]any)["fingerprint"].(string)

	// The scheduler's sweep probes the checked destination for the first time.
	if n, err := h.srv.RunEndpointVerificationOnce(t.Context()); err != nil || n != 1 {
		t.Fatalf("the sweep queued %d endpoints (%v), want the one destination that names its endpoint", n, err)
	}
	var payload []byte
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(), `SELECT payload FROM outbox WHERE tenant_id = $1 AND destination = $2`, h.tenant, relay.KindEndpointVerify).Scan(&payload)
	}); err != nil {
		t.Fatal(err)
	}
	var intent relay.EndpointVerifyIntent
	if err := json.Unmarshal(payload, &intent); err != nil || len(intent.Endpoints) != 1 {
		t.Fatalf("the sweep's job = %s (%v)", payload, err)
	}
	if want := intent.Endpoints[0]; want.EndpointID != checkedTarget || want.Address != listener || want.Fingerprint != fingerprint ||
		want.Connector != "aws-acm" || want.ServerName != checkedHost {
		t.Fatalf("the first probe's expectation = %+v, want target %s at %s expecting %s", want, checkedTarget, listener, fingerprint)
	}

	// The view says which destination is checked, and which nothing checks.
	if got := checked["destination"].(map[string]any)["verify_address"]; got != listener {
		t.Fatalf("the checked destination's verify_address = %v", got)
	}
	if got, ok := unchecked["destination"].(map[string]any)["verify_address"]; ok {
		t.Fatalf("the unchecked destination names an address: %v", got)
	}

	// The relay observes the certificate there: served, and no longer awaiting.
	active, err := h.store.ListActiveIssuedCertificatesForIdentity(t.Context(), h.tenant, owner["id"].(string), checkedHost)
	if err != nil || len(active) != 1 || active[0].NotBefore == nil || active[0].NotAfter == nil {
		t.Fatalf("active certificate = %+v %v", active, err)
	}
	observed := transport.ProbeTranscript{Address: listener, ServerName: checkedHost, Vantage: transport.VantageRelay, Reached: true,
		ExpectedFingerprint: fingerprint, ObservedFingerprint: fingerprint,
		NotBeforeUnix: active[0].NotBefore.Unix(), NotAfterUnix: active[0].NotAfter.Unix(), ObservedAtUnix: time.Now().Unix()}
	if err := h.srv.appendEndpointVerification(t.Context(), h.tenant, "a244l1-relay", checkedTarget, observed, ""); err != nil {
		t.Fatalf("record the relay observation: %v", err)
	}
	if v := view(checkedIdentity); v["inventory_state"] != "served" || v["served"].(map[string]any)["vantage"] != "relay" {
		t.Fatalf("after the first probe saw it the inventory reads %v (%v)", v["inventory_state"], v["served"])
	}
	// The endpoint now has a verification expecting the delivered certificate,
	// so it rides the normal re-verification loop rather than a first probe.
	var recorded int
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(), `SELECT count(*) FROM endpoint_verifications WHERE tenant_id = $1 AND endpoint_id = $2 AND expected_fingerprint = $3`,
			h.tenant, checkedTarget, fingerprint).Scan(&recorded)
	}); err != nil || recorded != 1 {
		t.Fatalf("verifications of the checked destination = %d (%v), want 1", recorded, err)
	}
	if v := view(uncheckedIdentity); v["inventory_state"] != "delivered" {
		t.Fatalf("the unchecked destination reads %v", v["inventory_state"])
	}
	t.Logf("A244L1_FIRST_VERIFICATION_OK target=%s fingerprint=%s", checkedTarget, fingerprint)
}
