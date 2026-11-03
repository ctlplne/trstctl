// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/ca/digicert"
	"trstctl.com/trstctl/internal/ca/digicert/digicertfake"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/acm"
	"trstctl.com/trstctl/internal/connector/acm/acmtest"
)

// A244 Done-when: an unfamiliar operator imports a certificate, assigns an
// owner, selects an external CA, deploys and renews twice without losing the
// CA selection; the application view shows the exact issuer, where the
// certificate goes and what was seen, and the inventory distinguishes issued
// from delivered or served (revoked and retired are proven beside it).
func TestServedApplicationViewKeepsTheExternalCAThroughTwoRenewalsA244(t *testing.T) {
	const (
		awsAccessKey = "AKIDA244"
		awsSecretKey = "A244SecretKeyForSigV4Only" // #nosec G101 -- fabricated test-only credential (CWE-798)
		acmARN       = "arn:aws:acm:us-east-1:123456789012:certificate/a244"
		hostname     = "a244-app.served.test"
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
			ID: "a244-digicert", Type: "digicert", Name: "Corporate DigiCert (A244)",
			CA: digicert.New("a244-digicert", dc.URL(), []byte(dc.APIKey()), digicert.WithHTTPClient(&http.Client{Timeout: 5 * time.Second})),
		}}
	})
	tok := seedScopedToken(t, h.store, h.tenant, "owners:read", "owners:write", "identities:read", "identities:write",
		"certs:read", "certs:write", "certs:issue", "certs:revoke", "connectors:read", "connectors:write", "lifecycle:read")
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

	// The operator finds the certificate the application serves today.
	post("/api/v1/certificates", "a244-import", map[string]any{"pem": servedCloudCertPEM(t, hostname), "source": "import"})
	owner := post("/api/v1/owners", "a244-owner", map[string]any{"kind": "workload", "name": "a244-orders-app"})
	target := post("/api/v1/connectors/targets", "a244-target", map[string]any{
		"name": acmARN, "connector": "aws-acm", "enabled": true,
		"config": map[string]any{"region": "us-east-1", "access_key_id": awsAccessKey, "secret_access_key_ref": "secret://connectors/aws-acm/a244"},
	})
	request := map[string]any{
		"owner_id": owner["id"], "identity_name": hostname, "target_id": target["id"],
		"issuer": map[string]any{"source": "external", "id": "a244-digicert"}, "reason": "A244 application journey",
	}
	preview := post("/api/v1/lifecycle/endpoint-bindings/preview", "", request)
	request["preview_fingerprint"] = preview["request_fingerprint"]
	binding := post("/api/v1/lifecycle/endpoint-bindings", "a244-bind", request)
	identityID := binding["identity"].(map[string]any)["id"].(string)

	view := func(stage string) map[string]any {
		t.Helper()
		status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/identities/"+identityID+"/application", tok, nil)
		if status != http.StatusOK {
			t.Fatalf("%s: application view %d %s", stage, status, raw)
		}
		var out map[string]any
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatal(err)
		}
		issuer := out["issuer"].(map[string]any)
		if issuer["source"] != "external" || issuer["id"] != "a244-digicert" {
			t.Fatalf("%s: the CA selection was lost: %v", stage, issuer)
		}
		if out["destination"].(map[string]any)["connector"] != "aws-acm" || out["owner"].(map[string]any)["name"] != "a244-orders-app" {
			t.Fatalf("%s: destination/owner = %v / %v", stage, out["destination"], out["owner"])
		}
		return out
	}
	before := view("before issuance")
	if before["inventory_state"] != "issued" && before["inventory_state"] != "requested" {
		t.Fatalf("before issuance the inventory reads %v", before["inventory_state"])
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain issue and deploy: %v", err)
	}
	serials := map[string]bool{}
	// ACM takes the certificate but reads nothing back, so each deploy reads
	// delivered until something sees an endpoint present the certificate.
	check := func(stage string) {
		t.Helper()
		v := view(stage)
		cert := v["certificate"].(map[string]any)
		issuer := v["issuer"].(map[string]any)
		if !strings.Contains(strings.ToLower(issuer["certificate_issuer"].(string)), "digicert") {
			t.Fatalf("%s: the exact issuer is %v", stage, issuer["certificate_issuer"])
		}
		if state := v["inventory_state"]; state != "delivered" || v["served"] != nil {
			t.Fatalf("%s: the inventory reads %v (served evidence %v) after the deploy", stage, state, v["served"])
		}
		dest := v["destination"].(map[string]any)
		if dest["last_delivery_fingerprint"] != cert["fingerprint"] {
			t.Fatalf("%s: the delivery is not of the active certificate: %v vs %v", stage, dest["last_delivery_fingerprint"], cert["fingerprint"])
		}
		if serials[cert["serial"].(string)] {
			t.Fatalf("%s: the serial did not change", stage)
		}
		serials[cert["serial"].(string)] = true
		if len(v["actions"].([]any)) != 3 || v["renewal"].(map[string]any)["next_action"] == "" {
			t.Fatalf("%s: actions/renewal = %v / %v", stage, v["actions"], v["renewal"])
		}
	}
	check("after the first deploy")

	// A relay agent sees the endpoint present the active certificate: the
	// inventory moves to served, with the vantage that saw it.
	active, err := h.store.ListActiveIssuedCertificatesForIdentity(t.Context(), h.tenant, owner["id"].(string), hostname)
	if err != nil || len(active) != 1 || active[0].NotBefore == nil || active[0].NotAfter == nil {
		t.Fatalf("active certificate = %+v %v", active, err)
	}
	observed := transport.ProbeTranscript{Address: "127.0.0.1:443", ServerName: hostname, Vantage: transport.VantageRelay, Reached: true,
		ExpectedFingerprint: active[0].Fingerprint, ObservedFingerprint: active[0].Fingerprint,
		NotBeforeUnix: active[0].NotBefore.Unix(), NotAfterUnix: active[0].NotAfter.Unix(), ObservedAtUnix: time.Now().Unix()}
	if err := h.srv.appendEndpointVerification(t.Context(), h.tenant, "a244-relay", "a244-orders-endpoint", observed, ""); err != nil {
		t.Fatalf("record the relay observation: %v", err)
	}
	seen := view("after a relay saw it")
	// The value-free review plan names what the next renewal acts on: the CA,
	// the destination and the vantage that saw it last.
	plan, _ := json.Marshal(seen["review_plan"])
	if want := `[{"action":"issue","subject":"external:a244-digicert"},{"action":"deploy","subject":"` + acmARN + ` (aws-acm)"},{"action":"verify","subject":"relay"}]`; string(plan) != want {
		t.Fatalf("review plan = %s, want %s", plan, want)
	}
	if served, _ := seen["served"].(map[string]any); seen["inventory_state"] != "served" || served == nil || served["vantage"] != "relay" ||
		served["matches_current"] != true || served["fingerprint"] != active[0].Fingerprint {
		t.Fatalf("after a relay saw the certificate the view reads %v / %v", seen["inventory_state"], seen["served"])
	}

	// Two renewals, each inside the certificate's signed renewal window. Each
	// renewal's new certificate reads delivered again: the relay saw the old one.
	for round := 1; round <= 2; round++ {
		certs, err := h.store.ListActiveIssuedCertificatesForIdentity(t.Context(), h.tenant, owner["id"].(string), hostname)
		if err != nil || len(certs) != 1 || certs[0].NotBefore == nil || certs[0].NotAfter == nil {
			t.Fatalf("round %d: active certificate = %+v %v", round, certs, err)
		}
		window := certs[0].NotAfter.Add(-certs[0].NotAfter.Sub(*certs[0].NotBefore) / 3)
		if queued, err := h.srv.runLifecycleOnceAt(t.Context(), window.Add(time.Second)); err != nil || queued != 1 {
			t.Fatalf("round %d: schedule renewal: queued=%d err=%v", round, queued, err)
		}
		if err := h.srv.Drain(t.Context()); err != nil {
			t.Fatalf("round %d: drain renewal: %v", round, err)
		}
		check("after renewal " + string(rune('0'+round)))
	}

	// The inventory lists the state too.
	listed := func() string {
		t.Helper()
		status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/identities?q="+hostname, tok, nil)
		if status != http.StatusOK {
			t.Fatalf("identity list: %d %s", status, raw)
		}
		var list struct {
			Items []struct {
				ID             string `json:"id"`
				InventoryState string `json:"inventory_state"`
			} `json:"items"`
		}
		if err := json.Unmarshal(raw, &list); err != nil {
			t.Fatal(err)
		}
		for _, item := range list.Items {
			if item.ID == identityID {
				return item.InventoryState
			}
		}
		t.Fatalf("identity list misses %s: %s", identityID, raw)
		return ""
	}
	if state := listed(); state != "delivered" {
		t.Fatalf("the inventory lists %q after the renewals", state)
	}
	// Revoked and retired read as such, with the revoke and retire actions
	// following the state.
	for _, step := range []struct{ to, want string }{{"revoked", "revoked"}, {"retired", "retired"}} {
		post("/api/v1/identities/"+identityID+"/transitions", "a244-"+step.to, map[string]any{"to": step.to, "reason": "cessationOfOperation"})
		if err := h.srv.Drain(t.Context()); err != nil {
			t.Fatalf("drain %s: %v", step.to, err)
		}
		if state := listed(); state != step.want {
			t.Fatalf("after %s the inventory lists %q", step.to, state)
		}
	}
	status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/identities/"+identityID+"/application", tok, nil)
	if status != http.StatusOK || !strings.Contains(string(raw), `"inventory_state":"retired"`) ||
		!strings.Contains(string(raw), `{"action":"retire","available":false`) {
		t.Fatalf("the retired application view: %d %s", status, raw)
	}
}
