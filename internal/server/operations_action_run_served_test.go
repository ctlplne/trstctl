// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/acm"
	"trstctl.com/trstctl/internal/connector/acm/acmtest"
)

// TestServedOperationActionCarriesTheRequestItRunsA245L4 is A245-L4. An
// operation's available actions carry the exact request they send (and the
// route that reviews it, when one exists), so the console runs them in place
// rather than linking elsewhere. A failed delivery's retry names its target's
// deploy route with the identity; sending exactly that request starts a new
// delivery through the route (its own checks and approval apply). A delivery
// that did not fail offers no retry and no request.
func TestServedOperationActionCarriesTheRequestItRunsA245L4(t *testing.T) {
	const (
		awsAccessKey = "AKIDA245L4"
		awsSecretKey = "A245L4KeyForSigV4Only" // #nosec G101 -- fabricated test-only credential (CWE-798)
	)
	provider := acmtest.New(awsAccessKey, awsSecretKey)
	t.Cleanup(provider.Close)
	registry := connector.NewRegistry(func(string) connector.Ops { return connector.NewHTTPOps(provider.Client()) })
	registry.Register(acm.New("us-east-1", acm.Credentials{AccessKeyID: awsAccessKey, SecretAccessKey: []byte(awsSecretKey)},
		acm.WithEndpoint(provider.URL())))
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) { d.ConnectorRegistry = registry })
	tok := seedScopedToken(t, h.store, h.tenant, "owners:write", "identities:read", "identities:write", "certs:read",
		"certs:write", "certs:issue", "connectors:read", "connectors:write", "lifecycle:read")
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
	owner := post("/api/v1/owners", "a245l4-owner", map[string]any{"kind": "workload", "name": "a245l4-app"})
	cloud := post("/api/v1/connectors/targets", "a245l4-cloud", map[string]any{
		"name": "arn:aws:acm:us-east-1:123456789012:certificate/a245l4", "connector": "aws-acm", "enabled": true,
		"config": map[string]any{"region": "us-east-1", "access_key_id": awsAccessKey, "secret_access_key_ref": "secret://connectors/aws-acm/a245l4"},
	})
	unreachable := post("/api/v1/connectors/targets", "a245l4-lb", map[string]any{
		"name": "a245l4/lb", "connector": "f5", "enabled": true,
		"config": map[string]any{"endpoint": "https://lb-a245l4.invalid", "partition": "Common"},
	})
	bind := func(name string, target map[string]any) string {
		t.Helper()
		request := map[string]any{"owner_id": owner["id"], "identity_name": name, "target_id": target["id"], "reason": "A245-L4 actions",
			"issuer": map[string]any{"source": "platform", "id": "trstctl-issuing-ca"}}
		preview := post("/api/v1/lifecycle/endpoint-bindings/preview", "", request)
		request["preview_fingerprint"] = preview["request_fingerprint"]
		return post("/api/v1/lifecycle/endpoint-bindings", "a245l4-bind-"+name, request)["identity"].(map[string]any)["id"].(string)
	}
	cloudID := bind("a245l4-cloud.served.test", cloud)
	lbID := bind("a245l4-lb.served.test", unreachable)
	_ = h.srv.Drain(t.Context()) // the load balancer's delivery fails

	type action struct {
		Action      string         `json:"action"`
		Available   bool           `json:"available"`
		Reason      string         `json:"reason"`
		Method      string         `json:"method"`
		Path        string         `json:"path"`
		Body        map[string]any `json:"body"`
		PreviewPath string         `json:"preview_path"`
	}
	deliveries := func() map[string][]servedOperation {
		t.Helper()
		status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/operations/ledger?source=connector_delivery&limit=100", tok, nil)
		if status != http.StatusOK {
			t.Fatalf("ledger %d %s", status, raw)
		}
		var page struct {
			Items []servedOperation `json:"items"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			t.Fatal(err)
		}
		out := map[string][]servedOperation{}
		for _, item := range page.Items {
			if item.Source == "connector_delivery" {
				out[item.Subject.ID] = append(out[item.Subject.ID], item)
			}
		}
		return out
	}
	actionsOf := func(opID string) map[string]action {
		t.Helper()
		status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/operations/ledger/"+opID, tok, nil)
		if status != http.StatusOK {
			t.Fatalf("operation %s: %d %s", opID, status, raw)
		}
		var detail struct {
			Actions []action `json:"actions"`
		}
		if err := json.Unmarshal(raw, &detail); err != nil {
			t.Fatal(err)
		}
		out := map[string]action{}
		for _, a := range detail.Actions {
			out[a.Action] = a
		}
		return out
	}
	before := deliveries()
	if len(before[lbID]) != 1 || before[lbID][0].State != "failed" || len(before[cloudID]) != 1 || before[cloudID][0].State != "delivered" {
		t.Fatalf("deliveries before the retry: %+v", before)
	}

	// The failed delivery's retry carries the request it sends. A delivery
	// can't be repeated (no private key is kept), so a deployed identity's
	// retry renews through its issuer and delivers the new certificate, and
	// names the preview that reviews that renewal.
	retry := actionsOf(before[lbID][0].ID)["retry"]
	if !retry.Available || retry.Method != http.MethodPost || retry.Path != "/api/v1/identities/"+lbID+"/transitions" ||
		retry.PreviewPath != "/api/v1/identities/"+lbID+"/transitions/preview" || retry.Body["to"] != "renewing" || retry.Body["reason"] == "" {
		t.Fatalf("the failed delivery's retry = %+v", retry)
	}
	// The preview reviews exactly that request without effects.
	if status, raw := secretsReqKey(t, h, http.MethodPost, retry.PreviewPath, tok, "", retry.Body); status != http.StatusOK {
		t.Fatalf("the retry's preview: %d %s", status, raw)
	}
	if rollback := actionsOf(before[lbID][0].ID)["rollback"]; rollback.Available || rollback.Body != nil || rollback.Reason == "" {
		t.Fatalf("a delivery with no predecessor offers rollback %+v", rollback)
	}
	// A delivery that did not fail offers no retry, and no request.
	if delivered := actionsOf(before[cloudID][0].ID)["retry"]; delivered.Available || delivered.Body != nil || delivered.Reason != "the delivery did not fail" {
		t.Fatalf("the delivered operation's retry = %+v", delivered)
	}

	// Sending exactly that request renews, and the new certificate is
	// delivered again through the route.
	status, raw := secretsReqKey(t, h, retry.Method, retry.Path, tok, "a245l4-retry", retry.Body)
	if status != http.StatusOK && status != http.StatusCreated && status != http.StatusAccepted {
		t.Fatalf("running the retry's request: %d %s", status, raw)
	}
	_ = h.srv.Drain(t.Context())
	if after := deliveries(); len(after[lbID]) != 2 {
		t.Fatalf("after the retry the load balancer has %d deliveries, want a second attempt: %+v", len(after[lbID]), after[lbID])
	}
	t.Logf("A245L4_ACTION_REQUEST_OK retry=%s %s", retry.Method, retry.Path)
}
