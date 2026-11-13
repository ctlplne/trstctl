// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/acm"
	"trstctl.com/trstctl/internal/connector/acm/acmtest"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// A245-L2 Done-when (served, report): a revoked certificate's existing
// sessions read from the hosts' own counts. Once its destination serves a
// replacement, the report reads not observed until the host counts the
// listener's sessions after that deploy; pending, naming the destination,
// while a process older than the deploy holds a connection; confirmed once a
// later count finds none; and a projection rebuild reads the same.
func TestServedRevocationReportReadsListenerSessionsA245L2(t *testing.T) {
	const (
		awsAccessKey = "AKIDA245S"
		awsSecretKey = "A245SessionsKeyForSigV4Only" // #nosec G101 -- fabricated test-only credential (CWE-798)
		acmARN       = "arn:aws:acm:us-east-1:123456789012:certificate/a245s"
		hostname     = "a245-sessions.served.test"
	)
	provider := acmtest.New(awsAccessKey, awsSecretKey)
	t.Cleanup(provider.Close)
	registry := connector.NewRegistry(func(string) connector.Ops { return connector.NewHTTPOps(provider.Client()) })
	registry.Register(acm.New("us-east-1", acm.Credentials{AccessKeyID: awsAccessKey, SecretAccessKey: []byte(awsSecretKey)},
		acm.WithEndpoint(provider.URL())))
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) { d.ConnectorRegistry = registry })
	ctx := t.Context()
	tok := seedScopedToken(t, h.store, h.tenant, "owners:write", "identities:read", "identities:write", "certs:read",
		"certs:write", "certs:issue", "certs:revoke", "connectors:read", "connectors:write", "lifecycle:read")
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
	owner := post("/api/v1/owners", "a245s-owner", map[string]any{"kind": "workload", "name": "a245-sessions-app"})
	target := post("/api/v1/connectors/targets", "a245s-target", map[string]any{
		"name": acmARN, "connector": "aws-acm", "enabled": true,
		"config": map[string]any{"region": "us-east-1", "access_key_id": awsAccessKey, "secret_access_key_ref": "secret://connectors/aws-acm/a245s"},
	})
	request := map[string]any{"owner_id": owner["id"], "identity_name": hostname, "target_id": target["id"], "reason": "A245-L2 sessions",
		"issuer": map[string]any{"source": "platform", "id": "trstctl-issuing-ca"}}
	preview := post("/api/v1/lifecycle/endpoint-bindings/preview", "", request)
	request["preview_fingerprint"] = preview["request_fingerprint"]
	identityID := post("/api/v1/lifecycle/endpoint-bindings", "a245s-bind", request)["identity"].(map[string]any)["id"].(string)
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain issue and deploy: %v", err)
	}
	post("/api/v1/identities/"+identityID+"/transitions", "a245s-revoke", map[string]any{"to": "revoked", "reason": "superseded"})
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain revoke: %v", err)
	}
	type facet struct {
		State  string `json:"state"`
		Detail string `json:"detail"`
	}
	report := func(stage string) (facet, string, []byte) {
		t.Helper()
		status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/identities/"+identityID+"/revocation-report", tok, nil)
		var out struct {
			Certificates []struct {
				ExistingSessions facet `json:"existing_sessions"`
				Destinations     []struct {
					Target string `json:"target"`
					Now    string `json:"now"`
				} `json:"destinations"`
			} `json:"certificates"`
		}
		if status != http.StatusOK || json.Unmarshal(raw, &out) != nil || len(out.Certificates) != 1 || len(out.Certificates[0].Destinations) != 1 {
			t.Fatalf("%s: report %d %s", stage, status, raw)
		}
		c := out.Certificates[0]
		return c.ExistingSessions, c.Destinations[0].Target, raw
	}
	sessions, destination, _ := report("after the revocation")
	if sessions.State != "not_observed" {
		t.Fatalf("before any replacement: %+v", sessions)
	}

	// The destination now serves a replacement certificate.
	replacement := strings.Repeat("b2", 32)
	id, deliveryRef := identityID, "a245s-replacement"
	if _, err := h.srv.orch.RecordConnectorDelivery(ctx, h.tenant, store.ConnectorDeliveryReceipt{IdentityID: &id,
		Destination: "connector.deploy", Connector: "aws-acm", Target: destination, Fingerprint: replacement,
		Status: "verified", Reason: "endpoint_serving_deployed_identity", IdempotencyKey: deliveryRef}); err != nil {
		t.Fatal(err)
	}
	if sessions, _, _ := report("replaced, not counted"); sessions.State != "not_observed" || !strings.Contains(sessions.Detail, "0 of 1") {
		t.Fatalf("a replacement nobody counted: %+v", sessions)
	}
	count := func(key string, older int, checked time.Time) {
		t.Helper()
		if err := h.srv.orch.RecordListenerSessionsWithEventID(ctx, h.tenant, "a245s-"+key, projections.ListenerSessionsObserved{
			ID: "a245s-" + key, IdentityID: &id, TargetID: "a245s-endpoint", Target: destination, Fingerprint: replacement,
			Port: 443, Established: 2, HeldByOlder: older, SinceUnix: checked.Add(-time.Minute).Unix(), CheckedAtUnix: checked.Unix(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	count("old-worker", 1, now.Add(-time.Minute))
	if sessions, _, _ := report("an old worker drains"); sessions.State != "pending" || !strings.Contains(sessions.Detail, "1 on "+destination) {
		t.Fatalf("an older process still holding a connection: %+v", sessions)
	}
	count("drained", 0, now)
	confirmed, _, before := report("drained")
	if confirmed.State != "confirmed" || !strings.Contains(confirmed.Detail, "on all 1 destinations") {
		t.Fatalf("after the old worker exited: %+v", confirmed)
	}
	if err := projections.New(h.store).Rebuild(ctx, h.log); err != nil {
		t.Fatalf("rebuild projections: %v", err)
	}
	if _, _, after := report("rebuilt"); string(after) != string(before) {
		t.Fatalf("a rebuild changed the report:\n before %s\n after  %s", before, after)
	}
	t.Logf("A245L2_SESSIONS_REPORT_OK destination=%s", destination)
}
