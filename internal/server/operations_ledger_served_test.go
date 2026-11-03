// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/acm"
	"trstctl.com/trstctl/internal/connector/acm/acmtest"
)

type servedOperation struct {
	ID              string `json:"id"`
	Source          string `json:"source"`
	CredentialType  string `json:"credential_type"`
	State           string `json:"state"`
	StateReason     string `json:"state_reason"`
	SourceStatus    string `json:"source_status"`
	Fingerprint     string `json:"fingerprint"`
	ObservedVantage string `json:"observed_vantage"`
	Subject         struct {
		ID string `json:"id"`
	} `json:"subject"`
}

// A245 (part 1): the operations ledger reads deliveries and rotations from
// their projections in one normalized state. A cloud certificate store takes a
// certificate but reads nothing back, so the delivery reads delivered, not
// verified, until an endpoint is seen presenting it; a renewal's rotation reads
// delivered until its new certificate is seen; paging returns every row once.
func TestServedOperationsLedgerNeedsConsumerEvidenceA245(t *testing.T) {
	const (
		awsAccessKey = "AKIDA245"
		awsSecretKey = "A245SecretKeyForSigV4Only" // #nosec G101 -- fabricated test-only credential (CWE-798)
		acmARN       = "arn:aws:acm:us-east-1:123456789012:certificate/a245"
		hostname     = "a245-ops.served.test"
	)
	provider := acmtest.New(awsAccessKey, awsSecretKey)
	t.Cleanup(provider.Close)
	registry := connector.NewRegistry(func(string) connector.Ops { return connector.NewHTTPOps(provider.Client()) })
	registry.Register(acm.New("us-east-1", acm.Credentials{AccessKeyID: awsAccessKey, SecretAccessKey: []byte(awsSecretKey)},
		acm.WithEndpoint(provider.URL())))
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.LifecycleRenewBefore = 31 * 24 * time.Hour
		d.ConnectorRegistry = registry
	})
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
	owner := post("/api/v1/owners", "a245-owner", map[string]any{"kind": "workload", "name": "a245-ops-app"})
	target := post("/api/v1/connectors/targets", "a245-target", map[string]any{
		"name": acmARN, "connector": "aws-acm", "enabled": true,
		"config": map[string]any{"region": "us-east-1", "access_key_id": awsAccessKey, "secret_access_key_ref": "secret://connectors/aws-acm/a245"},
	})
	request := map[string]any{"owner_id": owner["id"], "identity_name": hostname, "target_id": target["id"], "reason": "A245 operations",
		"issuer": map[string]any{"source": "platform", "id": "trstctl-issuing-ca"}}
	preview := post("/api/v1/lifecycle/endpoint-bindings/preview", "", request)
	request["preview_fingerprint"] = preview["request_fingerprint"]
	binding := post("/api/v1/lifecycle/endpoint-bindings", "a245-bind", request)
	identityID := binding["identity"].(map[string]any)["id"].(string)
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain issue and deploy: %v", err)
	}

	// Every page, cursor by cursor; no row twice.
	ledger := func(stage string) []servedOperation {
		t.Helper()
		var all []servedOperation
		seen := map[string]bool{}
		cursor := ""
		for page := 0; page < 50; page++ {
			q := url.Values{"limit": {"1"}}
			if cursor != "" {
				q.Set("cursor", cursor)
			}
			status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/operations/ledger?"+q.Encode(), tok, nil)
			if status != http.StatusOK {
				t.Fatalf("%s: ledger %d %s", stage, status, raw)
			}
			var out struct {
				Items      []servedOperation `json:"items"`
				NextCursor string            `json:"next_cursor"`
			}
			if err := json.Unmarshal(raw, &out); err != nil {
				t.Fatal(err)
			}
			for _, item := range out.Items {
				if seen[item.ID] {
					t.Fatalf("%s: %s came back on two pages", stage, item.ID)
				}
				seen[item.ID] = true
				all = append(all, item)
			}
			if out.NextCursor == "" {
				return all
			}
			cursor = out.NextCursor
		}
		t.Fatalf("%s: the ledger did not end within 50 pages", stage)
		return nil
	}
	deliveries := func(ops []servedOperation) []servedOperation {
		var out []servedOperation
		for _, op := range ops {
			if op.Source == "connector_delivery" && op.Subject.ID == identityID {
				out = append(out, op)
			}
		}
		return out
	}
	first := deliveries(ledger("after the deploy"))
	if len(first) != 1 || first[0].State != "delivered" || first[0].SourceStatus != "delivered" || first[0].CredentialType != "x509_certificate" {
		t.Fatalf("a delivery the store accepted but nothing saw must read delivered: %+v", first)
	}

	// A relay agent sees the endpoint present it: verified, with the vantage.
	active, err := h.store.ListActiveIssuedCertificatesForIdentity(t.Context(), h.tenant, owner["id"].(string), hostname)
	if err != nil || len(active) != 1 || active[0].NotBefore == nil || active[0].NotAfter == nil {
		t.Fatalf("active certificate = %+v %v", active, err)
	}
	observed := transport.ProbeTranscript{Address: "127.0.0.1:443", ServerName: hostname, Vantage: transport.VantageRelay, Reached: true,
		ExpectedFingerprint: active[0].Fingerprint, ObservedFingerprint: active[0].Fingerprint,
		NotBeforeUnix: active[0].NotBefore.Unix(), NotAfterUnix: active[0].NotAfter.Unix(), ObservedAtUnix: time.Now().Unix()}
	if err := h.srv.appendEndpointVerification(t.Context(), h.tenant, "a245-relay", "a245-endpoint", observed, ""); err != nil {
		t.Fatal(err)
	}
	if seen := deliveries(ledger("after a relay saw it")); len(seen) != 1 || seen[0].State != "verified" || seen[0].ObservedVantage != "relay" {
		t.Fatalf("a delivery seen at an endpoint must read verified: %+v", seen)
	}

	// A renewal: its rotation and its new delivery read delivered until seen.
	window := active[0].NotAfter.Add(-active[0].NotAfter.Sub(*active[0].NotBefore) / 3)
	if queued, err := h.srv.runLifecycleOnceAt(t.Context(), window.Add(time.Second)); err != nil || queued != 1 {
		t.Fatalf("schedule renewal: queued=%d err=%v", queued, err)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain renewal: %v", err)
	}
	ops := ledger("after the renewal")
	var rotation *servedOperation
	for i := range ops {
		if ops[i].Source == "certificate_rotation" && ops[i].Subject.ID == identityID {
			rotation = &ops[i]
		}
	}
	if rotation == nil || rotation.SourceStatus != "succeeded" || rotation.State != "delivered" || rotation.Fingerprint == active[0].Fingerprint {
		t.Fatalf("the renewal's rotation = %+v", rotation)
	}
	states := map[string]int{}
	for _, d := range deliveries(ops) {
		states[d.State]++
	}
	if states["verified"] != 1 || states["delivered"] != 1 {
		t.Fatalf("after the renewal the deliveries read %v, want the old one verified and the new one delivered", states)
	}
	// A filter by state applies to the normalized state.
	status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/operations/ledger?state=verified&limit=100", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("filtered ledger: %d %s", status, raw)
	}
	var filtered struct {
		Items []servedOperation `json:"items"`
	}
	if err := json.Unmarshal(raw, &filtered); err != nil {
		t.Fatal(err)
	}
	for _, item := range filtered.Items {
		if item.State != "verified" {
			t.Fatalf("state=verified returned %+v", item)
		}
	}
	if status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/operations/ledger?state=green", tok, nil); status != http.StatusBadRequest {
		t.Fatalf("an unknown state filter: %d %s", status, raw)
	}
}
