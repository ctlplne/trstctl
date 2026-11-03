// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/cli"
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
	// One operation's causal chain and its exactly scoped actions.
	status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/operations/ledger/"+rotation.ID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("rotation detail: %d %s", status, raw)
	}
	var detail struct {
		ID    string `json:"id"`
		State string `json:"state"`
		Chain []struct {
			Step, State, Detail string
		} `json:"chain"`
		Actions []struct {
			Action    string `json:"action"`
			Available bool   `json:"available"`
			Scope     string `json:"scope"`
			Path      string `json:"path"`
		} `json:"actions"`
	}
	if err := json.Unmarshal(raw, &detail); err != nil {
		t.Fatal(err)
	}
	steps := map[string]string{}
	for _, link := range detail.Chain {
		steps[link.Step] = link.State
	}
	if detail.ID != rotation.ID || detail.State != "delivered" || steps["request"] != "done" || steps["authority"] != "done" ||
		steps["external_action"] != "done" || steps["receipt"] != "done" || steps["observation"] != "not_observed" {
		t.Fatalf("the renewal's chain = %s", raw)
	}
	if len(detail.Actions) != 2 || detail.Actions[0].Action != "retry" || detail.Actions[0].Available ||
		!strings.Contains(detail.Actions[0].Scope, hostname) {
		t.Fatalf("a renewal that did not fail offers no retry, scoped to the identity: %s", raw)
	}
	for _, path := range []string{"/api/v1/operations/ledger/certificate_rotation:00000000-0000-0000-0000-000000000000",
		"/api/v1/operations/ledger/not-an-operation"} {
		if status, raw := secretsReq(t, h, http.MethodGet, path, tok, nil); status != http.StatusNotFound {
			t.Fatalf("GET %s: %d %s", path, status, raw)
		}
	}

	// A filter by state applies to the normalized state.
	status, raw = secretsReq(t, h, http.MethodGet, "/api/v1/operations/ledger?state=verified&limit=100", tok, nil)
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

// A245: a revocation report keeps the CA status, the deployed material, new
// connections and existing sessions apart. Revoking a certificate a cloud store
// still holds, that an endpoint still presents, reads exactly that; a CRL
// generation then confirms the CA status alone.
func TestServedRevocationReportSeparatesTheFourFacetsA245(t *testing.T) {
	const (
		awsAccessKey = "AKIDA245R"
		awsSecretKey = "A245RevokeKeyForSigV4Only" // #nosec G101 -- fabricated test-only credential (CWE-798)
		acmARN       = "arn:aws:acm:us-east-1:123456789012:certificate/a245r"
		hostname     = "a245-revoked.served.test"
	)
	provider := acmtest.New(awsAccessKey, awsSecretKey)
	t.Cleanup(provider.Close)
	registry := connector.NewRegistry(func(string) connector.Ops { return connector.NewHTTPOps(provider.Client()) })
	registry.Register(acm.New("us-east-1", acm.Credentials{AccessKeyID: awsAccessKey, SecretAccessKey: []byte(awsSecretKey)},
		acm.WithEndpoint(provider.URL())))
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) { d.ConnectorRegistry = registry })
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
	owner := post("/api/v1/owners", "a245r-owner", map[string]any{"kind": "workload", "name": "a245-revoked-app"})
	target := post("/api/v1/connectors/targets", "a245r-target", map[string]any{
		"name": acmARN, "connector": "aws-acm", "enabled": true,
		"config": map[string]any{"region": "us-east-1", "access_key_id": awsAccessKey, "secret_access_key_ref": "secret://connectors/aws-acm/a245r"},
	})
	request := map[string]any{"owner_id": owner["id"], "identity_name": hostname, "target_id": target["id"], "reason": "A245 revocation",
		"issuer": map[string]any{"source": "platform", "id": "trstctl-issuing-ca"}}
	preview := post("/api/v1/lifecycle/endpoint-bindings/preview", "", request)
	request["preview_fingerprint"] = preview["request_fingerprint"]
	identityID := post("/api/v1/lifecycle/endpoint-bindings", "a245r-bind", request)["identity"].(map[string]any)["id"].(string)
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain issue and deploy: %v", err)
	}
	active, err := h.store.ListActiveIssuedCertificatesForIdentity(t.Context(), h.tenant, owner["id"].(string), hostname)
	if err != nil || len(active) != 1 || active[0].NotBefore == nil || active[0].NotAfter == nil {
		t.Fatalf("active certificate = %+v %v", active, err)
	}
	observe := func(stage string, at time.Time) {
		t.Helper()
		tr := transport.ProbeTranscript{Address: "127.0.0.1:443", ServerName: hostname, Vantage: transport.VantageRelay, Reached: true,
			ExpectedFingerprint: active[0].Fingerprint, ObservedFingerprint: active[0].Fingerprint,
			NotBeforeUnix: active[0].NotBefore.Unix(), NotAfterUnix: active[0].NotAfter.Unix(), ObservedAtUnix: at.Unix()}
		if err := h.srv.appendEndpointVerification(t.Context(), h.tenant, "a245r-relay", "a245r-endpoint", tr, ""); err != nil {
			t.Fatalf("%s: %v", stage, err)
		}
	}
	observe("before the revocation", time.Now().Add(-time.Minute))
	post("/api/v1/identities/"+identityID+"/transitions", "a245r-revoke", map[string]any{"to": "revoked", "reason": "cessationOfOperation"})
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain revoke: %v", err)
	}
	type facet struct {
		State  string `json:"state"`
		Detail string `json:"detail"`
	}
	type certReport struct {
		Fingerprint      string `json:"fingerprint"`
		Reason           string `json:"reason"`
		CAStatus         facet  `json:"ca_status"`
		DeployedMaterial facet  `json:"deployed_material"`
		NewConnections   facet  `json:"new_connections"`
		ExistingSessions facet  `json:"existing_sessions"`
		Destinations     []struct {
			Now string `json:"now"`
		} `json:"destinations"`
	}
	report := func(stage string) certReport {
		t.Helper()
		status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/identities/"+identityID+"/revocation-report", tok, nil)
		if status != http.StatusOK {
			t.Fatalf("%s: report %d %s", stage, status, raw)
		}
		var out struct {
			Certificates []certReport `json:"certificates"`
		}
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatal(err)
		}
		if len(out.Certificates) != 1 || out.Certificates[0].Fingerprint != active[0].Fingerprint || out.Certificates[0].Reason != "cessationOfOperation" {
			t.Fatalf("%s: report = %s", stage, raw)
		}
		return out.Certificates[0]
	}
	r := report("after the revocation")
	if r.CAStatus.State != "pending" && r.CAStatus.State != "confirmed" {
		t.Fatalf("the CA status after a revocation reads %+v", r.CAStatus)
	}
	if r.DeployedMaterial.State != "pending" || len(r.Destinations) != 1 || r.Destinations[0].Now != "still_deployed" {
		t.Fatalf("the cloud store still holds it, but the report reads %+v %+v", r.DeployedMaterial, r.Destinations)
	}
	if r.NewConnections.State != "not_observed" || r.ExistingSessions.State != "not_observed" {
		t.Fatalf("an endpoint checked only before the revocation proves nothing: %+v / %+v", r.NewConnections, r.ExistingSessions)
	}
	// The endpoint still presents it after the revocation: new connections failed.
	observe("after the revocation", time.Now().Add(time.Second))
	if r := report("seen after the revocation"); r.NewConnections.State != "failed" || r.DeployedMaterial.State != "pending" {
		t.Fatalf("an endpoint still presenting it must read failed: %+v", r.NewConnections)
	}
	// A CRL generation confirms the CA status alone.
	if _, err := h.srv.GenerateCRL(t.Context(), h.tenant); err != nil {
		t.Fatalf("generate CRL: %v", err)
	}
	if r := report("after a CRL"); r.CAStatus.State != "confirmed" || r.NewConnections.State != "failed" || r.DeployedMaterial.State != "pending" {
		t.Fatalf("after a CRL: %+v / %+v / %+v", r.CAStatus, r.NewConnections, r.DeployedMaterial)
	}
}

// A245 Done-when: UI, API and CLI agree after a restart and a partial failure.
// One certificate deploys to a cloud store, another to a load balancer nobody
// can reach; the ledger reads one delivered and one failed, and a cold
// restart over the same datastores answers the same bytes to the API and the
// same items to the CLI.
func TestServedOperationsAgreeAcrossARestartAndAPartialFailureA245(t *testing.T) {
	const (
		awsAccessKey = "AKIDA245P"
		awsSecretKey = "A245PartialKeyForSigV4Only" // #nosec G101 -- fabricated test-only credential (CWE-798)
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
	owner := post("/api/v1/owners", "a245p-owner", map[string]any{"kind": "workload", "name": "a245-partial-app"})
	cloud := post("/api/v1/connectors/targets", "a245p-cloud", map[string]any{
		"name": "arn:aws:acm:us-east-1:123456789012:certificate/a245p", "connector": "aws-acm", "enabled": true,
		"config": map[string]any{"region": "us-east-1", "access_key_id": awsAccessKey, "secret_access_key_ref": "secret://connectors/aws-acm/a245p"},
	})
	unreachable := post("/api/v1/connectors/targets", "a245p-lb", map[string]any{
		"name": "a245p/lb", "connector": "f5", "enabled": true,
		"config": map[string]any{"endpoint": "https://lb-a245p.invalid", "partition": "Common"},
	})
	bind := func(name string, target map[string]any) string {
		t.Helper()
		request := map[string]any{"owner_id": owner["id"], "identity_name": name, "target_id": target["id"], "reason": "A245 partial failure",
			"issuer": map[string]any{"source": "platform", "id": "trstctl-issuing-ca"}}
		preview := post("/api/v1/lifecycle/endpoint-bindings/preview", "", request)
		request["preview_fingerprint"] = preview["request_fingerprint"]
		return post("/api/v1/lifecycle/endpoint-bindings", "a245p-bind-"+name, request)["identity"].(map[string]any)["id"].(string)
	}
	cloudID := bind("a245p-cloud.served.test", cloud)
	lbID := bind("a245p-lb.served.test", unreachable)
	_ = h.srv.Drain(t.Context()) // the load balancer's delivery fails; the drain reports it

	listBody := func(stage string, srv *servedHarness) []byte {
		t.Helper()
		status, raw := secretsReq(t, srv, http.MethodGet, "/api/v1/operations/ledger?limit=100", tok, nil)
		if status != http.StatusOK {
			t.Fatalf("%s: ledger %d %s", stage, status, raw)
		}
		return raw
	}
	states := func(raw []byte) map[string]string {
		t.Helper()
		var page struct {
			Items []servedOperation `json:"items"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, item := range page.Items {
			if item.Source == "connector_delivery" {
				out[item.Subject.ID] = item.State
			}
		}
		return out
	}
	before := listBody("before the restart", h)
	if got := states(before); got[cloudID] != "delivered" || got[lbID] != "failed" {
		t.Fatalf("the partial failure reads %v, want the cloud delivery delivered and the load balancer's failed", got)
	}

	// A cold restart over the same PostgreSQL, events and signer.
	restarted, err := Build(t.Context(), Deps{Store: h.store, Log: h.log, Signer: h.signer, SignAuthorizer: h.authz,
		CACertFile: h.caFile, KEK: h.kek, ConnectorRegistry: registry})
	if err != nil {
		t.Fatalf("restart assembly: %v", err)
	}
	cleanupServedServer(t, restarted)
	restartedHTTP := httptest.NewServer(restarted.Handler())
	t.Cleanup(restartedHTTP.Close)
	cold := &servedHarness{srv: restarted, ts: restartedHTTP, store: h.store, log: h.log, tenant: h.tenant,
		signer: h.signer, authz: h.authz, caFile: h.caFile, kek: h.kek}
	if after := listBody("after the restart", cold); !bytes.Equal(after, before) {
		t.Fatalf("the ledger changed across a restart:\nbefore %s\nafter  %s", before, after)
	}

	// The CLI reads the same operations in the same states.
	var cliOut, cliErr bytes.Buffer
	if exit := cli.Run(t.Context(), []string{"operations", "ledger", "--limit", "100"},
		cli.Env{Server: cold.ts.URL, Token: tok, Tenant: h.tenant, HTTPClient: cold.ts.Client()},
		strings.NewReader(""), &cliOut, &cliErr); exit != 0 {
		t.Fatalf("cli operations ledger: exit %d: %s", exit, cliErr.String())
	}
	if got, want := states(cliOut.Bytes()), states(before); len(got) == 0 || fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("the CLI reads %v, the API %v", got, want)
	}
}
