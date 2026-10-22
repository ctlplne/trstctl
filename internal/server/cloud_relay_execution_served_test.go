// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/gcpcm"
	"trstctl.com/trstctl/internal/connector/gcpcm/gcpcmtest"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// A59: with a network relay enrolled, a GCP Certificate Manager deploy is
// relay work. The control plane refuses to execute it, the relay claims it over
// the agent channel, redeems the bearer-token reference and the issued
// credential for one attempt, drives the real connector against the
// Certificate Manager double, and its signed report becomes the delivery
// receipt. A rollback follows the same path: the relay redeems only the bearer
// token, re-points the map entry, and the receipt reads rolled_back.
func TestServedCloudStoreDeployAndRollbackExecuteOnAnEnrolledRelay(t *testing.T) {
	const (
		gcpToken   = "a59-gcp-bearer-token" // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
		secretName = "connectors/gcp/a59"   // #nosec G101 -- a secret-store NAME the target references, not a credential value (CWE-798)
		certID     = "web-relay"
		mapEntry   = "web-map/web-entry"
	)
	provider := gcpcmtest.New(gcpToken)
	t.Cleanup(provider.Close)
	entry, err := gcpcm.ParseCertificateMapEntry(mapEntry)
	if err != nil {
		t.Fatal(err)
	}
	// The control plane carries the connector too: the proof below is that it
	// does NOT use it while a relay is enrolled.
	registry := connector.NewRegistry(func(string) connector.Ops {
		return connector.NewHTTPOps(provider.Client())
	})
	registry.Register(gcpcm.New("a59-project", "global", gcpcm.StaticToken([]byte(gcpToken)),
		gcpcm.WithEndpoint(provider.URL()), gcpcm.WithPollInterval(0), gcpcm.WithCertificateMapEntry(entry)))
	if err := registry.DeclareTargetVantage("gcp-certificate-manager", connector.VantageNetworkRelay); err != nil {
		t.Fatal(err)
	}
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleNetwork}, []string{"connector.deploy", "connector.rollback"}, func(d *Deps) {
		d.LifecycleRenewBefore = 31 * 24 * time.Hour
		d.ConnectorRegistry = registry
	})
	ctx := context.Background()
	sealed, err := h.srv.sealTenantSecretForTest(ctx, h.tenant, secretName, []byte(gcpToken))
	if err != nil {
		t.Fatalf("seal tenant secret: %v", err)
	}
	seedApplicationSecretFixture(t, h.store, h.tenant, secretName, sealed)
	tok := seedScopedToken(t, h.store, h.tenant,
		"owners:read", "owners:write", "identities:read", "identities:write",
		"certs:read", "certs:issue", "connectors:read", "connectors:write", "lifecycle:read",
	)
	// Bootstrap proves the role grant; the heartbeat is what records the relay
	// as present in the fleet, which is what routing reads.
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "test-1.0", Status: "active"}); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	hasRelay, err := h.store.TenantHasNetworkRelay(ctx, h.tenant)
	if err != nil || !hasRelay {
		t.Fatalf("tenant has no enrolled network relay: %v %v", hasRelay, err)
	}

	status, body := secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/connectors/targets", tok, map[string]any{
		"name": certID, "connector": "gcp-certificate-manager",
		"config": map[string]any{
			"endpoint": provider.URL(), "project": "a59-project", "location": "global",
			"bearer_token_ref": "secret://" + secretName, "certificate_map_entry": mapEntry, "poll_interval": "1ms",
		},
	})
	if status != http.StatusCreated {
		t.Fatalf("create target: status %d body %s", status, body)
	}
	var target struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &target); err != nil || target.ID == "" {
		t.Fatalf("decode target: %v %s", err, body)
	}
	status, body = secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/owners", tok, map[string]any{"kind": "workload", "name": "a59-owner"})
	if status != http.StatusCreated {
		t.Fatalf("create owner: status %d body %s", status, body)
	}
	var owner struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &owner); err != nil {
		t.Fatal(err)
	}
	status, body = secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/identities", tok, map[string]any{
		"kind": "x509_certificate", "name": "a59.served.test", "owner_id": owner.ID,
	})
	if status != http.StatusCreated {
		t.Fatalf("create identity: status %d body %s", status, body)
	}
	var ident struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &ident); err != nil {
		t.Fatal(err)
	}
	status, body = secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/identities/"+ident.ID+"/connector-target", tok, map[string]any{"target_id": target.ID})
	if status != http.StatusOK {
		t.Fatalf("bind identity to target: status %d body %s", status, body)
	}
	status, body = secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/identities/"+ident.ID+"/transitions", tok, map[string]any{
		"to": "issued", "reason": "a59 issue after target binding",
	})
	if status != http.StatusOK {
		t.Fatalf("issue: status %d body %s", status, body)
	}
	// The control plane's outbox worker sees the deploy row and leaves it for
	// the relay: nothing reaches Certificate Manager from here.
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if provider.CreateCalls() != 0 || provider.PatchCalls() != 0 {
		t.Fatalf("the control plane executed a cloud deploy while a relay is enrolled (create=%d patch=%d)", provider.CreateCalls(), provider.PatchCalls())
	}

	// The relay claims, redeems and executes the deploy.
	runRelayJob := func(kind string) (int64, int) {
		t.Helper()
		claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{kind}, Limit: 1, LeaseSeconds: 120})
		if err != nil {
			t.Fatalf("claim %s: %v", kind, err)
		}
		if len(claimed.Jobs) != 1 {
			t.Fatalf("relay claimed %d %s jobs, want 1", len(claimed.Jobs), kind)
		}
		job := claimed.Jobs[0]
		redeemed, err := h.client.RedeemJobCredential(ctx, &transport.RedeemJobCredentialRequest{JobID: job.JobID, Attempt: job.Attempt})
		if err != nil {
			t.Fatalf("redeem for %s: %v", kind, err)
		}
		material := relay.Material{}
		for _, item := range redeemed.Items {
			material[item.Name] = item.Value
		}
		if len(material["secret://"+secretName]) == 0 {
			t.Fatalf("redemption for %s did not carry the bearer token reference; got %d items", kind, len(redeemed.Items))
		}
		switch kind {
		case "connector.deploy":
			var intent relay.DeployIntent
			if err := json.Unmarshal(job.Payload, &intent); err != nil {
				t.Fatalf("decode deploy intent: %v", err)
			}
			if intent.Connector != "gcp-certificate-manager" || intent.Target != certID || intent.Fingerprint == "" {
				t.Fatalf("deploy intent = %+v", intent)
			}
			if _, err := relay.Execute(ctx, provider.Client(), intent, material); err != nil {
				t.Fatalf("relay deploy: %v", err)
			}
		case "connector.rollback":
			var intent relay.RollbackIntent
			if err := json.Unmarshal(job.Payload, &intent); err != nil {
				t.Fatalf("decode rollback intent: %v", err)
			}
			if len(material["credential.key_pem"]) != 0 {
				t.Fatal("a rollback redemption carried a private key")
			}
			if _, _, err := relay.RollbackWithResult(ctx, provider.Client(), intent, material); err != nil {
				t.Fatalf("relay rollback: %v", err)
			}
		}
		if _, err := h.client.ReportJobResult(ctx, h.report(t, job.JobID, job.Attempt, transport.JobOutcomeExecuted, "", "")); err != nil {
			t.Fatalf("report %s: %v", kind, err)
		}
		return job.JobID, job.Attempt
	}
	runRelayJob("connector.deploy")
	first := connectorDeliveriesForIdentity(t, h.servedHarness, tok, ident.ID)
	if len(first.Items) != 1 || first.Items[0].Status != "delivered" || first.Items[0].Fingerprint == "" {
		t.Fatalf("delivery after the relay deploy = %+v raw=%s", first.Items, first.Raw)
	}
	firstName := connector.DeployedObjectName(certID, first.Items[0].Fingerprint)
	if _, ok := provider.Imported(firstName); !ok {
		t.Fatalf("the relay deploy did not create %q in Certificate Manager", firstName)
	}

	// Renewal: a second relay-executed deploy leaves the first certificate in
	// the project and moves the map entry.
	leaf, err := h.store.GetCertificateByFingerprint(ctx, h.tenant, first.Items[0].Fingerprint)
	if err != nil || leaf.NotAfter == nil {
		t.Fatalf("load delivered leaf: %+v %v", leaf, err)
	}
	if queued, err := h.srv.runLifecycleOnceAt(ctx, leaf.NotAfter.Add(-12*time.Hour)); err != nil || queued != 1 {
		t.Fatalf("scheduled renewals = %d %v, want 1", queued, err)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain renewal: %v", err)
	}
	runRelayJob("connector.deploy")
	afterRenew := connectorDeliveriesForIdentity(t, h.servedHarness, tok, ident.ID)
	if len(afterRenew.Items) != 2 {
		t.Fatalf("deliveries after renewal = %d (%s)", len(afterRenew.Items), afterRenew.Raw)
	}
	if bound := provider.MapEntry(mapEntry); len(bound) != 1 || strings.HasSuffix(bound[0], "/certificates/"+firstName) {
		t.Fatalf("map entry after renewal = %v, want the successor", bound)
	}

	// Rollback: queued for the relay, refused by the control plane, executed
	// by the relay without a key.
	keysBefore := provider.UploadedKeys()
	status, body = secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/connectors/targets/"+target.ID+"/rollback", tok, map[string]any{
		"identity_id": ident.ID, "reason": "a59 relay rollback drill",
	})
	if status != http.StatusOK || !jsonContains(t, body, "rollback_queued_for_agent_execution") || !jsonContains(t, body, "network-relay execution") {
		t.Fatalf("rollback request: status %d body %s", status, body)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain rollback: %v", err)
	}
	if bound := provider.MapEntry(mapEntry); len(bound) != 1 || strings.HasSuffix(bound[0], "/certificates/"+firstName) {
		t.Fatal("the control plane executed a cloud rollback while a relay is enrolled")
	}
	runRelayJob("connector.rollback")
	if bound := provider.MapEntry(mapEntry); len(bound) != 1 || !strings.HasSuffix(bound[0], "/certificates/"+firstName) {
		t.Fatalf("map entry after the relay rollback = %v, want the predecessor %q", bound, firstName)
	}
	if provider.UploadedKeys() != keysBefore {
		t.Fatal("the relay rollback uploaded a private key")
	}
	afterRollback := connectorDeliveriesForIdentity(t, h.servedHarness, tok, ident.ID)
	found := false
	for _, item := range afterRollback.Items {
		if item.Destination == "connector.rollback" && item.Status == "rolled_back" {
			found = true
			if item.Fingerprint != first.Items[0].Fingerprint || item.Reason != "rolled_back" {
				t.Fatalf("rollback result receipt = %+v", item)
			}
		}
	}
	if !found {
		t.Fatalf("no rolled_back receipt after the relay rollback: %s", afterRollback.Raw)
	}
}

// A59: the same target in a tenant with no network relay keeps the control
// plane as its executor, and an endpoint binding needs no claimable agent kind.
func TestServedCloudStoreWithoutARelayStaysOnTheControlPlane(t *testing.T) {
	provider := gcpcmtest.New("a59-no-relay-token")
	t.Cleanup(provider.Close)
	registry := connector.NewRegistry(func(string) connector.Ops {
		return connector.NewHTTPOps(provider.Client())
	})
	registry.Register(gcpcm.New("a59-project", "global", gcpcm.StaticToken([]byte("a59-no-relay-token")),
		gcpcm.WithEndpoint(provider.URL()), gcpcm.WithPollInterval(0)))
	if err := registry.DeclareTargetVantage("gcp-certificate-manager", connector.VantageNetworkRelay); err != nil {
		t.Fatal(err)
	}
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) { d.ConnectorRegistry = registry })
	tok := seedScopedToken(t, h.store, h.tenant, "owners:write", "connectors:read", "connectors:write", "certs:issue")
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/owners", tok, map[string]any{"kind": "workload", "name": "a59-no-relay-owner"})
	if status != http.StatusCreated {
		t.Fatalf("create owner: status %d body %s", status, body)
	}
	var owner struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &owner); err != nil {
		t.Fatal(err)
	}
	request := map[string]any{
		"owner_id": owner.ID, "identity_name": "a59-no-relay.served.test", "reason": "a59 control-plane fallback",
		"target": map[string]any{
			"name": "a59/no-relay", "connector": "gcp-certificate-manager",
			"config": map[string]any{"target": "web-fallback", "project": "a59-project", "location": "global", "bearer_token_ref": "secret://connectors/gcp/none"},
		},
	}
	bindingRequest := previewPlatformEndpointBinding(t, h, tok, request)
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/lifecycle/endpoint-bindings", tok, bindingRequest)
	if status != http.StatusCreated {
		t.Fatalf("create endpoint binding without a relay: status %d body %s", status, body)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if got, ok := provider.Imported("web-fallback"); !ok || len(got.PEMCertificate) == 0 {
		t.Fatalf("the control plane did not execute the cloud deploy with no relay enrolled: %+v ok=%v", got, ok)
	}
}
