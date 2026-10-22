// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/envoy"
	"trstctl.com/trstctl/internal/connector/envoy/envoytest"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// A61: an Envoy target that declares vantage network needs no host
// assignment, its deploy is stamped for the network role, the control plane
// leaves it alone, and an enrolled network relay claims it, redeems the issued
// credential and drives the remote SDS endpoint. The same target without the
// declaration is host work and must name its host agent.
func TestServedRemoteEnvoyTargetDeploysThroughTheNetworkRelayWhenDeclared(t *testing.T) {
	sds := envoytest.New()
	t.Cleanup(sds.Close)
	registry := connector.NewRegistry(func(string) connector.Ops { return connector.NewHTTPOps(sds.Client()) })
	registry.Register(envoy.New(sds.URL(), "server_cert"))
	if err := registry.DeclareTargetVantage("envoy", connector.VantageHostAgent); err != nil {
		t.Fatal(err)
	}
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleNetwork}, []string{"connector.deploy"}, func(d *Deps) {
		d.ConnectorRegistry = registry
	})
	ctx := context.Background()
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "test-1.0", Status: "active"}); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	tok := seedScopedToken(t, h.store, h.tenant,
		"owners:read", "owners:write", "identities:read", "identities:write",
		"certs:read", "certs:issue", "connectors:read", "connectors:write", "lifecycle:read",
	)

	// Without the declaration an Envoy target is host work and needs its host
	// agent named; with it, no host assignment is required.
	status, body := secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/connectors/targets", tok, map[string]any{
		"name": "edge/envoy-host", "connector": "envoy",
		"config": map[string]any{"endpoint": sds.URL(), "secret_name": "server_cert"},
	})
	if status != http.StatusUnprocessableEntity || !jsonContains(t, body, "requires a host agent") {
		t.Fatalf("undeclared envoy target without a host agent: status %d body %s", status, body)
	}
	status, body = secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/connectors/targets", tok, map[string]any{
		"name": "edge/envoy-remote", "connector": "envoy",
		"config": map[string]any{"endpoint": sds.URL(), "secret_name": "server_cert", "vantage": "host"},
	})
	if status != http.StatusUnprocessableEntity || !jsonContains(t, body, "not permitted") {
		t.Fatalf("envoy target declaring an impermissible vantage: status %d body %s", status, body)
	}
	status, body = secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/connectors/targets", tok, map[string]any{
		"name": "edge/envoy-remote", "connector": "envoy",
		"config": map[string]any{"endpoint": sds.URL(), "secret_name": "server_cert", "vantage": "network"},
	})
	if status != http.StatusCreated {
		t.Fatalf("create remote envoy target: status %d body %s", status, body)
	}
	var target struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &target); err != nil || target.ID == "" {
		t.Fatalf("decode target: %v %s", err, body)
	}

	status, body = secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/owners", tok, map[string]any{"kind": "workload", "name": "a61-owner"})
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
		"kind": "x509_certificate", "name": "a61.served.test", "owner_id": owner.ID,
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
		"to": "issued", "reason": "a61 issue after target binding",
	})
	if status != http.StatusOK {
		t.Fatalf("issue: status %d body %s", status, body)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if sds.Puts() != 0 {
		t.Fatal("the control plane pushed to the remote SDS endpoint; host-family rows never execute there")
	}

	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{"connector.deploy"}, Limit: 1, LeaseSeconds: 120})
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if len(claimed.Jobs) != 1 {
		t.Fatalf("network relay claimed %d jobs, want the remote envoy deploy", len(claimed.Jobs))
	}
	job := claimed.Jobs[0]
	var intent relay.DeployIntent
	if err := json.Unmarshal(job.Payload, &intent); err != nil || intent.Connector != "envoy" || intent.Fingerprint == "" {
		t.Fatalf("claimed intent = %+v %v", intent, err)
	}
	redeemed, err := h.client.RedeemJobCredential(ctx, &transport.RedeemJobCredentialRequest{JobID: job.JobID, Attempt: job.Attempt})
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	material := relay.Material{}
	for _, item := range redeemed.Items {
		material[item.Name] = item.Value
	}
	if _, err := relay.Execute(ctx, sds.Client(), intent, material); err != nil {
		t.Fatalf("relay deploy to the remote envoy: %v", err)
	}
	got, ok := sds.Secret("server_cert")
	if !ok || got.Fingerprint != intent.Fingerprint || !bytes.Contains(got.CertPEM, []byte("BEGIN CERTIFICATE")) {
		t.Fatalf("remote SDS holds %+v ok=%v, want the issued certificate", got, ok)
	}
	if _, err := h.client.ReportJobResult(ctx, h.report(t, job.JobID, job.Attempt, transport.JobOutcomeExecuted, "", "")); err != nil {
		t.Fatalf("report: %v", err)
	}
	deliveries := connectorDeliveriesForIdentity(t, h.servedHarness, tok, ident.ID)
	if len(deliveries.Items) != 1 || deliveries.Items[0].Status != "delivered" || deliveries.Items[0].Connector != "envoy" {
		t.Fatalf("delivery after the relay deploy = %+v raw=%s", deliveries.Items, deliveries.Raw)
	}
}
