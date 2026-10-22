// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/pqc"
	"trstctl.com/trstctl/internal/pqcmigration"
	"trstctl.com/trstctl/internal/store"
)

// B5-2 (A41): the documented host-csr migration binds a requested ML-DSA
// identity to the host target that already serves the classical leaf the plan
// migrates. The plan used to refuse that with "already bound to another active
// identity", which made the documented flow impossible on any target that was
// actually in use. The identity serving the asset's certificate is the
// replacement's predecessor, not a competing writer; an unrelated active
// identity on the same target still refuses the plan.
func TestServedPQCPlanAcceptsTheRequestedReplacementBesideTheIdentityItSucceeds(t *testing.T) {
	// The attach seam installs the post-quantum algorithm classifier that makes
	// ML-DSA a valid profile entry; the served harness has no seam, so install it
	// the way the binary does.
	crypto.InstallLicensedAlgorithmClassifier(pqc.ClassifyAlgorithm)
	ctx := context.Background()
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleHost}, nil, func(d *Deps) {
		d.LicensedAPIOptionsFactory = pqcmigration.NewRuntime(d.Store).APIOptionsFactory
	})
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "host-test", Status: "active"}); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	owner, err := h.srv.orch.CreateOwner(ctx, h.tenant, "workload", "b5-2 owner", "")
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := json.Marshal(map[string]any{
		"name": "pq-host-b52", "max_validity": "720h", "allowed_protocols": []string{"api"},
		"allowed_dns_suffixes": []string{"example.test"}, "allowed_key_algorithms": []string{"ECDSA", "ML-DSA-65"},
	})
	if _, err := h.srv.orch.CreateProfile(ctx, h.tenant, "pq-host-b52", spec); err != nil {
		t.Fatalf("create profile: %v", err)
	}
	const (
		targetID    = "b5200000-0000-4000-8000-000000000001"
		classicalID = "b5200000-0000-4000-8000-000000000002"
		successorID = "b5200000-0000-4000-8000-000000000003"
		strangerID  = "b5200000-0000-4000-8000-000000000004"
		dnsName     = "b52.example.test"
		location    = "10.0.0.52:10443"
	)
	leafFP := strings.Repeat("c", 64)
	if _, err := h.store.UpsertCertificate(ctx, store.Certificate{TenantID: h.tenant, Subject: "CN=" + dnsName, Issuer: "CN=Lab Issuer", Serial: "52", Fingerprint: leafFP, KeyAlgorithm: "ECDSA", Source: "issuance"}); err != nil {
		t.Fatalf("seed certificate inventory: %v", err)
	}
	targetConfig, _ := json.Marshal(map[string]any{
		"profile": "lab-nginx", "cert_path": "/srv/tls/site.crt", "key_path": "/srv/tls/site.key",
		"executor": "agent", "required_agent_role": "host", "required_agent_id": agentRowID(h.tenant, h.agent),
		"verify_address": location, "verify_server_name": dnsName,
	})
	if err := h.store.UpsertDeploymentTarget(ctx, store.DeploymentTarget{
		ID: targetID, TenantID: h.tenant, Name: "lab/site-b52", Type: "nginx", Config: targetConfig, Enabled: true, EnabledSet: true,
	}); err != nil {
		t.Fatalf("seed target: %v", err)
	}
	identity := func(id, status string, extra map[string]any) {
		t.Helper()
		attrs := map[string]any{"deployment_target_id": targetID, "profile_name": "pq-host-b52", "dns_names": []string{dnsName}}
		for k, v := range extra {
			attrs[k] = v
		}
		raw, _ := json.Marshal(attrs)
		if err := h.store.UpsertIdentity(ctx, store.Identity{
			ID: id, TenantID: h.tenant, Kind: store.KindX509Certificate, Name: dnsName, OwnerID: owner.ID, Status: status, Attributes: raw,
		}); err != nil {
			t.Fatalf("seed identity %s: %v", id, err)
		}
	}
	// The classical identity is deployed on the target and its delivered leaf is
	// the asset the migration will replace.
	identity(classicalID, "deployed", nil)
	classical := classicalID
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return h.store.ApplyConnectorDeliveryRecordedTx(ctx, tx, store.ConnectorDeliveryReceipt{
			ID: "b5200000-0000-4000-8000-00000000000a", TenantID: h.tenant, IdentityID: &classical,
			Destination: "connector.deploy", Connector: "nginx", Target: "lab/site-b52", Fingerprint: leafFP,
			Status: "delivered", Attempts: 1, Reason: "native_delivered", IdempotencyKey: "b52-seed-deploy",
		})
	}); err != nil {
		t.Fatalf("seed delivery receipt: %v", err)
	}
	asset, err := h.store.UpsertCryptoAsset(ctx, store.CryptoAsset{
		TenantID: h.tenant, Kind: "certificate-key", Location: location, Algorithm: "ECDSA", KeyBits: 256,
		Strength: "acceptable", QuantumVulnerable: true, CertificateFingerprint: leafFP,
	})
	if err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	// The documented replacement: a requested identity with the run's subject key,
	// bound to the same target, issued by the served platform CA.
	identity(successorID, "requested", map[string]any{
		"subject_key_algorithm": "ML-DSA-65", "issuing_authority_source": "platform", "issuing_authority_id": "trstctl-issuing-ca",
	})

	tok := seedScopedToken(t, h.store, h.tenant, "certs:read", "certs:issue")
	plan := func() (int, []byte) {
		t.Helper()
		return secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/pqc/migrations/plan", tok, map[string]any{
			"asset_ids": []string{asset.ID}, "target_algorithm": "ML-DSA-65", "protocol": "host-csr",
			"certificate_bindings": []map[string]string{{"asset_id": asset.ID, "identity_id": successorID, "target_id": targetID}},
		})
	}
	// B6-1: the host agent's census says its exec profile pins no native TLS
	// probe; an ML-DSA host migration is refused by name before any attempt
	// is queued, and admitted once the binary reports the probe.
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "host-test", Status: "active",
		Executors: &transport.ExecutorReport{Version: "host-test", HostTLSProbe: false, Kinds: []transport.ExecutorKind{{Kind: "endpoint.renew", Connectors: []string{"nginx"}}}}}); err != nil {
		t.Fatalf("heartbeat without the probe: %v", err)
	}
	if status, body := plan(); status != http.StatusConflict || !strings.Contains(string(body), "pin tls_probe_openssl") || !strings.Contains(string(body), h.agent) {
		t.Fatalf("plan with a host that reports no TLS probe: status %d body %s", status, body)
	}
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "host-test", Status: "active",
		Executors: &transport.ExecutorReport{Version: "host-test", HostTLSProbe: true, Kinds: []transport.ExecutorKind{{Kind: "endpoint.renew", Connectors: []string{"nginx"}}}}}); err != nil {
		t.Fatalf("heartbeat with the probe: %v", err)
	}
	status, body := plan()
	if status != http.StatusOK {
		t.Fatalf("plan beside the identity it succeeds: status %d body %s", status, body)
	}
	var preview struct {
		Reissues []struct {
			IdentityID             string `json:"identity_id"`
			TargetID               string `json:"target_id"`
			PredecessorFingerprint string `json:"predecessor_fingerprint"`
		} `json:"reissues"`
	}
	if err := json.Unmarshal(body, &preview); err != nil || len(preview.Reissues) != 1 ||
		preview.Reissues[0].IdentityID != successorID || preview.Reissues[0].TargetID != targetID || preview.Reissues[0].PredecessorFingerprint != leafFP {
		t.Fatalf("plan preview = %s (%v)", body, err)
	}

	// An unrelated active identity on the same target is still a competing
	// writer: the plan refuses as before.
	identity(strangerID, "issued", nil)
	if status, body := plan(); status != http.StatusConflict || !strings.Contains(string(body), "already bound to another active identity") {
		t.Fatalf("plan with a stranger on the target: status %d body %s", status, body)
	}
}
