// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	agentrelay "trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/migration"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// A34: a migration replaces the leaf a target serves, whichever authority
// issued it. An identity whose last delivered certificate came from the
// external CA registry is admitted at start; the member binding freezes that
// leaf as the predecessor and records its source and issuing external CA, and
// the run proceeds through the same trust-first gate. A receipt naming a leaf
// the inventory does not hold is refused by name.
func TestServedMigrationAdmitsAnExternallyIssuedPredecessor(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleHost},
		[]string{agentrelay.KindTrustDistribute, agentrelay.KindEndpointRenew, agentrelay.KindConnectorRollback},
		func(d *Deps) { d.DefaultProfile = "a34-api" })
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "a34-test", Status: "active"}); err != nil {
		t.Fatalf("register host agent: %v", err)
	}
	spec, _ := json.Marshal(map[string]any{"name": "a34-api", "max_validity": "720h", "allowed_protocols": []string{"api"}})
	if _, err := h.srv.orch.CreateProfile(ctx, h.tenant, "a34-api", spec); err != nil {
		t.Fatalf("create profile: %v", err)
	}
	owner, err := h.srv.orch.CreateOwner(ctx, h.tenant, "workload", "A34 owner", "")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	target := func(name, dnsName string) store.DeploymentTarget {
		t.Helper()
		cfg, _ := json.Marshal(map[string]any{
			"executor": "agent", "cert_path": filepath.Join(root, name+".crt"), "key_path": filepath.Join(root, name+".key"),
			"required_agent_id": agentRowID(h.tenant, h.agent), "required_agent_role": mtls.AgentRoleHost,
			"verify_address": "127.0.0.1:8443", "verify_server_name": dnsName,
		})
		created, err := h.srv.orch.UpsertDeploymentTarget(ctx, h.tenant, store.DeploymentTarget{Name: "host/" + name, Type: "nginx", Config: cfg, Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		return created
	}
	deployed := func(dnsName string, tgt store.DeploymentTarget) string {
		t.Helper()
		attrs, _ := json.Marshal(map[string]string{"deployment_target_id": tgt.ID, "connector": tgt.Type, "target": tgt.Name, "profile_name": "a34-api"})
		ident, err := h.srv.orch.CreateIdentity(ctx, h.tenant, store.Identity{Kind: store.KindX509Certificate, Name: dnsName, OwnerID: owner.ID, Attributes: attrs})
		if err != nil {
			t.Fatal(err)
		}
		ident.Status = "deployed"
		if err := h.store.UpsertIdentity(ctx, ident); err != nil {
			t.Fatal(err)
		}
		return ident.ID
	}
	delivered := func(identityID string, tgt store.DeploymentTarget, fingerprint, key string) {
		t.Helper()
		if _, err := h.srv.orch.RecordConnectorDelivery(ctx, h.tenant, store.ConnectorDeliveryReceipt{
			IdentityID: &identityID, Destination: "connector.deploy", Connector: tgt.Type, Target: tgt.Name,
			Fingerprint: fingerprint, Status: "delivered", Reason: "a34 fixture", IdempotencyKey: key,
		}); err != nil {
			t.Fatalf("record delivery: %v", err)
		}
	}

	// The predecessor: a leaf a partner CA issued through the external
	// registry, recorded the way the registry records it, so its issuing
	// authority is authenticated from the event rather than a label.
	const dnsName = "a34-partner-issued.test"
	externalCAID := uuid.NewString()
	issued, err := testExternalCACertificate(ca.IssueRequest{CSR: serverTestCSR(t, dnsName, nil), DNSNames: []string{dnsName}}, "Partner public CA")
	if err != nil {
		t.Fatal(err)
	}
	info, err := certinfo.Inspect(issued.CertificatePEM)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := certinfo.LeafDER(issued.CertificatePEM)
	if err != nil {
		t.Fatal(err)
	}
	const issueKey = "a34-external-issue-1"
	notBefore, notAfter := info.NotBefore.UTC(), info.NotAfter.UTC()
	predecessorID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(h.tenant+"\x00external-ca\x00"+issueKey)).String()
	payload, _ := json.Marshal(projections.CertificateRecorded{
		ID: predecessorID, Subject: info.Subject, SANs: info.DNSNames, Issuer: info.Issuer, Serial: info.SerialNumber,
		Fingerprint: info.SHA256Fingerprint, KeyAlgorithm: info.KeyAlgorithm, NotBefore: &notBefore, NotAfter: &notAfter,
		Source: "external-ca:" + externalCAID, CertificateDER: leafDER, CertificatePEM: issued.CertificatePEM,
		IssuanceResponse: []byte(`{"issuer":"partner"}`), IssuanceIdempotencyKey: issueKey, IssuanceRequestBinding: strings.Repeat("ab", 32),
	})
	if err := h.srv.orch.RecordCertificateEvent(ctx, events.Event{
		ID:   uuid.NewSHA1(uuid.NameSpaceOID, []byte(h.tenant+"\x00certificate.recorded\x00"+issueKey)).String(),
		Type: projections.EventCertificateRecorded, TenantID: h.tenant, Data: payload,
	}); err != nil {
		t.Fatalf("record external leaf: %v", err)
	}
	predecessor, err := h.store.GetCertificate(ctx, h.tenant, predecessorID)
	if err != nil || predecessor.IssuingExternalCAID != externalCAID || predecessor.OwnerID != nil || predecessor.Status != "active" {
		t.Fatalf("external predecessor = %+v %v, want an active ownerless leaf with an authenticated external issuer", predecessor, err)
	}
	partnerTarget := target("partner", dnsName)
	partnerIdentity := deployed(dnsName, partnerTarget)
	delivered(partnerIdentity, partnerTarget, info.SHA256Fingerprint, "a34-deploy-partner")

	// A second identity whose last delivery names a leaf nobody inventoried.
	const orphanName = "a34-uninventoried.test"
	orphanTarget := target("orphan", orphanName)
	orphanIdentity := deployed(orphanName, orphanTarget)
	delivered(orphanIdentity, orphanTarget, strings.Repeat("0f", 32), "a34-deploy-orphan")

	caOperator := seedScopedTokenSubject(t, h.store, h.tenant, "a34-ca-operator", "issuers:read", "issuers:write")
	caApprover := seedScopedTokenSubject(t, h.store, h.tenant, "a34-ca-custodian", "issuers:read", "issuers:write")
	rootSpec := map[string]any{
		"common_name": "A34 successor root", "max_path_len": 1,
		"ttl_seconds":           int64((365 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{dnsName, orphanName}, "extended_key_usages": []string{"serverAuth"},
		"signature_algorithm": "ecdsa-p256",
	}
	ceremony := createCACeremony(t, h.servedHarness, caOperator, "create_root", "", rootSpec, 1, "a34-root-ceremony")
	approveCACeremony(t, h.servedHarness, caApprover, ceremony.ID, 1, "a34-root-approval")
	successor := createRootCA(t, h.servedHarness, caOperator, ceremony.ID, rootSpec, "a34-root-create")
	token := seedScopedTokenSubject(t, h.store, h.tenant, "a34-migration-operator", "keys:read", "keys:write", "certs:issue")
	trustPath := filepath.Join(root, "next-root.pem")
	start := func(planID, identityID, key string) (int, []byte) {
		return secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/migrations/runs", token, key, map[string]any{
			"plan_id": planID, "new_authority_id": successor.ID,
			"waves": []any{map[string]any{"id": "canary", "ordinal": 1, "members": []any{map[string]any{
				"identity_id": identityID, "agent_id": agentRowID(h.tenant, h.agent), "trust_anchor_path": trustPath,
			}}}},
		})
	}

	status, body := start("plan-a34-orphan", orphanIdentity, "a34-start-orphan")
	if status != http.StatusBadRequest || !bytes.Contains(body, []byte("last delivered certificate is not inventoried")) {
		t.Fatalf("a receipt naming an uninventoried leaf started a migration: %d %s", status, body)
	}

	status, body = start("plan-a34", partnerIdentity, "a34-start")
	if status != http.StatusCreated {
		t.Fatalf("start migration from an externally issued predecessor = %d %s", status, body)
	}
	var started migration.Run
	if err := json.Unmarshal(body, &started); err != nil {
		t.Fatalf("decode started run: %v (%s)", err, body)
	}
	if started.Status != migration.RunRunning || len(started.Waves) != 1 || started.Waves[0].Phase != migration.PhaseVerifyingTrust {
		t.Fatalf("started run = %+v", started)
	}
	binding := started.Waves[0].Members[0].Binding
	if binding.PredecessorCertificateID != predecessorID || binding.PredecessorFingerprint != cleanFingerprint(info.SHA256Fingerprint) ||
		binding.PredecessorSource != "external-ca:"+externalCAID || binding.PredecessorExternalCAID != externalCAID ||
		len(binding.SubjectDNSNames) != 1 || binding.SubjectDNSNames[0] != dnsName || binding.IssuingAuthorityID != successor.ID {
		t.Fatalf("member binding = %+v, want the external leaf frozen as the predecessor with its provenance", binding)
	}
	if !bytes.Contains(body, []byte(`"predecessor_source":"external-ca:`+externalCAID+`"`)) ||
		!bytes.Contains(body, []byte(`"predecessor_external_ca_id":"`+externalCAID+`"`)) {
		t.Fatalf("the run view does not show the predecessor's provenance: %s", body)
	}
	assertMigrationOutboxCountAUD40(t, h, started.ID, "distribute_trust", 1)
	assertMigrationOutboxCountAUD40(t, h, started.ID, "issue_successor", 0)
}
