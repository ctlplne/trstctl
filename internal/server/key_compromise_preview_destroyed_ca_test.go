// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Run 1 lead defect:certificates-destroyed-predecessor-preview: the compromise
// preview reported ready while listing a superseded predecessor whose issuing
// CA key had been destroyed by signed retirement. Nothing can revoke such a
// leaf, so the preview must exclude it with a warning, and refuse outright when
// the served leaf's own CA is gone, before any irreversible command.
func TestKeyCompromisePreviewExcludesPredecessorOfDestroyedCA(t *testing.T) {
	var mu sync.Mutex
	destroyed := map[string]bool{}
	h := newServedHarness(t, config.Protocols{}, withAgentChannel, func(d *Deps) {
		d.AgentClaimableJobKinds = []string{"endpoint.contain"}
		d.CAKeyRetirementState = func(_ context.Context, tenantID, keyID string) (string, bool, error) {
			mu.Lock()
			defer mu.Unlock()
			if destroyed[tenantID+"/"+keyID] {
				return "destroyed", true, nil
			}
			return "", false, nil
		}
	})
	ctx := t.Context()
	registerServedTenant(t, h, "Destroyed predecessor preview fixture")
	operator := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "destroyed-ca-operator", []string{
		"issuers:write", "issuers:read", "certs:issue", "certs:read",
		"identities:write", "identities:read", "connectors:write", "connectors:read",
	})
	first := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "destroyed-ca-custodian-one", []string{"issuers:write", "issuers:read", "certs:issue"})
	second := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "destroyed-ca-custodian-two", []string{"issuers:write", "issuers:read", "certs:issue"})
	rootSpec := map[string]any{
		"common_name": "destroyed predecessor root", "max_path_len": 1,
		"ttl_seconds":           int64((365 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"destroyed.example.test"},
		"extended_key_usages":   []string{"serverAuth"}, "signature_algorithm": "ecdsa-p256",
	}
	rootCeremony := createCACeremony(t, h, operator, "create_root", "", rootSpec, 2, "destroyed-root-ceremony")
	approveCACeremony(t, h, first, rootCeremony.ID, 1, "destroyed-root-first")
	approveCACeremony(t, h, second, rootCeremony.ID, 2, "destroyed-root-second")
	root := createRootCA(t, h, operator, rootCeremony.ID, rootSpec, "destroyed-root-create")
	issuerFor := func(name, idem string) servedCAAuthority {
		t.Helper()
		spec := map[string]any{
			"common_name": name, "ttl_seconds": int64((180 * 24 * time.Hour).Seconds()),
			"permitted_dns_domains": []string{"destroyed.example.test"},
			"extended_key_usages":   []string{"serverAuth"}, "signature_algorithm": "ecdsa-p256",
		}
		ceremony := createCACeremony(t, h, operator, "create_intermediate", root.ID, spec, 2, idem+"-ceremony")
		approveCACeremony(t, h, first, ceremony.ID, 1, idem+"-first")
		approveCACeremony(t, h, second, ceremony.ID, 2, idem+"-second")
		return createIntermediateCA(t, h, operator, ceremony.ID, root.ID, spec, idem+"-create")
	}
	predecessorCA := issuerFor("retired predecessor issuer", "destroyed-predecessor")
	successorCA := issuerFor("live successor issuer", "destroyed-successor")

	owner, err := h.srv.orch.CreateOwner(ctx, h.tenant, "service", "destroyed predecessor owner", "")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := h.srv.orch.CreateIdentity(ctx, h.tenant, store.Identity{
		Kind: store.KindX509Certificate, Name: "destroyed.example.test", OwnerID: owner.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.srv.orch.Transition(ctx, h.tenant, identity.ID, orchestrator.StateIssued, "fixture issue"); err != nil {
		t.Fatal(err)
	}
	leafFor := func(issuer servedCAAuthority, eventID string) store.Certificate {
		t.Helper()
		stored, err := h.store.GetCAAuthority(ctx, h.tenant, issuer.ID)
		if err != nil {
			t.Fatal(err)
		}
		remote, err := h.srv.caHierarchy.signerForAuthority(ctx, stored)
		if err != nil {
			t.Fatal(err)
		}
		leafKey, err := h.signer.Client().GenerateKey(ctx, crypto.ECDSAP256)
		if err != nil {
			t.Fatal(err)
		}
		csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
			CommonName: identity.Name, DNSNames: []string{identity.Name},
		}, leafKey)
		if err != nil {
			t.Fatal(err)
		}
		issuerDER, err := firstCertDER(issuer.CertificatePEM)
		if err != nil {
			t.Fatal(err)
		}
		profile, err := h.srv.caHierarchy.leafProfileForAuthority(h.tenant, stored, h.srv.caHierarchy.leafProfile)
		if err != nil {
			t.Fatal(err)
		}
		profile.ClampTTLToIssuer = true
		leafDER, err := crypto.SignLeafFromCSRWithProfile(issuerDER, remote, csrDER, time.Hour, profile)
		if err != nil {
			t.Fatal(err)
		}
		info, err := certinfo.Inspect(leafDER)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := json.Marshal(map[string]any{
			"ca_id": issuer.ID, "serial": info.SerialNumber, "subject": info.Subject,
			"certificate_der": leafDER, "fingerprint": info.SHA256Fingerprint,
		})
		if err != nil {
			t.Fatal(err)
		}
		event, err := h.log.Append(ctx, events.Event{
			ID: eventID, TenantID: h.tenant, Type: projections.EventCAEndEntityIssued,
			SchemaVersion: projections.CAIssuedCertificateEvidenceSchemaVersion, Data: payload,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := projections.New(h.store).Apply(ctx, event); err != nil {
			t.Fatal(err)
		}
		cert, err := h.store.GetCertificateByFingerprint(ctx, h.tenant, info.SHA256Fingerprint)
		if err != nil {
			t.Fatal(err)
		}
		if cert.ID == "" {
			t.Fatalf("projected leaf %s has no inventory id: %+v", eventID, cert)
		}
		if _, err := h.srv.orch.RecordConnectorDelivery(ctx, h.tenant, store.ConnectorDeliveryReceipt{
			IdentityID: &identity.ID, Destination: "connector.deploy", Connector: "apache",
			Target: "destroyed-predecessor-host", Fingerprint: cert.Fingerprint, Status: "verified",
			IdempotencyKey: "deploy:" + eventID,
		}); err != nil {
			t.Fatal(err)
		}
		return cert
	}
	predecessor := leafFor(predecessorCA, "destroyed-predecessor-leaf")
	served := leafFor(successorCA, "destroyed-successor-leaf")
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE certificates SET status='superseded' WHERE tenant_id=$1 AND id=$2::uuid AND status='active'`,
			h.tenant, predecessor.ID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("supersede predecessor rows=%d", tag.RowsAffected())
		}
		return nil
	}); err != nil {
		t.Fatalf("supersede predecessor: %v", err)
	}
	if err := h.srv.orch.Transition(ctx, h.tenant, identity.ID, orchestrator.StateDeployed, "fixture served leaf"); err != nil {
		t.Fatal(err)
	}
	agentID := uuid.NewString()
	targetConfig, err := json.Marshal(map[string]any{"executor": "agent", "required_agent_id": agentID})
	if err != nil {
		t.Fatal(err)
	}
	target, err := h.srv.orch.UpsertDeploymentTarget(ctx, h.tenant, store.DeploymentTarget{
		Name: "destroyed-predecessor-host", Type: "apache", Config: targetConfig, Enabled: true, EnabledSet: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := json.Marshal(map[string]any{"target_id": target.ID, "identity_id": identity.ID, "fingerprint": served.Fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO outbox
			(tenant_id, destination, payload, idempotency_key, required_agent_role, required_agent_id, claimed_by_agent_id, claim_expires_at, claim_attempts, claim_completed_at, status, delivered_at)
			VALUES ($1, 'connector.deploy', $2, 'destroyed-host-deploy-evidence', 'host', $3::uuid, $3::uuid, now() + interval '1 hour', 1, now(), 'delivered', now())`,
			h.tenant, evidence, agentID)
		return err
	}); err != nil {
		t.Fatalf("seed host deploy evidence: %v", err)
	}

	preview := func() (int, map[string]any) {
		t.Helper()
		code, raw := doBearer(t, h.ts, http.MethodPost, "/api/v1/identities/"+identity.ID+"/compromise/preview", operator, "", map[string]any{"target_id": target.ID})
		var body map[string]any
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &body); err != nil {
				t.Fatalf("decode preview %d: %v body=%s", code, err, raw)
			}
		}
		return code, body
	}
	ids := func(list any) []string {
		var out []string
		items, _ := list.([]any)
		for _, item := range items {
			m, _ := item.(map[string]any)
			id, _ := m["id"].(string)
			out = append(out, id)
		}
		return out
	}

	code, body := preview()
	if code != http.StatusOK || body["ready"] != true || len(ids(body["certificates"])) != 2 || len(ids(body["excluded_certificates"])) != 0 {
		t.Fatalf("preview with both CAs live = %d %v", code, body)
	}
	liveFingerprint, _ := body["preview_fingerprint"].(string)

	mu.Lock()
	destroyed[h.tenant+"/"+predecessorCA.ID] = true
	mu.Unlock()
	code, body = preview()
	if code != http.StatusOK || body["ready"] != true {
		t.Fatalf("preview after predecessor CA destruction = %d %v", code, body)
	}
	if got := ids(body["certificates"]); len(got) != 1 || got[0] != served.ID {
		t.Fatalf("revocable certificates = %v, want only the served leaf %s", got, served.ID)
	}
	excluded, _ := body["excluded_certificates"].([]any)
	if len(excluded) != 1 {
		t.Fatalf("excluded certificates = %v, want the destroyed-CA predecessor", body["excluded_certificates"])
	}
	row, _ := excluded[0].(map[string]any)
	reason, _ := row["reason"].(string)
	if row["id"] != predecessor.ID || row["certificate_status"] != "superseded" || !strings.Contains(reason, "destroyed") {
		t.Fatalf("excluded predecessor row = %v", row)
	}
	warnings, _ := body["warnings"].([]any)
	if len(warnings) != 1 || !strings.Contains(warnings[0].(string), "destroyed") {
		t.Fatalf("preview warnings = %v", body["warnings"])
	}
	if fp, _ := body["preview_fingerprint"].(string); fp == "" || fp == liveFingerprint {
		t.Fatal("excluding a predecessor must change the reviewed preview fingerprint")
	}

	mu.Lock()
	destroyed[h.tenant+"/"+successorCA.ID] = true
	mu.Unlock()
	code, body = preview()
	detail, _ := body["detail"].(string)
	if code != http.StatusConflict || !strings.Contains(detail, "destroyed") {
		t.Fatalf("preview with the served leaf's CA destroyed = %d %v; want 409 refusal", code, body)
	}
}
