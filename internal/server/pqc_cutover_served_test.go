// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	agentrelay "trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/pqc"
	"trstctl.com/trstctl/internal/pqcmigration"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/succession"
	// Registers the PCAS ledger's privacy policies, as the attach seam does.
	_ "trstctl.com/trstctl/internal/succession/orchestrator"
	"trstctl.com/trstctl/internal/succession/retirement"
	pcasstore "trstctl.com/trstctl/internal/succession/store"
)

// A217: a hybrid composite leaf's reissue to pure ML-DSA is planned as a
// cutover and held — no host job — until the identity's relying-party
// acknowledgment quorum is recorded. With no policy, or an acknowledgment
// for another epoch, it stays held; a signed acknowledgment for the policy's
// epoch releases it, the queued host job asks the host for an ML-DSA-65
// subject key, and the host's CSR is issued as a pure ML-DSA-65 leaf.
func TestServedPQCHybridToPureCutoverWaitsForTheRelyingPartyQuorum(t *testing.T) {
	t.Run("active policy", func(t *testing.T) { servedHybridToPureCutover(t, false) })
	// PCAS retirement can act on the same quorum first and retire the
	// identity's policy; the cutover still releases on that quorum.
	t.Run("policy retired by PCAS first", func(t *testing.T) { servedHybridToPureCutover(t, true) })
}

func servedHybridToPureCutover(t *testing.T, retiredFirst bool) {
	crypto.InstallLicensedAlgorithmClassifier(pqc.ClassifyAlgorithm)
	ctx := context.Background()
	var runtime *pqcmigration.Runtime
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleHost}, []string{agentJobKindEndpointRenew}, func(d *Deps) {
		d.Store.WithExtraMigrations(pcasstore.MigrationsFS())
		if err := d.Store.Migrate(t.Context()); err != nil {
			t.Fatalf("PCAS migrations: %v", err)
		}
		runtime = pqcmigration.NewRuntime(d.Store)
		d.LicensedAPIOptionsFactory = runtime.APIOptionsFactory
		d.LicensedProjectionOptions = append(d.LicensedProjectionOptions, runtime.ProjectionOptions...)
		d.LicensedCSRParser = pqc.ParsePureMLDSACSR
		d.LicensedCSRInspector = pqc.InspectHybridCSR
		d.LicensedLeafSigner = pqc.SignLicensedLeafFromCSRWithProfile
		d.PreparedSubjectLeafSigner = pqc.SignPQCLeafFromCSRWithPreparation
	})
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "host-test", Status: "active",
		Executors: &transport.ExecutorReport{Version: "host-test", HostTLSProbe: true,
			Kinds: []transport.ExecutorKind{{Kind: "endpoint.renew", Connectors: []string{"nginx"}}}}}); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	owner, err := h.srv.orch.CreateOwner(ctx, h.tenant, "workload", "a217 owner", "")
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := json.Marshal(map[string]any{
		"name": "pq-host-a217", "max_validity": "720h", "allowed_protocols": []string{"api"},
		"allowed_dns_suffixes": []string{"example.test"}, "allowed_key_algorithms": []string{"ECDSA", "ML-DSA-65"},
	})
	if _, err := h.srv.orch.CreateProfile(ctx, h.tenant, "pq-host-a217", spec); err != nil {
		t.Fatalf("create profile: %v", err)
	}
	const (
		targetID    = "a2170000-0000-4000-8000-000000000001"
		hybridID    = "a2170000-0000-4000-8000-000000000002"
		successorID = "a2170000-0000-4000-8000-000000000003"
		dnsName     = "a217.example.test"
		location    = "10.0.0.217:10443"
	)
	leafFP := strings.Repeat("d", 64)
	// Recorded through the ledger, as issuance records it, so the host's later
	// issuance can record its certificate too.
	recorded, _ := json.Marshal(projections.CertificateRecorded{ID: uuid.NewString(), Subject: "CN=" + dnsName,
		Issuer: "CN=Lab Issuer", Serial: "217", Fingerprint: leafFP, KeyAlgorithm: pqcmigration.EffectiveHybridTLS, Source: "issuance"})
	recordedEvent, err := h.log.Append(ctx, events.Event{Type: projections.EventCertificateRecorded, TenantID: h.tenant, Data: recorded})
	if err != nil {
		t.Fatal(err)
	}
	if err := projections.New(h.store).Apply(ctx, recordedEvent); err != nil {
		t.Fatalf("seed certificate inventory: %v", err)
	}
	targetConfig, _ := json.Marshal(map[string]any{
		"profile": "lab-nginx", "cert_path": "/srv/tls/site.crt", "key_path": "/srv/tls/site.key",
		"executor": "agent", "required_agent_role": "host", "required_agent_id": agentRowID(h.tenant, h.agent),
		"verify_address": location, "verify_server_name": dnsName,
	})
	if err := h.store.UpsertDeploymentTarget(ctx, store.DeploymentTarget{
		ID: targetID, TenantID: h.tenant, Name: "lab/site-a217", Type: "nginx", Config: targetConfig, Enabled: true, EnabledSet: true,
	}); err != nil {
		t.Fatalf("seed target: %v", err)
	}
	identity := func(id, status string, extra map[string]any) {
		t.Helper()
		attrs := map[string]any{"deployment_target_id": targetID, "profile_name": "pq-host-a217", "dns_names": []string{dnsName}}
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
	identity(hybridID, "deployed", nil)
	hybrid := hybridID
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return h.store.ApplyConnectorDeliveryRecordedTx(ctx, tx, store.ConnectorDeliveryReceipt{
			ID: "a2170000-0000-4000-8000-00000000000a", TenantID: h.tenant, IdentityID: &hybrid,
			Destination: "connector.deploy", Connector: "nginx", Target: "lab/site-a217", Fingerprint: leafFP,
			Status: "delivered", Attempts: 1, Reason: "native_delivered", IdempotencyKey: "a217-seed-deploy",
		})
	}); err != nil {
		t.Fatalf("seed delivery receipt: %v", err)
	}
	// The served leaf is the hybrid composite: quantum-safe through its ML-DSA
	// component, still carrying a classical one.
	asset, err := h.store.UpsertCryptoAsset(ctx, store.CryptoAsset{
		TenantID: h.tenant, Kind: "certificate-key", Location: location, Algorithm: pqcmigration.EffectiveHybridTLS,
		Strength: "strong", QuantumVulnerable: false, CertificateFingerprint: leafFP,
	})
	if err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	identity(successorID, "requested", map[string]any{
		"subject_key_algorithm": "ML-DSA-65", "issuing_authority_source": "platform", "issuing_authority_id": "trstctl-issuing-ca",
	})

	tok := seedScopedToken(t, h.store, h.tenant, "certs:read", "certs:issue")
	request := map[string]any{
		"asset_ids": []string{asset.ID}, "target_algorithm": "ML-DSA-65", "protocol": "host-csr",
		"certificate_bindings": []map[string]string{{"asset_id": asset.ID, "identity_id": successorID, "target_id": targetID}},
	}
	status, body := secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/pqc/migrations/plan", tok, request)
	if status != http.StatusOK || !strings.Contains(string(body), `"cutover":true`) {
		t.Fatalf("plan for the hybrid leaf = %d %s; want a cutover reissue", status, body)
	}
	status, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/pqc/migrations", tok, "a217-start", request)
	var started struct {
		RunID                  string `json:"run_id"`
		Queued                 int    `json:"certificate_reissues_queued"`
		AwaitingAcknowledgment int    `json:"certificate_cutovers_awaiting_acknowledgment"`
	}
	if status != http.StatusAccepted || json.Unmarshal(body, &started) != nil || started.Queued != 0 || started.AwaitingAcknowledgment != 1 {
		t.Fatalf("start = %d %s; want the cutover held, nothing queued", status, body)
	}
	renewJobs := func() []orchestrator.Record {
		t.Helper()
		rows, err := h.srv.outbox.Pending(ctx, h.tenant)
		if err != nil {
			t.Fatal(err)
		}
		var out []orchestrator.Record
		for _, row := range rows {
			if row.Destination == agentrelay.KindEndpointRenew {
				out = append(out, row)
			}
		}
		return out
	}
	if jobs := renewJobs(); len(jobs) != 0 {
		t.Fatalf("a held cutover queued %d host jobs", len(jobs))
	}
	findingStatus := func() string {
		t.Helper()
		status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/pqc/migrations/"+started.RunID, tok, nil)
		if status != http.StatusOK {
			t.Fatalf("progress = %d %s", status, body)
		}
		var progress struct {
			Findings []struct {
				AssetID string `json:"asset_id"`
				Status  string `json:"status"`
			} `json:"findings"`
		}
		if err := json.Unmarshal(body, &progress); err != nil {
			t.Fatal(err)
		}
		for _, finding := range progress.Findings {
			if finding.AssetID == asset.ID {
				return finding.Status
			}
		}
		t.Fatalf("progress has no finding for the asset: %s", body)
		return ""
	}
	if got := findingStatus(); got != pqcmigration.CertificateFindingAwaitingAcknowledgment {
		t.Fatalf("cutover finding = %q; want awaiting_acknowledgment", got)
	}

	worker := runtime.CutoverReleaseWorker(h.store, h.log, time.Hour)
	release := func(want int) {
		t.Helper()
		if released, err := worker.ReleaseOnce(ctx); err != nil || released != want {
			t.Fatalf("release pass = %d, %v; want %d", released, err, want)
		}
	}
	release(0) // no acknowledgment policy for the identity yet

	rpKey, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	roster, _ := json.Marshal([]retirement.RosterEntry{{RelyingParty: "rp-payments", PublicDER: rpKey.Public().DER}})
	pcas := pcasstore.New(h.store)
	if err := pcas.UpsertRetirementPolicy(ctx, h.tenant, pcasstore.RetirementPolicy{
		IdentityID: successorID, PredecessorEpoch: 1, Threshold: 1, RosterJSON: roster, ValidityWindowSeconds: 3600, Status: "active",
	}); err != nil {
		t.Fatal(err)
	}
	release(0) // a policy, but no acknowledgment

	acknowledge := func(epoch uint64) {
		t.Helper()
		signature, err := retirement.SignAck(rpKey, h.tenant, successorID, epoch, "rp-payments")
		if err != nil {
			t.Fatal(err)
		}
		ev, err := succession.Encode(succession.RPAckV1{IdentityID: successorID, TenantID: h.tenant, Epoch: epoch,
			RelyingParty: "rp-payments", AckSignature: signature})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.log.Append(ctx, events.Event{Type: ev.Type, TenantID: h.tenant, SchemaVersion: ev.SchemaVersion, Data: ev.Data}); err != nil {
			t.Fatal(err)
		}
	}
	acknowledge(2)
	release(0) // an acknowledgment for another epoch counts for nothing
	if jobs := renewJobs(); len(jobs) != 0 || findingStatus() != pqcmigration.CertificateFindingAwaitingAcknowledgment {
		t.Fatal("the cutover left its hold without the quorum")
	}

	acknowledge(1)
	if retiredFirst {
		if err := pcas.MarkRetirementRetired(ctx, h.tenant, successorID, 1); err != nil {
			t.Fatal(err)
		}
	}
	release(1)
	jobs := renewJobs()
	var pinnedAgent string
	if len(jobs) == 1 {
		if err := h.store.SystemPool().QueryRow(ctx, `SELECT coalesce(required_agent_id::text, '') FROM outbox WHERE id = $1`, jobs[0].ID).Scan(&pinnedAgent); err != nil {
			t.Fatal(err)
		}
	}
	if len(jobs) != 1 || pinnedAgent != agentRowID(h.tenant, h.agent) {
		t.Fatalf("released host jobs = %+v pinned to %q; want one on the target's host agent", jobs, pinnedAgent)
	}
	var job struct {
		SubjectKeyAlgorithm string `json:"subject_key_algorithm"`
		IdentityID          string `json:"identity_id"`
	}
	if err := json.Unmarshal(jobs[0].Payload, &job); err != nil || job.SubjectKeyAlgorithm != "ML-DSA-65" || job.IdentityID != successorID {
		t.Fatalf("released host job = %s (%v); want an ML-DSA-65 subject key for the identity", jobs[0].Payload, err)
	}
	if got := findingStatus(); got != "queued" {
		t.Fatalf("released cutover finding = %q; want queued", got)
	}
	if !h.hasEvent(t, pqcmigration.EventCertificateCutoverReleased) {
		t.Fatal("the release was not recorded")
	}
	release(0)
	if again := renewJobs(); len(again) != 1 {
		t.Fatalf("a second pass queued again: %d host jobs", len(again))
	}

	// The host generates the ML-DSA-65 key and sends only its CSR; trstctl
	// issues a pure ML-DSA-65 leaf for the identity. Issuance alone is not
	// deployment: the finding waits for the host's signed readback.
	claimed := claimOneRenewal(t, ctx, h)
	hostKey, err := pqc.GenerateHostMLDSASubjectKey(crypto.CertificateRequestTemplate{CommonName: dnsName, DNSNames: []string{dnsName}}, pqc.MLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	defer hostKey.Destroy()
	signed, err := h.client.SignJobCSR(ctx, &transport.SignJobCSRRequest{JobID: claimed.JobID, Attempt: claimed.Attempt, CSRDER: hostKey.CSRDER})
	if err != nil {
		t.Fatalf("sign the host's ML-DSA-65 CSR: %v", err)
	}
	leaf, err := h.store.GetCertificateByFingerprint(ctx, h.tenant, signed.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	info, err := certinfo.Inspect(leaf.CertificateDER)
	if err != nil || info.KeyAlgorithm != "ML-DSA-65" || leaf.KeyOrigin != "host_agent" {
		t.Fatalf("issued leaf key = %q, origin %q (%v); want a host-held pure ML-DSA-65 key", info.KeyAlgorithm, leaf.KeyOrigin, err)
	}
	if got := findingStatus(); got == "applied" {
		t.Fatal("issuance alone reported the cutover as applied")
	}
}
