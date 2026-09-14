// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/adcs"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/enrollmentdiag"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

const servedDiagnosticTenantB = "22222222-2222-2222-2222-222222222222"

type refusingDiagnosticADCS struct{}

func (refusingDiagnosticADCS) Name() string { return "AUD-49 AD CS" }
func (refusingDiagnosticADCS) Issue(context.Context, ca.IssueRequest) (ca.Certificate, error) {
	return ca.Certificate{}, &adcs.RefusalError{
		RequestID: 49, Disposition: adcs.DispDenied, Code: "0x80094800",
	}
}

// AUD-49: callbacks count only if the assembled protocol mounts persist their
// exact refusal evidence. This drives EST's auth boundary and SCEP's Intune
// challenge boundary through the real TLS listener, then reads the RLS-backed
// API as the same tenant.
func TestServedESTAndSCEPRefusalsPersistExactEvidence(t *testing.T) {
	intuneCfg, _ := servedSCEPIntuneChallenge(t, "unused-valid-device")
	h := newServedHarness(t, config.Protocols{
		EST:                 config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
		SCEP:                config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
		SCEPIntuneChallenge: intuneCfg,
	})
	readToken := seedScopedToken(t, h.store, h.tenant, "certs:read")

	estReq, err := http.NewRequest(http.MethodPost, h.ts.URL+"/.well-known/est/simpleenroll", strings.NewReader("not-read-because-auth-refuses"))
	if err != nil {
		t.Fatal(err)
	}
	estResp, err := h.ts.Client().Do(estReq)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = readAllClose(estResp)
	if estResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("served EST refusal status = %d, want 401", estResp.StatusCode)
	}

	caResp, err := h.ts.Client().Get(h.ts.URL + "/scep?operation=GetCACert")
	if err != nil {
		t.Fatal(err)
	}
	caBody, _ := readAllClose(caResp)
	raCertDER := scepRARecipient(t, caBody)
	clientCert, clientKey, csrDER := newSCEPClient(t, "SERIAL-AUD49")
	pkiMessage, err := crypto.BuildSCEPRequest(csrDER, clientCert, clientKey, raCertDER, "txn-aud49")
	if err != nil {
		t.Fatal(err)
	}
	scepResp, err := h.ts.Client().Post(h.ts.URL+"/scep?operation=PKIOperation", "application/x-pki-message", bytes.NewReader(pkiMessage))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = readAllClose(scepResp)
	if scepResp.StatusCode != http.StatusForbidden {
		t.Fatalf("served SCEP refusal status = %d, want 403", scepResp.StatusCode)
	}

	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/enrollment/diagnostics", readToken, nil)
	if status != http.StatusOK {
		t.Fatalf("list served diagnostics: status=%d body=%s", status, body)
	}
	var got api.EnrollmentDiagnosticList
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Items) != 2 {
		t.Fatalf("served diagnostics = %+v, want one EST and one SCEP refusal", got.Items)
	}
	byProtocol := map[string]api.EnrollmentDiagnostic{}
	for _, item := range got.Items {
		byProtocol[item.Protocol] = item
	}
	estDiagnostic := byProtocol["est"]
	if estDiagnostic.OperationRef != "POST /.well-known/est/simpleenroll" || estDiagnostic.IdentityRef != "principal:unauthorized" ||
		estDiagnostic.EndpointRef == "" || estDiagnostic.VerificationAddress != "" {
		t.Fatalf("served EST evidence = %+v, want exact operation/principal/refused listener and no guessed deployment", estDiagnostic)
	}
	scepDiagnostic := byProtocol["scep"]
	if scepDiagnostic.OperationRef != "scep:txn-aud49" || scepDiagnostic.IdentityRef != "device:SERIAL-AUD49" ||
		scepDiagnostic.EndpointRef == "" || scepDiagnostic.VerificationKind != "" {
		t.Fatalf("served SCEP evidence = %+v, want exact transaction/device/refused listener and no guessed deployment", scepDiagnostic)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/enrollment/diagnostics/support-addendum", readToken, nil)
	if status != http.StatusOK {
		t.Fatalf("diagnostic support addendum: status=%d body=%s", status, body)
	}
	for _, forbidden := range []string{"operation_ref", "identity_ref", "endpoint_ref", "diagnostic_id", "tenant_id", "observed_at", "txn-aud49", "SERIAL-AUD49"} {
		if bytes.Contains(body, []byte(forbidden)) {
			t.Fatalf("diagnostic support addendum leaked %q: %s", forbidden, body)
		}
	}
	var addendum api.EnrollmentDiagnosticsSupportAddendum
	if err := json.Unmarshal(body, &addendum); err != nil {
		t.Fatal(err)
	}
	if len(addendum.Rows) != 2 || addendum.SchemaVersion != 1 {
		t.Fatalf("diagnostic support addendum = %+v, want two typed aggregate rows", addendum)
	}
}

// AD CS is an outbox-owned upstream rather than an HTTP enrollment mount. Drive
// that real delivery boundary and prove its allow-listed HRESULT becomes a
// typed, tenant-scoped row without retaining the upstream status message.
func TestServedADCSRefusalPersistsSafeExactEvidence(t *testing.T) {
	const caID = "corp-adcs-aud49"
	h := newServedHarness(t, config.Protocols{}, func(deps *Deps) {
		deps.ExternalCAs = []ExternalCA{{
			ID: caID, Type: "adcs", TenantID: servedTestTenant,
			Endpoint: "https://adcs.example.test/certsrv", CA: refusingDiagnosticADCS{},
		}}
	})
	csr := externalCACSR(t, "aud49.adcs.example.test")
	payload, err := json.Marshal(ca.ExternalIssuePayload{
		AuthorityID: caID, TenantID: h.tenant, CSR: csr,
		DNSNames: []string{"aud49.adcs.example.test"}, TTLNanos: int64(time.Hour),
		ProviderIdempotencyKey: ca.ProviderIdempotencyKey("aud49-adcs-issue"),
		RequestBinding:         "aud49-adcs-binding",
	})
	if err != nil {
		t.Fatal(err)
	}
	err = h.srv.externalCAs.DeliverExternalCAIssue(t.Context(), orchestrator.Message{
		TenantID: h.tenant, Destination: ca.DestinationExternalCAIssue,
		IdempotencyKey: "aud49-adcs-issue", Payload: payload,
	})
	if err == nil {
		t.Fatal("AD CS refusal unexpectedly succeeded")
	}
	token := seedScopedToken(t, h.store, h.tenant, "certs:read")
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/enrollment/diagnostics", token, nil)
	if status != http.StatusOK {
		t.Fatalf("list AD CS diagnostic: status=%d body=%s", status, body)
	}
	var got api.EnrollmentDiagnosticList
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Items) != 1 {
		t.Fatalf("AD CS diagnostics = %+v, want one", got.Items)
	}
	diagnosis := got.Items[0]
	if diagnosis.Protocol != "adcs" || diagnosis.Cause != "template_acl_denied" ||
		diagnosis.OperationRef != "external-ca:"+caID+":aud49-adcs-issue" ||
		diagnosis.IdentityRef != "dns:aud49.adcs.example.test" ||
		diagnosis.EndpointRef != "https://adcs.example.test/certsrv" ||
		diagnosis.VerificationAddress != "" {
		t.Fatalf("AD CS diagnostic = %+v, want typed safe refusal and exact workflow refs", diagnosis)
	}
	if strings.Contains(string(body), "StatusMessage") || strings.Contains(string(body), "submitted credentials") {
		t.Fatalf("AD CS diagnostic leaked raw upstream status: %s", body)
	}
}

// The action is the missing half of a diagnostic: it queues D2's existing
// network-agent handshake, then links the agent-signed transcript back to the
// original failed operation. It must be authorization-gated and idempotent.
func TestServedEnrollmentDiagnosticProveFixedQueuesAndLinksSignedResult(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleNetwork}, relay.KindEndpointVerify)
	repairedEndpoint := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(repairedEndpoint.Close)
	repairedAddress := strings.TrimPrefix(repairedEndpoint.URL, "https://")
	if len(repairedEndpoint.Certificate().DNSNames) == 0 {
		t.Fatal("repair fixture certificate has no DNS identity")
	}
	repairedDNSName := strings.ToLower(repairedEndpoint.Certificate().DNSNames[0])
	targetConfig, err := json.Marshal(map[string]string{
		"verify_address": repairedAddress, "verify_server_name": repairedDNSName,
	})
	if err != nil {
		t.Fatal(err)
	}
	target, err := h.srv.orch.UpsertDeploymentTarget(ctx, h.tenant, store.DeploymentTarget{
		Name: "AUD-49 repaired listener", Type: "nginx", Config: targetConfig, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	owner, err := h.srv.orch.CreateOwner(ctx, h.tenant, "workload", "AUD-49 repaired workload", "")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := h.srv.orch.CreateIdentity(ctx, h.tenant, store.Identity{
		Kind: store.KindX509Certificate, Name: repairedDNSName, OwnerID: owner.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.orch.BindIdentityDeploymentTarget(ctx, h.tenant, identity.ID, target); err != nil {
		t.Fatal(err)
	}
	obsoleteCertificatePEM, obsoleteKeyPEM := issueHostPair(t, h, repairedDNSName)
	t.Cleanup(func() { secret.Wipe(obsoleteKeyPEM) })
	obsoleteInfo, err := certinfo.Inspect(obsoleteCertificatePEM)
	if err != nil {
		t.Fatal(err)
	}
	obsoleteCertificateDER, err := certinfo.LeafDER(obsoleteCertificatePEM)
	if err != nil {
		t.Fatal(err)
	}
	obsoleteNotBefore, obsoleteNotAfter := obsoleteInfo.NotBefore, obsoleteInfo.NotAfter
	if _, err := h.srv.orch.RecordCertificate(ctx, h.tenant, store.Certificate{
		OwnerID: &owner.ID, Subject: repairedDNSName, SANs: obsoleteInfo.DNSNames, Issuer: obsoleteInfo.Issuer,
		Serial: obsoleteInfo.SerialNumber, Fingerprint: obsoleteInfo.SHA256Fingerprint, KeyAlgorithm: obsoleteInfo.KeyAlgorithm,
		NotBefore: &obsoleteNotBefore, NotAfter: &obsoleteNotAfter, Source: "issued", Status: "active",
		CertificateDER: obsoleteCertificateDER, CertificatePEM: obsoleteCertificatePEM,
	}); err != nil {
		t.Fatal(err)
	}
	diagnosis := enrollmentdiag.Diagnose(enrollmentdiag.ProtocolEST, enrollmentdiag.StepAuthorize,
		enrollmentdiag.CauseTemplateACLDenied).WithEvidence(enrollmentdiag.Evidence{
		OperationRef: "est-enroll:aud49-prove", IdentityRef: "dns:" + repairedDNSName,
		EndpointRef: "est-enrollment.example.test:8443",
	})
	if err := h.srv.api.RecordEnrollmentDiagnosis(ctx, h.tenant, diagnosis); err != nil {
		t.Fatal(err)
	}
	readToken := seedScopedToken(t, h.store, h.tenant, "certs:read")
	issueToken := seedScopedToken(t, h.store, h.tenant, "certs:issue")
	listed := assertServedDiagnosticTenant(t, h.servedHarness, readToken, "template_acl_denied", 1)
	diagnosticID := listed.Items[0].ID
	if listed.Items[0].VerificationAddress != repairedAddress || listed.Items[0].ExpectedFingerprint != "" {
		t.Fatalf("recorded verification route = %+v, want exact configured target and no pre-retry certificate", listed.Items[0])
	}
	path := "/api/v1/enrollment/diagnostics/" + diagnosticID + "/prove-fixed"

	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, path, readToken, "aud49-read-only", nil); status != http.StatusForbidden {
		t.Fatalf("read-only prove-fixed = %d %s, want 403", status, body)
	}
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, path, issueToken, "aud49-before-retry", nil); status != http.StatusConflict ||
		!bytes.Contains(body, []byte("retry the enrollment successfully")) {
		t.Fatalf("prove-fixed before successful retry = %d %s, want explanatory 409", status, body)
	}
	info, err := certinfo.Inspect(repairedEndpoint.Certificate().Raw)
	if err != nil {
		t.Fatal(err)
	}
	notBefore, notAfter := info.NotBefore, info.NotAfter
	repairedCertificate, err := h.srv.orch.RecordCertificate(ctx, h.tenant, store.Certificate{
		OwnerID: &owner.ID, Subject: repairedDNSName, SANs: info.DNSNames, Issuer: info.Issuer,
		Serial: info.SerialNumber, Fingerprint: info.SHA256Fingerprint, KeyAlgorithm: info.KeyAlgorithm,
		NotBefore: &notBefore, NotAfter: &notAfter, Source: "issued", Status: "active",
		CertificateDER: repairedEndpoint.Certificate().Raw,
		CertificatePEM: crypto.EncodeCertificatePEM(repairedEndpoint.Certificate().Raw),
	})
	if err != nil {
		t.Fatal(err)
	}
	resolvedTarget, err := h.store.GetEnrollmentDiagnosticVerificationTarget(ctx, h.tenant, diagnosticID)
	if err != nil {
		t.Fatalf("resolve post-failure certificate created=%s observed=%s fingerprint=%s sans=%v: %v",
			repairedCertificate.CreatedAt.UTC().Format(time.RFC3339Nano), resolvedTarget.ObservedAt.UTC().Format(time.RFC3339Nano),
			repairedCertificate.Fingerprint, repairedCertificate.SANs, err)
	}
	status, firstBody := secretsReqKey(t, h.servedHarness, http.MethodPost, path, issueToken, "aud49-prove", nil)
	if status != http.StatusAccepted {
		t.Fatalf("prove-fixed = %d %s, want 202", status, firstBody)
	}
	status, replayBody := secretsReqKey(t, h.servedHarness, http.MethodPost, path, issueToken, "aud49-prove", nil)
	if status != http.StatusAccepted || !bytes.Equal(firstBody, replayBody) {
		t.Fatalf("prove-fixed replay = %d %s, want exact cached 202 %s", status, replayBody, firstBody)
	}
	var queued api.EnrollmentDiagnosticVerification
	if err := json.Unmarshal(firstBody, &queued); err != nil {
		t.Fatal(err)
	}
	if queued.DiagnosticID != diagnosticID || queued.Status != "queued" || queued.ResultPath == "" {
		t.Fatalf("queued prove-fixed = %+v, want linked diagnostic/result", queued)
	}
	// Simulate the append-ACK / SQL-rollback crash window by removing the job
	// row while retaining its immutable queued event. Boot reconciliation must
	// recreate that exact network-only command once.
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`DELETE FROM outbox WHERE tenant_id = $1 AND destination = $2`,
			h.tenant, relay.KindEndpointVerify)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	healed, err := h.srv.orch.ReconcileOutbox(ctx, h.log)
	if err != nil || healed != 1 {
		t.Fatalf("prove-fixed outbox reconciliation healed=%d err=%v, want 1", healed, err)
	}

	channel := &servedHostRelayChannel{client: h.client, identity: h.identity}
	processed, err := relay.RunOnce(ctx, channel, http.DefaultClient, 5, 60)
	if err != nil || processed != 1 || channel.lastOutcome != relay.OutcomeExecuted || !channel.lastAccepted {
		t.Fatalf("real network relay prove-fixed run: processed=%d outcome=%q accepted=%t err=%v report_err=%v",
			processed, channel.lastOutcome, channel.lastAccepted, err, channel.lastReportErr)
	}
	// The production binary runs the projection tailer. The served harness does
	// not start background workers, so replay the signed observation through the
	// same production projector before reading the linked result.
	projector := projections.New(h.store)
	if err := h.log.Replay(ctx, 0, func(event events.Event) error {
		if event.TenantID == h.tenant && event.Type == projections.EventEndpointVerified {
			return projector.Apply(ctx, event)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(3 * time.Second)
	var proved api.EnrollmentDiagnostic
	for time.Now().Before(deadline) {
		listed = assertServedDiagnosticTenant(t, h.servedHarness, readToken, "template_acl_denied", 1)
		proved = listed.Items[0]
		if proved.VerificationStatus == "verified" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if proved.VerificationStatus != "verified" || proved.VerificationEvidenceDigest == "" || proved.VerificationAgent != h.agent ||
		proved.VerificationResultPath != queued.ResultPath || proved.ExpectedFingerprint != repairedCertificate.Fingerprint {
		t.Fatalf("proved diagnostic = %+v, want green signed result link", proved)
	}
	if status, body := secretsReq(t, h.servedHarness, http.MethodGet, queued.ResultPath, readToken, nil); status != http.StatusOK ||
		!bytes.Contains(body, []byte(proved.VerificationEvidenceDigest)) {
		t.Fatalf("signed result link = %d %s, want exact evidence digest", status, body)
	}

	if err := h.store.UpsertTenant(ctx, store.Tenant{TenantID: servedDiagnosticTenantB, Name: "foreign diagnostic tenant"}); err != nil {
		t.Fatal(err)
	}
	foreignIssueToken := seedScopedToken(t, h.store, servedDiagnosticTenantB, "certs:issue")
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, path, foreignIssueToken, "aud49-foreign", nil); status != http.StatusNotFound {
		t.Fatalf("foreign tenant prove-fixed = %d %s, want tenant-scoped 404", status, body)
	}

	// Exercise the supported complete rebuild, which also resets the derived
	// event receipts and metadata ordering state before replaying retained history.
	projector = projections.New(h.store)
	if err := projector.Rebuild(ctx, h.log); err != nil {
		t.Fatalf("complete diagnostic rebuild: %v", err)
	}

	rebuilt := assertServedDiagnosticTenant(t, h.servedHarness, readToken, "template_acl_denied", 1).Items[0]
	if rebuilt.VerificationStatus != "verified" || rebuilt.VerificationEvidenceDigest != proved.VerificationEvidenceDigest ||
		rebuilt.VerificationResultPath != proved.VerificationResultPath {
		t.Fatalf("cold-rebuilt diagnostic = %+v, want exact signed green link", rebuilt)
	}
}

func TestServedEnrollmentDiagnosticWithoutExactRouteRefusesProveFixed(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	diagnosis := enrollmentdiag.Diagnose(enrollmentdiag.ProtocolEST, enrollmentdiag.StepAuthorize,
		enrollmentdiag.CauseTemplateACLDenied).WithEvidence(enrollmentdiag.Evidence{
		OperationRef: "est-enroll:aud49-no-route", IdentityRef: "dns:no-route.example.test",
		EndpointRef: "est-enrollment.example.test:8443",
	})
	if err := h.srv.api.RecordEnrollmentDiagnosis(context.Background(), h.tenant, diagnosis); err != nil {
		t.Fatal(err)
	}
	readToken := seedScopedToken(t, h.store, h.tenant, "certs:read")
	issueToken := seedScopedToken(t, h.store, h.tenant, "certs:issue")
	listed := assertServedDiagnosticTenant(t, h, readToken, "template_acl_denied", 1)
	path := "/api/v1/enrollment/diagnostics/" + listed.Items[0].ID + "/prove-fixed"
	status, body := secretsReqKey(t, h, http.MethodPost, path, issueToken, "aud49-no-route", nil)
	if status != http.StatusConflict || !bytes.Contains(body, []byte("exact deployment target")) {
		t.Fatalf("prove-fixed without route = %d %s, want explanatory 409", status, body)
	}
}

// This is the AUD-48 wire proof. One failure enters through the actual ACME
// refusal choke point while another tenant reports through that protocol
// callback's production API seam. Authenticated API reads, event envelopes, and
// a clean replay must all preserve the same boundary.
func TestServedEnrollmentDiagnosticsAreTenantScopedEvents(t *testing.T) {
	ctx := context.Background()
	h := newServedHarness(t, config.Protocols{
		ACME: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
	})
	if err := h.store.UpsertTenant(ctx, store.Tenant{TenantID: servedDiagnosticTenantB, Name: "diagnostic tenant B"}); err != nil {
		t.Fatalf("seed tenant B: %v", err)
	}
	tokenA := seedScopedToken(t, h.store, h.tenant, "certs:read")
	tokenB := seedScopedToken(t, h.store, servedDiagnosticTenantB, "certs:read")

	start := make(chan struct{})
	errCh := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		errCh <- causeServedACMERefusal(h)
	}()
	go func() {
		defer wg.Done()
		<-start
		errCh <- h.srv.api.RecordEnrollmentDiagnosis(ctx, servedDiagnosticTenantB,
			enrollmentdiag.Diagnose(enrollmentdiag.ProtocolACME, enrollmentdiag.StepValidation, enrollmentdiag.CauseChallengeNotVisible))
	}()
	close(start)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	// A second refusal of the same class must change only tenant A's count.
	if err := causeServedACMERefusal(h); err != nil {
		t.Fatal(err)
	}

	wantA := assertServedDiagnosticTenant(t, h, tokenA, "unknown", 2)
	wantB := assertServedDiagnosticTenant(t, h, tokenB, string(enrollmentdiag.CauseChallengeNotVisible), 1)
	if wantA.Items[0].Summary == wantB.Items[0].Summary {
		t.Fatalf("test setup did not produce distinguishable tenant rows: A=%+v B=%+v", wantA, wantB)
	}

	eventCounts := map[string]int{}
	if err := h.log.Replay(ctx, 0, func(event events.Event) error {
		if event.Type == projections.EventEnrollmentDiagnosticObserved {
			eventCounts[event.TenantID]++
		}
		return nil
	}); err != nil {
		t.Fatalf("replay diagnostic evidence: %v", err)
	}
	if eventCounts[h.tenant] != 2 || eventCounts[servedDiagnosticTenantB] != 1 {
		t.Fatalf("diagnostic event envelopes = %+v, want tenant A=2 tenant B=1", eventCounts)
	}

	// Delete both derived tables and replay only their immutable source events.
	// API tokens remain in their independent table, so the same authenticated
	// callers can verify the rebuilt projection over the same served route.
	if _, err := h.store.SystemPool().Exec(ctx,
		"TRUNCATE enrollment_diagnostic_observations, enrollment_diagnostics"); err != nil {
		t.Fatalf("truncate diagnostic projection: %v", err)
	}
	projector := projections.New(h.store)
	if err := h.log.Replay(ctx, 0, func(event events.Event) error {
		if event.Type != projections.EventEnrollmentDiagnosticObserved {
			return nil
		}
		return projector.Apply(ctx, event)
	}); err != nil {
		t.Fatalf("rebuild diagnostic projection: %v", err)
	}
	assertServedDiagnosticTenant(t, h, tokenA, "unknown", 2)
	assertServedDiagnosticTenant(t, h, tokenB, string(enrollmentdiag.CauseChallengeNotVisible), 1)
}

func causeServedACMERefusal(h *servedHarness) error {
	response, err := h.ts.Client().Get(h.ts.URL + "/directory")
	if err != nil {
		return fmt.Errorf("read served ACME directory: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	var directory struct {
		NewAccount string `json:"newAccount"`
	}
	if err := json.NewDecoder(response.Body).Decode(&directory); err != nil {
		return fmt.Errorf("decode served ACME directory: %w", err)
	}
	request, err := http.NewRequest(http.MethodPost, directory.NewAccount, strings.NewReader("{}"))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/jose+json")
	refusal, err := h.ts.Client().Do(request)
	if err != nil {
		return fmt.Errorf("cause served ACME refusal: %w", err)
	}
	defer func() { _ = refusal.Body.Close() }()
	_, _ = io.Copy(io.Discard, refusal.Body)
	if refusal.StatusCode < 400 {
		return fmt.Errorf("malformed ACME new-account returned %d, want a refusal", refusal.StatusCode)
	}
	return nil
}

func assertServedDiagnosticTenant(t *testing.T, h *servedHarness, token, wantCause string, wantCount int64) api.EnrollmentDiagnosticList {
	t.Helper()
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/enrollment/diagnostics", token, nil)
	if status != http.StatusOK {
		t.Fatalf("list enrollment diagnostics: status=%d body=%s", status, body)
	}
	var got api.EnrollmentDiagnosticList
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode enrollment diagnostics: %v body=%s", err, body)
	}
	if len(got.Items) != 1 || got.Items[0].Cause != wantCause || got.Items[0].Count != wantCount {
		t.Fatalf("tenant diagnostics = %+v, want one %s row with count %d", got, wantCause, wantCount)
	}
	if got.Items[0].ObservedAt == "" || !strings.Contains(got.Guidance, "durable tenant-scoped events") {
		t.Fatalf("tenant diagnostics omit durable timestamp/guidance: %+v", got)
	}
	return got
}
