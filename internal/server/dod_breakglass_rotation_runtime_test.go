//go:build trstctl_dodproof

// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/tools/dodcensus/proof"
)

const (
	dodBreakglassEntryID = "breakglass_rotation.cross_sign_rekey"
	dodBreakglassTenant  = "d0d00000-0000-4000-8000-000000000601"
	dodBreakglassOther   = "d0d00000-0000-4000-8000-000000000602"
)

// TestDODBreakglassRotationProductionAssembly first bootstraps the persisted
// signer handle through the served CA ceremony/create-root routes, then proves
// that configured handle through buildRunDeps -> Build. It exercises authenticated
// event-backed quorum, exact request binding, bidirectional CA rotation, restart
// replay, tenant isolation, signer-backed/offline-root cross-signing, and
// independent leaf chains through every returned cross-certificate.
func TestDODBreakglassRotationProductionAssembly(t *testing.T) {
	_ = dodRuntimeSelection(t, dodBreakglassEntryID)
	external := proof.StartCommand(t, "breakglass_rotation.cross_sign_rekey")
	verifierEndpoint := dodParentSubstrateLoopbackBridge(t, external.Endpoint())
	ctx := context.Background()
	dir := t.TempDir()
	st := newServerTestStore(t)
	natsDir := filepath.Join(dir, "nats")
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: natsDir, SyncAlways: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	signer, reconnectSigner := dodStartRestartableAuthorizedSoftwareSignerProcess(t, dir)
	cfg := config.Default()
	cfg.RateLimit.Enabled = false
	cfg.Audit.SigningKeyFile = filepath.Join(dir, "audit-signing-key.pem")
	cfg.Secrets.KEKFile = filepath.Join(dir, "secrets-kek.bin")
	cfg.Signer.KeyStoreDir = filepath.Join(dir, "signer-keys")
	cfg.CA.CertFile = filepath.Join(dir, "issuing-ca.crt")
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate bootstrap config: %v", err)
	}
	runSecrets, err := loadRunSecrets(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer runSecrets.Close()
	commander := dodSeedAPIToken(t, ctx, st, dodBreakglassTenant, "dod-breakglass-commander", []string{
		string(authz.CertsIssue), string(authz.IssuersRead), string(authz.IssuersWrite),
	})
	operatorA := dodSeedAPIToken(t, ctx, st, dodBreakglassTenant, "dod-operator-a", []string{string(authz.IssuersWrite)})
	operatorB := dodSeedAPIToken(t, ctx, st, dodBreakglassTenant, "dod-operator-b", []string{string(authz.IssuersWrite)})
	rogueOperator := dodSeedAPIToken(t, ctx, st, dodBreakglassTenant, "dod-operator-not-in-roster", []string{string(authz.IssuersWrite)})
	otherTenant := dodSeedAPIToken(t, ctx, st, dodBreakglassOther, "dod-other-tenant", []string{string(authz.CertsIssue)})

	// Bootstrap through the shipped CA hierarchy instead of constructing a signer
	// handle in the test. An operator can perform these exact CLI/API steps with
	// online break-glass disabled, then restart with the returned persisted handle.
	bootstrap := dodBreakglassBuildServer(t, ctx, cfg, st, log, signer, runSecrets)
	bootstrapSpec := map[string]any{
		"common_name": "DoD Breakglass Root", "permitted_dns_domains": []string{"dod-breakglass.test"},
		"max_path_len": 1, "extended_key_usages": []string{"serverAuth", "clientAuth"},
		"ttl_seconds": 259200, "signature_algorithm": "ecdsa-p256",
	}
	_, bootstrapCeremonyBody := dodBreakglassRequest(t, bootstrap, commander, http.MethodPost, "/api/v1/ca/ceremonies", "dod-bg-bootstrap-ceremony", map[string]any{
		"operation": "create_root", "threshold": 2, "spec": bootstrapSpec,
	}, http.StatusCreated)
	bootstrapCeremony := dodBreakglassCeremonyID(t, bootstrapCeremonyBody)
	dodBreakglassApproveTwo(t, bootstrap, operatorA, operatorB, bootstrapCeremony, "bootstrap")
	_, bootstrapAuthorityBody := dodBreakglassRequest(t, bootstrap, commander, http.MethodPost, "/api/v1/ca/authorities/roots", "dod-bg-bootstrap-create", map[string]any{
		"ceremony_id": bootstrapCeremony, "spec": bootstrapSpec,
	}, http.StatusCreated)
	var initialAuthority api.CAAuthority
	if err := json.Unmarshal(bootstrapAuthorityBody, &initialAuthority); err != nil || initialAuthority.SignerHandle == "" {
		t.Fatalf("decode served break-glass bootstrap authority: %+v err=%v body=%s", initialAuthority, err, bootstrapAuthorityBody)
	}
	initialCADER, err := oneCertificateDER(initialAuthority.CertificatePEM)
	if err != nil {
		t.Fatal(err)
	}
	initialPublicDER, err := crypto.PublicKeyDERFromCert(initialCADER)
	if err != nil {
		t.Fatal(err)
	}
	if err := bootstrap.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	signer = reconnectSigner()
	st = dodReopenBreakglassStore(t, ctx)
	log = dodReopenBreakglassLog(t, ctx, natsDir)
	caPath := filepath.Join(dir, "breakglass-ca.der")
	publicPath := filepath.Join(dir, "breakglass-public.der")
	if err := os.WriteFile(caPath, initialCADER, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicPath, initialPublicDER, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Breakglass = config.Breakglass{
		Enabled: true, OnlineEnabled: true, CACertFile: caPath, PublicKeyFile: publicPath,
		TenantID: dodBreakglassTenant, SignerHandle: initialAuthority.SignerHandle,
		Operators: []string{"dod-operator-a", "dod-operator-b", "dod-operator-c"}, Threshold: 2,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate production break-glass config: %v", err)
	}
	srv := dodBreakglassBuildServer(t, ctx, cfg, st, log, signer, runSecrets)

	workload, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer workload.Destroy()
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: "recovery.dod-breakglass.test", DNSNames: []string{"recovery.dod-breakglass.test"},
	}, workload)
	if err != nil {
		t.Fatal(err)
	}
	issueIntent := map[string]any{
		"request_id": "dod-breakglass-issue-1", "subject": "recovery.dod-breakglass.test",
		"csr_der": csr, "reason": "restore production while the primary issuer is isolated", "ttl_seconds": 900,
	}
	_, ceremonyBody := dodBreakglassRequest(t, srv, commander, http.MethodPost, "/api/v1/breakglass/issue-ceremonies", "dod-bg-issue-ceremony", issueIntent, http.StatusCreated)
	issueCeremony := dodBreakglassCeremonyID(t, ceremonyBody)
	dodBreakglassRequest(t, srv, operatorA, http.MethodPost, "/api/v1/ca/ceremonies/"+issueCeremony+"/approvals", "dod-bg-issue-approval-a", nil, http.StatusOK)
	issueIntent["ceremony_id"] = issueCeremony
	_, subquorum := dodBreakglassRequest(t, srv, commander, http.MethodPost, "/api/v1/breakglass/issue", "dod-bg-issue-subquorum", issueIntent, http.StatusUnprocessableEntity)
	dodBreakglassRequest(t, srv, operatorB, http.MethodPost, "/api/v1/ca/ceremonies/"+issueCeremony+"/approvals", "dod-bg-issue-approval-b", nil, http.StatusOK)
	altered := cloneDODBreakglassMap(issueIntent)
	altered["reason"] = "different request after approval"
	_, exactMismatch := dodBreakglassRequest(t, srv, commander, http.MethodPost, "/api/v1/breakglass/issue", "dod-bg-issue-mismatch", altered, http.StatusUnprocessableEntity)
	_, initialIssue := dodBreakglassRequest(t, srv, commander, http.MethodPost, "/api/v1/breakglass/issue", "dod-bg-issue-correct", issueIntent, http.StatusCreated)
	_, consumedReplay := dodBreakglassRequest(t, srv, commander, http.MethodPost, "/api/v1/breakglass/issue", "dod-bg-issue-consumed-replay", issueIntent, http.StatusUnprocessableEntity)

	unauthorizedIntent := map[string]any{
		"request_id": "dod-breakglass-unauthorized-roster", "subject": "roster.dod-breakglass.test",
		"csr_der": csr, "reason": "prove an authenticated non-roster actor has no signing authority", "ttl_seconds": 300,
	}
	_, unauthorizedCeremonyBody := dodBreakglassRequest(t, srv, commander, http.MethodPost, "/api/v1/breakglass/issue-ceremonies", "dod-bg-roster-ceremony", unauthorizedIntent, http.StatusCreated)
	unauthorizedCeremony := dodBreakglassCeremonyID(t, unauthorizedCeremonyBody)
	dodBreakglassRequest(t, srv, rogueOperator, http.MethodPost, "/api/v1/ca/ceremonies/"+unauthorizedCeremony+"/approvals", "dod-bg-roster-rogue", nil, http.StatusOK)
	dodBreakglassApproveTwo(t, srv, operatorA, operatorB, unauthorizedCeremony, "roster-authorized")
	unauthorizedIntent["ceremony_id"] = unauthorizedCeremony
	_, unauthorizedRoster := dodBreakglassRequest(t, srv, commander, http.MethodPost, "/api/v1/breakglass/issue", "dod-bg-roster-execute", unauthorizedIntent, http.StatusUnprocessableEntity)

	rotationIntent := map[string]any{"reason": "scheduled emergency authority re-key", "ttl_seconds": 172800}
	_, rotationCeremonyBody := dodBreakglassRequest(t, srv, commander, http.MethodPost, "/api/v1/breakglass/rotation-ceremonies", "dod-bg-rotate-ceremony", rotationIntent, http.StatusCreated)
	rotationCeremony := dodBreakglassCeremonyID(t, rotationCeremonyBody)
	dodBreakglassApproveTwo(t, srv, operatorA, operatorB, rotationCeremony, "rotate")
	rotationRequest := cloneDODBreakglassMap(rotationIntent)
	rotationRequest["ceremony_id"] = rotationCeremony
	_, rotation := dodBreakglassRequest(t, srv, commander, http.MethodPost, "/api/v1/breakglass/rotate", "dod-bg-rotate", rotationRequest, http.StatusCreated)

	status, crossTenant := dodBreakglassRequest(t, srv, otherTenant, http.MethodPost, "/api/v1/breakglass/issue-ceremonies", "dod-bg-other-tenant", map[string]any{
		"request_id": "cross-tenant", "subject": "cross-tenant.test", "csr_der": csr, "reason": "must fail", "ttl_seconds": 60,
	}, http.StatusInternalServerError)
	if status != http.StatusInternalServerError || !bytes.Contains(crossTenant, []byte(`"code":"problem.internal.error"`)) ||
		bytes.Contains(crossTenant, []byte(dodBreakglassTenant)) || bytes.Contains(crossTenant, []byte(dodBreakglassOther)) ||
		bytes.Contains(crossTenant, []byte("configured online break-glass tenant")) {
		t.Fatalf("tenant isolation response status=%d body=%s", status, crossTenant)
	}
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	// A production control-plane restart creates a fresh signer connection. The
	// old Client remains bound to the old Server's now-closed signing bulkhead and
	// must not be reused for pre-Build audit/break-glass handle binding.
	signer = reconnectSigner()
	st = dodReopenBreakglassStore(t, ctx)
	log = dodReopenBreakglassLog(t, ctx, natsDir)
	srv = dodBreakglassBuildServer(t, ctx, cfg, st, log, signer, runSecrets) // exact assembly restart replays active handle/certificate.
	defer func() { _ = srv.Shutdown(context.Background()) }()

	restartIntent := map[string]any{
		"request_id": "dod-breakglass-issue-after-restart", "subject": "restart.dod-breakglass.test",
		"csr_der": csr, "reason": "prove rotated signer replay after restart", "ttl_seconds": 600,
	}
	_, restartCeremonyBody := dodBreakglassRequest(t, srv, commander, http.MethodPost, "/api/v1/breakglass/issue-ceremonies", "dod-bg-restart-ceremony", restartIntent, http.StatusCreated)
	restartCeremony := dodBreakglassCeremonyID(t, restartCeremonyBody)
	dodBreakglassApproveTwo(t, srv, operatorA, operatorB, restartCeremony, "restart")
	restartIntent["ceremony_id"] = restartCeremony
	_, restartedIssue := dodBreakglassRequest(t, srv, commander, http.MethodPost, "/api/v1/breakglass/issue", "dod-bg-restart-issue", restartIntent, http.StatusCreated)

	targetResponse, err := http.Get(verifierEndpoint + "/v1/target")
	if err != nil {
		t.Fatalf("fetch independent target CA: %v", err)
	}
	targetPEM, err := io.ReadAll(io.LimitReader(targetResponse.Body, 1<<20))
	_ = targetResponse.Body.Close()
	if err != nil || targetResponse.StatusCode != http.StatusOK || !bytes.Contains(targetPEM, []byte("BEGIN CERTIFICATE")) {
		t.Fatalf("independent target response status=%d err=%v body=%s", targetResponse.StatusCode, err, targetPEM)
	}
	offlineResponse, err := http.Get(verifierEndpoint + "/v1/offline-package")
	if err != nil {
		t.Fatalf("fetch independent offline-root package: %v", err)
	}
	offlinePackageBody, err := io.ReadAll(io.LimitReader(offlineResponse.Body, 1<<20))
	_ = offlineResponse.Body.Close()
	var offlinePackage map[string]string
	if err != nil || offlineResponse.StatusCode != http.StatusOK || json.Unmarshal(offlinePackageBody, &offlinePackage) != nil {
		t.Fatalf("independent offline-root package status=%d err=%v body=%s", offlineResponse.StatusCode, err, offlinePackageBody)
	}
	for name, value := range offlinePackage {
		if !strings.Contains(value, "BEGIN CERTIFICATE") || strings.Contains(value, "PRIVATE KEY") {
			t.Fatalf("offline-root package %q is not certificate-only public material", name)
		}
	}

	signerCASpec := map[string]any{
		"common_name": "DoD Signer-Backed Cross Sign CA", "max_path_len": 1,
		"ttl_seconds": 172800, "signature_algorithm": "ecdsa-p256",
	}
	_, signerCACeremonyBody := dodBreakglassRequest(t, srv, commander, http.MethodPost, "/api/v1/ca/ceremonies", "dod-ca-root-ceremony", map[string]any{
		"operation": "create_root", "threshold": 2, "spec": signerCASpec,
	}, http.StatusCreated)
	signerCACeremony := dodBreakglassCeremonyID(t, signerCACeremonyBody)
	dodBreakglassApproveTwo(t, srv, operatorA, operatorB, signerCACeremony, "signer-ca-root")
	_, signerCA := dodBreakglassRequest(t, srv, commander, http.MethodPost, "/api/v1/ca/authorities/roots", "dod-ca-root-create", map[string]any{
		"ceremony_id": signerCACeremony, "spec": signerCASpec,
	}, http.StatusCreated)
	signerCAID := dodBreakglassAuthorityID(t, signerCA)
	_, signerCACrossCeremonyBody := dodBreakglassRequest(t, srv, commander, http.MethodPost, "/api/v1/ca/ceremonies", "dod-ca-cross-ceremony", map[string]any{
		"operation": "cross_sign_ca", "authority_id": signerCAID,
		"target_certificate_pem": string(targetPEM), "threshold": 2,
	}, http.StatusCreated)
	signerCACrossCeremony := dodBreakglassCeremonyID(t, signerCACrossCeremonyBody)
	dodBreakglassApproveTwo(t, srv, operatorA, operatorB, signerCACrossCeremony, "signer-ca-cross")
	_, signerCACross := dodBreakglassRequest(t, srv, commander, http.MethodPost, "/api/v1/ca/authorities/"+signerCAID+"/cross-sign", "dod-ca-cross-execute", map[string]any{
		"ceremony_id": signerCACrossCeremony, "certificate_pem": string(targetPEM),
	}, http.StatusCreated)

	offlineSpec := map[string]any{
		"common_name": "Independent Offline Root", "max_path_len": 1,
		"ttl_seconds": 172800, "signature_algorithm": "ecdsa-p256",
	}
	previousOfflinePEM := offlinePackage["offline_previous_certificate_pem"]
	successorOfflinePEM := offlinePackage["offline_successor_certificate_pem"]
	newByPreviousPEM := offlinePackage["new_signed_by_previous_pem"]
	previousByNewPEM := offlinePackage["previous_signed_by_new_pem"]
	targetByNewPEM := offlinePackage["target_signed_by_new_pem"]
	_, importOfflineCeremonyBody := dodBreakglassRequest(t, srv, commander, http.MethodPost, "/api/v1/ca/ceremonies", "dod-offline-root-ceremony", map[string]any{
		"operation": "import_offline_root", "certificate_pem": previousOfflinePEM,
		"threshold": 2, "spec": offlineSpec,
	}, http.StatusCreated)
	importOfflineCeremony := dodBreakglassCeremonyID(t, importOfflineCeremonyBody)
	dodBreakglassApproveTwo(t, srv, operatorA, operatorB, importOfflineCeremony, "offline-root")
	_, importedOfflineRoot := dodBreakglassRequest(t, srv, commander, http.MethodPost, "/api/v1/ca/authorities/offline-roots", "dod-offline-root-import", map[string]any{
		"ceremony_id": importOfflineCeremony, "certificate_pem": previousOfflinePEM, "spec": offlineSpec,
	}, http.StatusCreated)
	previousOfflineID := dodBreakglassAuthorityID(t, importedOfflineRoot)
	offlineReason := "rotate the disconnected recovery root without importing either private key"
	_, offlineRekeyCeremonyBody := dodBreakglassRequest(t, srv, commander, http.MethodPost, "/api/v1/ca/ceremonies", "dod-offline-rekey-ceremony", map[string]any{
		"operation": "rekey_offline_root", "authority_id": previousOfflineID,
		"certificate_pem": successorOfflinePEM, "cross_certificate_pem": newByPreviousPEM,
		"reverse_cross_certificate_pem": previousByNewPEM, "reason": offlineReason,
		"threshold": 2, "spec": offlineSpec,
	}, http.StatusCreated)
	offlineRekeyCeremony := dodBreakglassCeremonyID(t, offlineRekeyCeremonyBody)
	dodBreakglassApproveTwo(t, srv, operatorA, operatorB, offlineRekeyCeremony, "offline-rekey")
	_, offlineRekey := dodBreakglassRequest(t, srv, commander, http.MethodPost, "/api/v1/ca/authorities/"+previousOfflineID+"/offline-rekey", "dod-offline-rekey-execute", map[string]any{
		"ceremony_id": offlineRekeyCeremony, "successor_certificate_pem": successorOfflinePEM,
		"new_signed_by_previous_pem": newByPreviousPEM, "previous_signed_by_new_pem": previousByNewPEM,
		"reason": offlineReason, "spec": offlineSpec,
	}, http.StatusCreated)
	successorOfflineID := dodBreakglassOfflineSuccessorID(t, offlineRekey)
	_, offlineCrossCeremonyBody := dodBreakglassRequest(t, srv, commander, http.MethodPost, "/api/v1/ca/ceremonies", "dod-offline-cross-ceremony", map[string]any{
		"operation": "import_offline_cross_sign", "authority_id": successorOfflineID,
		"target_certificate_pem": string(targetPEM), "cross_certificate_pem": targetByNewPEM,
		"threshold": 2,
	}, http.StatusCreated)
	offlineCrossCeremony := dodBreakglassCeremonyID(t, offlineCrossCeremonyBody)
	dodBreakglassApproveTwo(t, srv, operatorA, operatorB, offlineCrossCeremony, "offline-cross")
	_, offlineCrossImport := dodBreakglassRequest(t, srv, commander, http.MethodPost, "/api/v1/ca/authorities/"+successorOfflineID+"/offline-cross-signs", "dod-offline-cross-import", map[string]any{
		"ceremony_id": offlineCrossCeremony, "target_certificate_pem": string(targetPEM),
		"cross_certificate_pem": targetByNewPEM,
	}, http.StatusCreated)

	crossIntent := map[string]any{"certificate_pem": string(targetPEM)}
	_, crossCeremonyBody := dodBreakglassRequest(t, srv, commander, http.MethodPost, "/api/v1/breakglass/cross-sign-ceremonies", "dod-bg-cross-ceremony", crossIntent, http.StatusCreated)
	crossCeremony := dodBreakglassCeremonyID(t, crossCeremonyBody)
	dodBreakglassApproveTwo(t, srv, operatorA, operatorB, crossCeremony, "cross")
	crossIntent["ceremony_id"] = crossCeremony
	rawCross, err := json.Marshal(crossIntent)
	if err != nil {
		t.Fatal(err)
	}
	finalRequest, err := http.NewRequest(http.MethodPost, "/api/v1/breakglass/cross-sign", bytes.NewReader(rawCross))
	if err != nil {
		t.Fatal(err)
	}
	finalRequest.Header.Set("Authorization", "Bearer "+commander)
	finalRequest.Header.Set("Idempotency-Key", "dod-bg-cross-execute")
	finalRequest.Header.Set("Content-Type", "application/json")
	session := proof.Start(t, "breakglass_rotation.cross_sign_rekey", srv.Handler(), finalRequest)
	if session.StatusCode() != http.StatusCreated {
		t.Fatalf("final cross-sign status=%d body=%s", session.StatusCode(), session.ResponseBody())
	}
	issueRequest, err := json.Marshal(issueIntent)
	if err != nil {
		t.Fatal(err)
	}
	verification := map[string]any{
		"protocol":             "trstctl-breakglass-rotation-v1",
		"initial_ca_pem":       base64.StdEncoding.EncodeToString([]byte(initialAuthority.CertificatePEM)),
		"bootstrap_authority":  base64.StdEncoding.EncodeToString(bootstrapAuthorityBody),
		"issue_request":        base64.StdEncoding.EncodeToString(issueRequest),
		"subquorum":            base64.StdEncoding.EncodeToString(subquorum),
		"exact_mismatch":       base64.StdEncoding.EncodeToString(exactMismatch),
		"consumed_replay":      base64.StdEncoding.EncodeToString(consumedReplay),
		"unauthorized_roster":  base64.StdEncoding.EncodeToString(unauthorizedRoster),
		"cross_tenant":         base64.StdEncoding.EncodeToString(crossTenant),
		"initial_issue":        base64.StdEncoding.EncodeToString(initialIssue),
		"rotation":             base64.StdEncoding.EncodeToString(rotation),
		"restarted_issue":      base64.StdEncoding.EncodeToString(restartedIssue),
		"target_ca_pem":        base64.StdEncoding.EncodeToString(targetPEM),
		"cross_sign":           base64.StdEncoding.EncodeToString(session.ResponseBody()),
		"signer_ca":            base64.StdEncoding.EncodeToString(signerCA),
		"signer_ca_cross":      base64.StdEncoding.EncodeToString(signerCACross),
		"offline_rekey":        base64.StdEncoding.EncodeToString(offlineRekey),
		"offline_cross_import": base64.StdEncoding.EncodeToString(offlineCrossImport),
	}
	verifierReadback := dodBreakglassVerifyTranscript(t, verifierEndpoint, verification)
	executionReceipt := external.StopAndReceipt()
	transcript := bytes.Join([][]byte{
		bootstrapAuthorityBody, issueRequest, subquorum, exactMismatch, consumedReplay, unauthorizedRoster, crossTenant,
		initialIssue, rotation, restartedIssue, targetPEM,
		signerCA, signerCACross, importedOfflineRoot, offlineRekey, offlineCrossImport,
		session.ResponseBody(),
	}, nil)
	session.Complete(proof.IndependentInterop(proof.IndependentInteropProbe{
		ClientIdentity: []byte("OpenSSL independent break-glass chain verifier"), Transcript: transcript,
		IndependentVerifier: verifierReadback, ExecutionReceipt: executionReceipt,
	}))
}

func dodReopenBreakglassStore(t *testing.T, ctx context.Context) *store.Store {
	t.Helper()
	st, err := store.Open(ctx, serverTestPostgresDSN(t))
	if err != nil {
		t.Fatalf("reopen break-glass store: %v", err)
	}
	t.Cleanup(st.Close)
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate reopened break-glass store: %v", err)
	}
	return st
}

func dodReopenBreakglassLog(t *testing.T, ctx context.Context, dir string) *events.Log {
	t.Helper()
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: dir, SyncAlways: true})
	if err != nil {
		t.Fatalf("reopen break-glass event log: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	return log
}

func dodBreakglassBuildServer(t *testing.T, ctx context.Context, cfg *config.Config, st *store.Store, log *events.Log, signer runSigner, sec runSecrets) *Server {
	t.Helper()
	guard, err := egressGuardFromConfig(cfg.AirGap)
	if err != nil {
		t.Fatal(err)
	}
	deps, err := buildRunDeps(ctx, cfg, st, log, signer, sec, slog.New(slog.NewTextHandler(io.Discard, nil)), guard)
	if err != nil {
		t.Fatalf("production buildRunDeps: %v", err)
	}
	srv, err := Build(ctx, deps)
	if err != nil {
		t.Fatalf("Build production deps: %v", err)
	}
	return srv
}

func dodBreakglassRequest(t *testing.T, srv *Server, token, method, path, idempotency string, body any, want int) (int, []byte) {
	t.Helper()
	var raw []byte
	var err error
	if body != nil {
		raw, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	req, err := http.NewRequest(method, path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if idempotency != "" {
		req.Header.Set("Idempotency-Key", idempotency)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response := &dodHTTPRecorder{header: make(http.Header), status: http.StatusOK}
	srv.Handler().ServeHTTP(response, req)
	if response.status != want {
		t.Fatalf("%s %s status=%d want=%d body=%s", method, path, response.status, want, response.body.Bytes())
	}
	return response.status, append([]byte(nil), response.body.Bytes()...)
}

func dodBreakglassCeremonyID(t *testing.T, body []byte) string {
	t.Helper()
	var ceremony api.BreakglassCeremony
	if err := json.Unmarshal(body, &ceremony); err != nil || ceremony.ID == "" || ceremony.Threshold != 2 {
		t.Fatalf("decode break-glass ceremony: %+v err=%v body=%s", ceremony, err, body)
	}
	return ceremony.ID
}

func dodBreakglassAuthorityID(t *testing.T, body []byte) string {
	t.Helper()
	var authority api.CAAuthority
	if err := json.Unmarshal(body, &authority); err != nil || authority.ID == "" {
		t.Fatalf("decode CA authority: %+v err=%v body=%s", authority, err, body)
	}
	return authority.ID
}

func dodBreakglassOfflineSuccessorID(t *testing.T, body []byte) string {
	t.Helper()
	var rekey api.CAOfflineRootRekey
	if err := json.Unmarshal(body, &rekey); err != nil || rekey.Rotation.Successor.ID == "" || rekey.Rotation.Successor.SignerHandle != "" {
		t.Fatalf("decode offline-root successor: %+v err=%v body=%s", rekey, err, body)
	}
	return rekey.Rotation.Successor.ID
}

func dodBreakglassApproveTwo(t *testing.T, srv *Server, operatorA, operatorB, ceremonyID, prefix string) {
	t.Helper()
	dodBreakglassRequest(t, srv, operatorA, http.MethodPost, "/api/v1/ca/ceremonies/"+ceremonyID+"/approvals", "dod-bg-"+prefix+"-approval-a", nil, http.StatusOK)
	dodBreakglassRequest(t, srv, operatorB, http.MethodPost, "/api/v1/ca/ceremonies/"+ceremonyID+"/approvals", "dod-bg-"+prefix+"-approval-b", nil, http.StatusOK)
}

func cloneDODBreakglassMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func dodBreakglassVerifyTranscript(t *testing.T, endpoint string, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.Post(endpoint+"/v1/verify", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("independent OpenSSL verifier: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil || response.StatusCode != http.StatusOK || len(body) < 16 {
		t.Fatalf("independent OpenSSL verifier status=%d err=%v body=%s", response.StatusCode, err, body)
	}
	return body
}
