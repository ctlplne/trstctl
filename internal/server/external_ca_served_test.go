// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/digicert"
	"trstctl.com/trstctl/internal/ca/digicert/digicertfake"
	"trstctl.com/trstctl/internal/ca/letsencrypt"
	"trstctl.com/trstctl/internal/ca/letsencrypt/acmefake"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// TestServedExternalCARegistryIssuesViaConfiguredBackends is the CLM-03 acceptance
// test: the running control-plane binary exposes a served external-CA registry and
// routes issuance through configured upstream CA plugins. The calls are HTTP API
// requests against server.Build -> Handler, not package-level plugin calls, and the
// issue path proves both AN-5 replay behavior and the ca.issue outbox record (AN-6).
func TestServedExternalCARegistryIssuesViaConfiguredBackends(t *testing.T) {
	dc, err := digicertfake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dc.Close)
	acme, err := acmefake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(acme.Close)
	account, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate test ACME account signer: %v", err)
	}
	t.Cleanup(account.Destroy)
	le, err := letsencrypt.NewPluginWithRemoteAccountSigner("lets-encrypt", acme.DirectoryURL(), http.DefaultClient, account)
	if err != nil {
		t.Fatalf("letsencrypt remote-account plugin: %v", err)
	}
	t.Cleanup(le.Destroy)

	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.APIOptions = append(d.APIOptions, api.WithInsecureHeaderResolver())
		d.ExternalCAs = []ExternalCA{
			{ID: "digicert", Type: "digicert", CA: digicert.New("digicert", dc.URL(), []byte(dc.APIKey()), digicert.WithHTTPClient(&http.Client{Timeout: 5 * time.Second}))},
			{ID: "lets-encrypt", Type: "letsencrypt", CA: le},
		}
	})

	var listed struct {
		Items []externalCAListItem `json:"items"`
	}
	code, body := doExternalCARequest(t, h, http.MethodGet, "/api/v1/external-cas", "", nil)
	if code != http.StatusOK {
		t.Fatalf("list external CAs = %d, want 200; body=%s", code, body)
	}
	if err := json.Unmarshal(body, &listed); err != nil {
		t.Fatalf("decode external CA list: %v body=%s", err, body)
	}
	if !hasExternalCA(listed.Items, "digicert", "digicert") || !hasExternalCA(listed.Items, "lets-encrypt", "letsencrypt") {
		t.Fatalf("registry items = %+v, want digicert and lets-encrypt", listed.Items)
	}

	digiBody := externalCAIssueRequestBody(t, "svc.digicert.served.test")
	digi := issueExternalCAWithBody(t, h, "digicert", "clm-03-digicert", digiBody)
	assertServedCert(t, digi, "digicert", "svc.digicert.served.test")
	if got := externalCAOutboxCount(t, h, "clm-03-digicert:external-ca:digicert"); got != 1 {
		t.Fatalf("DigiCert ca.issue outbox rows = %d, want 1", got)
	}
	digiReplay := issueExternalCAWithBody(t, h, "digicert", "clm-03-digicert", digiBody)
	if digiReplay.Serial != digi.Serial || digiReplay.CertificatePEM != digi.CertificatePEM {
		t.Fatalf("DigiCert replay minted a different cert: first=%s replay=%s", digi.Serial, digiReplay.Serial)
	}
	if got := externalCAOutboxCount(t, h, "clm-03-digicert:external-ca:digicert"); got != 1 {
		t.Fatalf("DigiCert replay ca.issue rows = %d, want still 1", got)
	}

	acmeCert := issueExternalCA(t, h, "lets-encrypt", "svc.acme.served.test", "clm-03-lets-encrypt")
	assertServedCert(t, acmeCert, "lets-encrypt", "svc.acme.served.test")
	if got := externalCAOutboxCount(t, h, "clm-03-lets-encrypt:external-ca:lets-encrypt"); got != 1 {
		t.Fatalf("Let's Encrypt ca.issue outbox rows = %d, want 1", got)
	}
}

func TestExternalCAResponseWaitsForIssueRecordCommit(t *testing.T) {
	dc, err := digicertfake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dc.Close)
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.APIOptions = append(d.APIOptions, api.WithInsecureHeaderResolver())
		d.ExternalCAs = []ExternalCA{{
			ID:   "digicert",
			Type: "digicert",
			CA: digicert.New(
				"digicert",
				dc.URL(),
				[]byte(dc.APIKey()),
				digicert.WithHTTPClient(&http.Client{Timeout: 5 * time.Second}),
			),
		}}
	})

	const advisoryLockKey int64 = 728662
	ctx := context.Background()
	lockConn, err := h.store.SystemPool().Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire advisory-lock connection: %v", err)
	}
	var unlockOnce sync.Once
	unlock := func() {
		unlockOnce.Do(func() {
			if _, err := lockConn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, advisoryLockKey); err != nil {
				t.Errorf("unlock ca.issue insert barrier: %v", err)
			}
			lockConn.Release()
		})
	}
	t.Cleanup(func() {
		// The issue transaction can be waiting inside the trigger below. Release
		// its advisory lock before dropping the trigger, or a failed assertion
		// can deadlock cleanup while DROP waits for that transaction to finish.
		unlock()
		_, err := h.store.SystemPool().Exec(context.Background(), `
			DROP TRIGGER IF EXISTS trstctl_test_block_ca_issue_insert ON outbox;
			DROP FUNCTION IF EXISTS trstctl_test_block_ca_issue_insert()
		`)
		if err != nil {
			t.Errorf("remove ca.issue insert barrier: %v", err)
		}
	})
	if _, err := lockConn.Exec(ctx, `SELECT pg_advisory_lock($1)`, advisoryLockKey); err != nil {
		t.Fatalf("lock ca.issue insert barrier: %v", err)
	}
	if _, err := h.store.SystemPool().Exec(ctx, fmt.Sprintf(`
		CREATE OR REPLACE FUNCTION trstctl_test_block_ca_issue_insert()
		RETURNS trigger
		LANGUAGE plpgsql
		AS $$
		BEGIN
			IF NEW.destination = 'ca.issue' THEN
				PERFORM pg_advisory_xact_lock(%d);
			END IF;
			RETURN NEW;
		END
		$$;
		DROP TRIGGER IF EXISTS trstctl_test_block_ca_issue_insert ON outbox;
		CREATE TRIGGER trstctl_test_block_ca_issue_insert
		BEFORE INSERT ON outbox
		FOR EACH ROW
		EXECUTE FUNCTION trstctl_test_block_ca_issue_insert()
	`, advisoryLockKey)); err != nil {
		t.Fatalf("install ca.issue insert barrier: %v", err)
	}

	const rawKey = "external-ca-record-ordering"
	serviceKey := rawKey + ":external-ca:digicert"
	body, err := json.Marshal(externalCAIssueRequestBody(t, "ordering.digicert.served.test"))
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, h.ts.URL+"/api/v1/external-cas/digicert/issue", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Tenant-ID", h.tenant)
	req.Header.Set("X-Roles", "admin")
	req.Header.Set("X-Subject", "clm-03-admin")
	req.Header.Set("Idempotency-Key", rawKey)
	req.Header.Set("Content-Type", "application/json")

	type issueResult struct {
		status int
		body   []byte
		err    error
	}
	result := make(chan issueResult, 1)
	startServedExternalCADispatcher(t, h)
	go func() {
		resp, err := h.ts.Client().Do(req)
		if err != nil {
			result <- issueResult{err: err}
			return
		}
		defer func() { _ = resp.Body.Close() }()
		responseBody, readErr := io.ReadAll(resp.Body)
		result <- issueResult{status: resp.StatusCode, body: responseBody, err: readErr}
	}()

	projectionDeadline := time.NewTimer(5 * time.Second)
	defer projectionDeadline.Stop()
	projectionPoll := time.NewTicker(5 * time.Millisecond)
	defer projectionPoll.Stop()
	for {
		_, err := h.store.GetIssuedCertificateRecovery(ctx, h.tenant, serviceKey)
		if err == nil {
			break
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("read durable external-CA result: %v", err)
		}
		select {
		case got := <-result:
			t.Fatalf("served response escaped before durable projection was observable: status=%d err=%v body=%s", got.status, got.err, got.body)
		case <-projectionPoll.C:
		case <-projectionDeadline.C:
			t.Fatal("timed out waiting for durable external-CA projection")
		}
	}

	select {
	case got := <-result:
		t.Fatalf("served response escaped before ca.issue record commit: status=%d err=%v body=%s", got.status, got.err, got.body)
	case <-time.After(250 * time.Millisecond):
	}

	unlock()
	select {
	case got := <-result:
		if got.err != nil {
			t.Fatalf("issue request after ca.issue record commit: %v", got.err)
		}
		if got.status != http.StatusCreated {
			t.Fatalf("issue request after ca.issue record commit = %d, want 201; body=%s", got.status, got.body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("issue request did not complete after ca.issue record commit")
	}
	if got := externalCAOutboxCount(t, h, serviceKey); got != 1 {
		t.Fatalf("ca.issue rows after served response = %d, want 1", got)
	}
}

func TestServedDirectCADiscoveryInventoryCAPDISC04(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.APIOptions = append(d.APIOptions, api.WithInsecureHeaderResolver())
		d.ExternalCAs = []ExternalCA{
			{ID: "digicert-prod", Type: "digicert", CA: newIdempotentExternalCA("digicert-prod")},
			{ID: "corp-adcs", Type: "adcs", CA: newIdempotentExternalCA("corp-adcs")},
		}
	})
	operator := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "cap-disc-04-operator", []string{
		"issuers:write", "issuers:read",
	})
	approver := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "cap-disc-04-approver", []string{
		"issuers:write", "issuers:read",
	})

	privateRootKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(privateRootKey.Destroy)
	privateRoot, err := crypto.SelfSignedHierarchyCA(privateRootKey, crypto.HierarchyCAProfile{
		CommonName:          "customer private offline root",
		MaxPathLen:          1,
		TTL:                 365 * 24 * time.Hour,
		PermittedDNSDomains: []string{"corp.example.test"},
		EKUs:                []string{"serverAuth"},
	})
	if err != nil {
		t.Fatalf("create private root fixture: %v", err)
	}
	privateSpec := map[string]any{
		"common_name":           "customer private offline root",
		"max_path_len":          1,
		"ttl_seconds":           int64((365 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"corp.example.test"},
		"extended_key_usages":   []string{"serverAuth"},
		"signature_algorithm":   "ecdsa-p256",
	}
	ceremony := createCACeremonyWithCertificate(t, h, operator, "import_offline_root", string(privateRoot.CertificatePEM), privateSpec, 1, "cap-disc-04-offline-root-ceremony")
	approveCACeremony(t, h, approver, ceremony.ID, 1, "cap-disc-04-offline-root-approval")
	importedPrivate := importOfflineRootCA(t, h, operator, ceremony.ID, string(privateRoot.CertificatePEM), privateSpec, "cap-disc-04-offline-root-import")

	code, raw := doBearer(t, h.ts, http.MethodGet, "/api/v1/ca/discovery", operator, "", nil)
	if code != http.StatusOK {
		t.Fatalf("direct CA discovery inventory = %d body=%s; want 200", code, raw)
	}
	var got caDiscoveryInventoryResponse
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decode CA discovery inventory: %v body=%s", err, raw)
	}
	if !hasCADiscoveryItem(got.Items, "external-ca/digicert-prod", "public", "external_ca_registry") {
		t.Fatalf("CA discovery items = %+v, want public DigiCert upstream", got.Items)
	}
	if !hasCADiscoveryItem(got.Items, "external-ca/corp-adcs", "private", "external_ca_registry") {
		t.Fatalf("CA discovery items = %+v, want private ADCS upstream", got.Items)
	}
	if !hasCADiscoveryItem(got.Items, "ca-authority/"+importedPrivate.ID, "private", "ca_hierarchy") {
		t.Fatalf("CA discovery items = %+v, want imported private hierarchy CA %s", got.Items, importedPrivate.ID)
	}
	if got.Summary.PublicCount < 1 || got.Summary.PrivateCount < 2 || got.Summary.ExternalRegistryCount != 2 || got.Summary.AuthorityCount != 1 {
		t.Fatalf("CA discovery summary = %+v, want public/private external and imported authority counts", got.Summary)
	}
	if strings.Contains(string(raw), "PRIVATE KEY") || strings.Contains(string(raw), "BEGIN CERTIFICATE") {
		t.Fatalf("CA discovery inventory leaked key or certificate PEM: %s", raw)
	}
}

func TestExternalCAOutboxIntentExistsBeforeProviderIssue(t *testing.T) {
	const (
		caID    = "guarded"
		idemKey = "spine-001"
		dnsName = "svc.spine-001.served.test"
	)
	issueKey := idemKey + ":external-ca:" + caID
	guard := &externalCAIntentGuard{
		key: issueKey,
	}
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.APIOptions = append(d.APIOptions, api.WithInsecureHeaderResolver())
		guard.store = d.Store
		d.ExternalCAs = []ExternalCA{{ID: caID, Type: "guarded", CA: guard}}
	})

	issued := issueExternalCA(t, h, caID, dnsName, idemKey)
	if issued.Serial == "" {
		t.Fatal("guarded external CA returned no certificate serial")
	}
	if guard.calls != 1 {
		t.Fatalf("provider Issue calls = %d, want 1", guard.calls)
	}
	if got := externalCAIntentOutboxCount(t, h, issueKey); got != 1 {
		t.Fatalf("external CA intent outbox rows = %d, want 1", got)
	}
	if got := guard.providerToken; got != ca.ProviderIdempotencyKey(issueKey) {
		t.Fatalf("provider idempotency token = %q, want derived token %q", got, ca.ProviderIdempotencyKey(issueKey))
	}
}

func TestExternalCAIssueNeverDrainsUnrelatedWorkOnRequestPath(t *testing.T) {
	const (
		targetCA    = "target"
		unrelatedCA = "unrelated"
		idemKey     = "external-ca-isolation"
	)
	set := bulkhead.NewSet(
		bulkhead.Config{Name: bulkhead.SubsystemAPI, Workers: 2, Queue: 8},
		bulkhead.Config{Name: bulkhead.SubsystemOutbox, Workers: 1, Queue: 0},
	)
	t.Cleanup(set.Close)
	blocked := &externalCABlockingProbe{name: unrelatedCA}
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.Bulkhead = set
		d.ExternalCAs = []ExternalCA{
			{ID: targetCA, Type: "probe", CA: newIdempotentExternalCA(targetCA)},
			{ID: unrelatedCA, Type: "probe", CA: blocked},
		}
	})

	csr := externalCACSR(t, "svc.external-ca-isolation.test")
	payload, err := json.Marshal(ca.ExternalIssuePayload{
		AuthorityID: unrelatedCA, TenantID: h.tenant, CSR: csr,
		DNSNames: []string{"unrelated.external-ca-isolation.test"}, TTLNanos: int64(time.Hour),
		ProviderIdempotencyKey: ca.ProviderIdempotencyKey("older-unrelated-external-ca"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.WithTenant(context.Background(), h.tenant, func(tx pgx.Tx) error {
		_, err := h.srv.outbox.Enqueue(context.Background(), tx, orchestrator.Entry{
			TenantID: h.tenant, Destination: ca.DestinationExternalCAIssue,
			IdempotencyKey: "older-unrelated-external-ca", Payload: payload,
		})
		return err
	}); err != nil {
		t.Fatalf("enqueue unrelated external CA work: %v", err)
	}

	release := make(chan struct{})
	occupied := make(chan struct{})
	var releaseOnce sync.Once
	releaseWorker := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseWorker)
	if err := set.Pool(bulkhead.SubsystemOutbox).Submit(func() {
		close(occupied)
		<-release
	}); err != nil {
		t.Fatalf("occupy outbox bulkhead: %v", err)
	}
	<-occupied
	startServedExternalCADispatcher(t, h)

	requestCtx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err = h.srv.externalCAs.IssueExternalCA(requestCtx, h.tenant, targetCA, idemKey, "external-ca-isolation-binding", api.ExternalCAIssueRequest{
		CSRDER: csr, DNSNames: []string{"svc.external-ca-isolation.test"}, TTLSeconds: 3600,
	})
	elapsed := time.Since(started)
	if !errors.Is(err, api.ErrExternalCAUpstream) || !strings.Contains(err.Error(), "timed out") {
		releaseWorker()
		t.Fatalf("isolated issue error = %v, want sanitized request timeout while bounded worker is saturated", err)
	}
	if elapsed > time.Second {
		releaseWorker()
		t.Fatalf("isolated issue took %s, want prompt request-context cancellation", elapsed)
	}
	if calls := blocked.calls.Load(); calls != 0 {
		releaseWorker()
		t.Fatalf("request path dispatched unrelated external CA %d times; only RunDispatcher may deliver outbox work", calls)
	}
	releaseWorker()
}

func TestExternalCAOutboxCrashRecovery(t *testing.T) {
	const (
		caID    = "crashy"
		idemKey = "red-003-crash"
		dnsName = "svc.red-003-crash.served.test"
	)
	upstream := newIdempotentExternalCA(caID)
	upstream.failFirst = true
	upstream.requireOutboxWorker = true
	upstream.tenantID = servedTestTenant
	upstream.outboxKey = idemKey + ":external-ca:" + caID
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.APIOptions = append(d.APIOptions, api.WithInsecureHeaderResolver())
		upstream.store = d.Store
		d.ExternalCAs = []ExternalCA{{ID: caID, Type: "crashy", CA: upstream, ReplaySafety: ca.ExternalIssueReconciled}}
	})
	startServedExternalCADispatcher(t, h)

	csrDER := externalCACSR(t, dnsName)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	req := map[string]any{
		"csr_pem":     string(csrPEM),
		"dns_names":   []string{dnsName},
		"ttl_seconds": int64((24 * time.Hour).Seconds()),
	}
	code, body := doExternalCARequest(t, h, http.MethodPost, "/api/v1/external-cas/"+caID+"/issue", idemKey, req)
	if code != http.StatusBadGateway {
		t.Fatalf("first crashy external CA issue = %d, want 502; body=%s", code, body)
	}
	if upstream.mints != 1 || upstream.calls != 1 {
		t.Fatalf("first provider calls=%d mints=%d, want one upstream mint before local recovery", upstream.calls, upstream.mints)
	}
	forceExternalCAOutboxDue(t, h, idemKey+":external-ca:"+caID)

	code, body = doExternalCARequest(t, h, http.MethodPost, "/api/v1/external-cas/"+caID+"/issue", idemKey, req)
	if code != http.StatusCreated {
		t.Fatalf("retry crashy external CA issue = %d, want 201; body=%s", code, body)
	}
	var recovered externalCAIssueResponse
	if err := json.Unmarshal(body, &recovered); err != nil {
		t.Fatalf("decode recovered external CA response: %v body=%s", err, body)
	}
	if recovered.Serial == "" || recovered.Serial != upstream.lastSerial {
		t.Fatalf("recovered serial = %q, want upstream serial %q", recovered.Serial, upstream.lastSerial)
	}
	if upstream.calls != 2 {
		t.Fatalf("provider calls = %d, want retry delivery to call provider with same idempotency token", upstream.calls)
	}
	if upstream.mints != 1 {
		t.Fatalf("provider mints = %d, want exactly one upstream certificate across crash+retry", upstream.mints)
	}
	if got := externalCAOutboxCount(t, h, idemKey+":external-ca:"+caID); got != 1 {
		t.Fatalf("ca.issue observability rows = %d, want exactly 1 after recovery", got)
	}
}

func TestExternalCARetryDoesNotDoubleMint(t *testing.T) {
	const (
		caID    = "idempotent"
		idemKey = "red-003-retry"
		dnsName = "svc.red-003-retry.served.test"
	)
	upstream := newIdempotentExternalCA(caID)
	upstream.requireOutboxWorker = true
	upstream.tenantID = servedTestTenant
	upstream.outboxKey = idemKey + ":external-ca:" + caID
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.APIOptions = append(d.APIOptions, api.WithInsecureHeaderResolver())
		upstream.store = d.Store
		d.ExternalCAs = []ExternalCA{{ID: caID, Type: "idempotent", CA: upstream}}
	})

	body := externalCAIssueRequestBody(t, dnsName)
	first := issueExternalCAWithBody(t, h, caID, idemKey, body)
	second := issueExternalCAWithBody(t, h, caID, idemKey, body)
	if second.Serial != first.Serial || second.CertificatePEM != first.CertificatePEM {
		t.Fatalf("external CA idempotent retry changed certificate: first=%s second=%s", first.Serial, second.Serial)
	}
	if upstream.calls != 1 || upstream.mints != 1 {
		t.Fatalf("provider calls=%d mints=%d, want one provider delivery and one upstream mint", upstream.calls, upstream.mints)
	}
	if got := externalCAOutboxCount(t, h, idemKey+":external-ca:"+caID); got != 1 {
		t.Fatalf("ca.issue observability rows = %d, want exactly 1", got)
	}
}

func TestExternalCAReplaySurvivesResponseAndOutboxGCAndRejectsChangedCaller(t *testing.T) {
	const (
		caID    = "durable-binding"
		idemKey = "external-ca-durable-binding"
		dnsName = "svc.external-ca-durable-binding.test"
	)
	upstream := newIdempotentExternalCA(caID)
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.APIOptions = append(d.APIOptions, api.WithInsecureHeaderResolver())
		d.ExternalCAs = []ExternalCA{{ID: caID, Type: "test", CA: upstream}}
	})
	body := externalCAIssueRequestBody(t, dnsName)
	startServedExternalCADispatcher(t, h)
	code, firstRaw := doExternalCARequest(t, h, http.MethodPost, "/api/v1/external-cas/"+caID+"/issue", idemKey, body)
	if code != http.StatusCreated {
		t.Fatalf("initial durable external CA issue = %d body=%s", code, firstRaw)
	}
	var first externalCAIssueResponse
	if err := json.Unmarshal(firstRaw, &first); err != nil {
		t.Fatalf("decode initial durable response: %v", err)
	}
	if upstream.calls != 1 || upstream.mints != 1 {
		t.Fatalf("initial provider calls=%d mints=%d, want 1/1", upstream.calls, upstream.mints)
	}
	intentID := externalCAIntentOutboxID(t, h, idemKey+":external-ca:"+caID)
	waitForOutboxStatus(t, h.srv.outbox, h.tenant, intentID, "delivered")
	purgeExternalCAWorkerResult(t, h, idemKey, caID)
	forceExternalCAOutboxDue(t, h, idemKey+":external-ca:"+caID)
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("reconcile crash-after-certificate-record: %v", err)
	}
	if upstream.calls != 1 || upstream.mints != 1 {
		t.Fatalf("worker crash recovery repeated provider: calls=%d mints=%d", upstream.calls, upstream.mints)
	}
	purgeExternalCAEphemeralState(t, h, idemKey, caID)

	code, replayRaw := doExternalCARequest(t, h, http.MethodPost, "/api/v1/external-cas/"+caID+"/issue", idemKey, body)
	if code != http.StatusCreated {
		t.Fatalf("post-GC replay = %d body=%s", code, replayRaw)
	}
	if !bytes.Equal(replayRaw, firstRaw) {
		t.Fatalf("post-GC replay bytes changed:\nfirst=%s\nreplay=%s", firstRaw, replayRaw)
	}
	var replay externalCAIssueResponse
	if err := json.Unmarshal(replayRaw, &replay); err != nil {
		t.Fatalf("decode replay response: %v", err)
	}
	if replay.Serial != first.Serial || replay.CertificatePEM != first.CertificatePEM {
		t.Fatalf("post-GC replay changed result: first=%s replay=%s", first.Serial, replay.Serial)
	}
	if upstream.calls != 1 || upstream.mints != 1 {
		t.Fatalf("post-GC replay reached provider: calls=%d mints=%d", upstream.calls, upstream.mints)
	}

	// Remove the freshly recreated bounded HTTP response, leaving only the
	// certificate.recorded projection as authority. A different caller must hit a
	// durable conflict before provider I/O.
	purgeExternalCAAPIResult(t, h, idemKey)
	code, response := doExternalCARequestAs(t, h, http.MethodPost, "/api/v1/external-cas/"+caID+"/issue", idemKey, "different-issuer", body)
	if code != http.StatusConflict {
		t.Fatalf("changed caller after GC = %d body=%s, want 409", code, response)
	}
	if upstream.calls != 1 || upstream.mints != 1 {
		t.Fatalf("changed caller reached provider: calls=%d mints=%d", upstream.calls, upstream.mints)
	}
}

func TestExternalCASanitizeUpstreamErrors(t *testing.T) {
	const caID = "leaky"
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.APIOptions = append(d.APIOptions, api.WithInsecureHeaderResolver())
		d.ExternalCAs = []ExternalCA{{
			ID:   caID,
			Type: "leaky",
			CA: externalCALeakyFailure{
				err: fmt.Errorf("provider POST https://127.0.0.1:8200/v1/pki/sign/web?token=secret-token failed: upstream body secret-upstream-body"),
			},
		}}
	})
	startServedExternalCADispatcher(t, h)

	csrDER := externalCACSR(t, "svc.leaky.served.test")
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	code, body := doExternalCARequest(t, h, http.MethodPost, "/api/v1/external-cas/"+caID+"/issue", "sanitize-001", map[string]any{
		"csr_pem":     string(csrPEM),
		"dns_names":   []string{"svc.leaky.served.test"},
		"ttl_seconds": int64((24 * time.Hour).Seconds()),
	})
	if code != http.StatusBadGateway {
		t.Fatalf("leaky external CA status = %d, want 502; body=%s", code, body)
	}
	got := string(body)
	for _, leak := range []string{"127.0.0.1", "8200", "secret-token", "secret-upstream-body", "https://"} {
		if strings.Contains(got, leak) {
			t.Fatalf("external CA problem leaked %q: %s", leak, got)
		}
	}
	if !strings.Contains(got, "external CA upstream request failed") {
		t.Fatalf("external CA problem body = %s, want sanitized upstream detail", got)
	}
}

type externalCALeakyFailure struct {
	err error
}

type externalCABlockingProbe struct {
	name  string
	calls atomic.Int64
}

func (p *externalCABlockingProbe) Name() string { return p.name }

func (p *externalCABlockingProbe) Issue(ctx context.Context, _ ca.IssueRequest) (ca.Certificate, error) {
	p.calls.Add(1)
	<-ctx.Done()
	return ca.Certificate{}, ctx.Err()
}

func (f externalCALeakyFailure) Name() string { return "leaky-external-ca" }

func (f externalCALeakyFailure) Issue(context.Context, ca.IssueRequest) (ca.Certificate, error) {
	return ca.Certificate{}, f.err
}

type externalCAIntentGuard struct {
	store         *store.Store
	key           string
	calls         int
	providerToken string
}

type idempotentExternalCA struct {
	name                string
	failFirst           bool
	requireOutboxWorker bool
	store               *store.Store
	tenantID            string
	outboxKey           string
	calls               int
	mints               int
	lastSerial          string
	issued              map[string]ca.Certificate
}

func newIdempotentExternalCA(name string) *idempotentExternalCA {
	return &idempotentExternalCA{name: name, issued: map[string]ca.Certificate{}}
}

func (f *idempotentExternalCA) Name() string { return f.name }

func (f *idempotentExternalCA) Issue(_ context.Context, req ca.IssueRequest) (ca.Certificate, error) {
	f.calls++
	if req.ProviderIdempotencyKey == "" {
		return ca.Certificate{}, errors.New("missing provider idempotency key")
	}
	if f.requireOutboxWorker {
		if err := f.assertOutboxWorker(req.ProviderIdempotencyKey); err != nil {
			return ca.Certificate{}, err
		}
	}
	if cert, ok := f.issued[req.ProviderIdempotencyKey]; ok {
		return cert, nil
	}
	f.mints++
	cert, err := testExternalCACertificate(req, f.Name())
	if err != nil {
		return ca.Certificate{}, err
	}
	f.issued[req.ProviderIdempotencyKey] = cert
	f.lastSerial = cert.Serial
	if f.failFirst {
		f.failFirst = false
		return ca.Certificate{}, errors.New("simulated process crash after upstream mint")
	}
	return cert, nil
}

func (f *idempotentExternalCA) assertOutboxWorker(providerToken string) error {
	if f.store == nil || f.tenantID == "" || f.outboxKey == "" {
		return errors.New("outbox worker assertion is missing store, tenant, or key")
	}
	if providerToken != ca.ProviderIdempotencyKey(f.outboxKey) {
		return fmt.Errorf("provider idempotency token = %q, want %q", providerToken, ca.ProviderIdempotencyKey(f.outboxKey))
	}
	var status string
	err := f.store.WithTenant(context.Background(), f.tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `
			SELECT status
			FROM outbox
			WHERE destination = 'external-ca.issue'
			  AND idempotency_key = $1
		`, f.outboxKey).Scan(&status)
	})
	if err != nil {
		return err
	}
	if status != "processing" {
		return fmt.Errorf("external CA provider called outside outbox worker; outbox status = %q", status)
	}
	return nil
}

func (g *externalCAIntentGuard) Name() string { return "guarded-external-ca" }

func (g *externalCAIntentGuard) Issue(ctx context.Context, req ca.IssueRequest) (ca.Certificate, error) {
	g.calls++
	g.providerToken = req.ProviderIdempotencyKey
	count := 0
	if err := g.store.WithTenant(ctx, req.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT count(*)
			FROM outbox
			WHERE destination = 'external-ca.issue'
			  AND idempotency_key = $1
		`, g.key).Scan(&count)
	}); err != nil {
		return ca.Certificate{}, err
	}
	if count != 1 {
		return ca.Certificate{}, fmt.Errorf("external CA provider called before durable outbox intent; count=%d", count)
	}
	if req.ProviderIdempotencyKey != ca.ProviderIdempotencyKey(g.key) {
		return ca.Certificate{}, fmt.Errorf("provider idempotency token = %q, want %q", req.ProviderIdempotencyKey, ca.ProviderIdempotencyKey(g.key))
	}
	return testExternalCACertificate(req, g.Name())
}

// testExternalCACertificate makes the provider seam return a real leaf, not a
// PEM-shaped placeholder. The served issuance worker now projects the public
// certificate into durable inventory, so the test double must satisfy the same
// cryptographic parse/verification contract as a real upstream CA.
func testExternalCACertificate(req ca.IssueRequest, issuer string) (ca.Certificate, error) {
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		return ca.Certificate{}, err
	}
	defer signer.Destroy()
	caDER, err := crypto.SelfSignedCACert(signer, issuer, 48*time.Hour)
	if err != nil {
		return ca.Certificate{}, err
	}
	ttl := req.TTL
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	leafDER, err := crypto.SignLeafFromCSR(caDER, signer, req.CSR, ttl)
	if err != nil {
		return ca.Certificate{}, err
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	info, err := certinfo.Inspect(leafPEM)
	if err != nil {
		return ca.Certificate{}, err
	}
	return ca.Certificate{
		CertificatePEM: leafPEM,
		Serial:         info.SerialNumber,
		NotAfter:       info.NotAfter.UTC(),
		Issuer:         info.Issuer,
	}, nil
}

type externalCAIssueResponse struct {
	CertificatePEM string    `json:"certificate_pem"`
	Serial         string    `json:"serial"`
	NotAfter       time.Time `json:"not_after"`
	Issuer         string    `json:"issuer"`
}

type externalCAListItem struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Name string `json:"name"`
}

func issueExternalCA(t *testing.T, h *servedHarness, caID, dnsName, idem string) externalCAIssueResponse {
	t.Helper()
	return issueExternalCAWithBody(t, h, caID, idem, externalCAIssueRequestBody(t, dnsName))
}

func externalCAIssueRequestBody(t *testing.T, dnsName string) map[string]any {
	t.Helper()
	csrDER := externalCACSR(t, dnsName)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return map[string]any{
		"csr_pem": string(csrPEM), "dns_names": []string{dnsName},
		"ttl_seconds": int64((24 * time.Hour).Seconds()),
	}
}

func issueExternalCAWithBody(t *testing.T, h *servedHarness, caID, idem string, body map[string]any) externalCAIssueResponse {
	t.Helper()
	startServedExternalCADispatcher(t, h)
	code, response := doExternalCARequest(t, h, http.MethodPost, "/api/v1/external-cas/"+caID+"/issue", idem, body)
	if code != http.StatusCreated {
		t.Fatalf("issue through %s = %d, want 201; body=%s", caID, code, response)
	}
	var got externalCAIssueResponse
	if err := json.Unmarshal(response, &got); err != nil {
		t.Fatalf("decode issue response from %s: %v body=%s", caID, err, response)
	}
	return got
}

func externalCACSR(t *testing.T, dnsName string) []byte {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: dnsName, DNSNames: []string{dnsName}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

func doExternalCARequest(t *testing.T, h *servedHarness, method, path, idem string, body any) (int, []byte) {
	t.Helper()
	return doExternalCARequestAs(t, h, method, path, idem, "clm-03-admin", body)
}

func doExternalCARequestAs(t *testing.T, h *servedHarness, method, path, idem, subject string, body any) (int, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, h.ts.URL+path, rdr)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Tenant-ID", h.tenant)
	req.Header.Set("X-Roles", "admin")
	req.Header.Set("X-Subject", subject)
	if idem != "" {
		req.Header.Set("Idempotency-Key", idem)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := h.ts.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func purgeExternalCAAPIResult(t *testing.T, h *servedHarness, rawKey string) {
	t.Helper()
	if err := h.store.WithTenant(context.Background(), h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `DELETE FROM idempotency_keys WHERE tenant_id = $1 AND key = $2`, h.tenant, rawKey)
		return err
	}); err != nil {
		t.Fatalf("purge external CA API response: %v", err)
	}
}

func purgeExternalCAWorkerResult(t *testing.T, h *servedHarness, rawKey, caID string) {
	t.Helper()
	serviceKey := rawKey + ":external-ca:" + caID
	if err := h.store.WithTenant(context.Background(), h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(),
			`DELETE FROM idempotency_keys WHERE tenant_id = $1 AND key = $2`,
			h.tenant, "external-ca.issue:"+serviceKey)
		return err
	}); err != nil {
		t.Fatalf("purge external CA worker result: %v", err)
	}
}

func purgeExternalCAEphemeralState(t *testing.T, h *servedHarness, rawKey, caID string) {
	t.Helper()
	serviceKey := rawKey + ":external-ca:" + caID
	if err := h.store.WithTenant(context.Background(), h.tenant, func(tx pgx.Tx) error {
		if _, err := tx.Exec(context.Background(),
			`DELETE FROM idempotency_keys
			  WHERE tenant_id = $1 AND key = ANY($2::text[])`,
			h.tenant, []string{rawKey, "external-ca.issue:" + serviceKey}); err != nil {
			return err
		}
		_, err := tx.Exec(context.Background(),
			`DELETE FROM outbox
			  WHERE tenant_id = $1 AND destination = 'external-ca.issue' AND idempotency_key = $2`,
			h.tenant, serviceKey)
		return err
	}); err != nil {
		t.Fatalf("purge external CA ephemeral state: %v", err)
	}
}

func assertServedCert(t *testing.T, cert externalCAIssueResponse, issuer, dnsName string) {
	t.Helper()
	if cert.CertificatePEM == "" || cert.Serial == "" || cert.Issuer != issuer {
		t.Fatalf("issued cert = %+v, want PEM/serial/issuer %s", cert, issuer)
	}
	info, err := certinfo.Inspect([]byte(cert.CertificatePEM))
	if err != nil {
		t.Fatalf("inspect issued cert: %v", err)
	}
	if info.SerialNumber != cert.Serial {
		t.Fatalf("serial mismatch response=%s cert=%s", cert.Serial, info.SerialNumber)
	}
	found := false
	for _, got := range info.DNSNames {
		if got == dnsName {
			found = true
		}
	}
	if !found {
		t.Fatalf("issued cert SANs = %v, want %s", info.DNSNames, dnsName)
	}
	if !info.NotAfter.After(time.Now()) {
		t.Fatalf("issued cert already expired: %s", info.NotAfter)
	}
}

func externalCAOutboxCount(t *testing.T, h *servedHarness, key string) int {
	t.Helper()
	var count int
	err := h.store.WithTenant(context.Background(), h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `
			SELECT count(*)
			FROM outbox
			WHERE tenant_id = $1
			  AND destination = 'ca.issue'
			  AND idempotency_key = $2
		`, h.tenant, ca.IssueRecordIdempotencyKey(key)).Scan(&count)
	})
	if err != nil {
		t.Fatalf("count ca.issue outbox rows: %v", err)
	}
	return count
}

func externalCAIntentOutboxCount(t *testing.T, h *servedHarness, key string) int {
	t.Helper()
	var count int
	err := h.store.WithTenant(context.Background(), h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `
			SELECT count(*)
			FROM outbox
			WHERE tenant_id = $1
			  AND destination = 'external-ca.issue'
			  AND idempotency_key = $2
		`, h.tenant, key).Scan(&count)
	})
	if err != nil {
		t.Fatalf("count external CA intent outbox rows: %v", err)
	}
	return count
}

func externalCAIntentOutboxID(t *testing.T, h *servedHarness, key string) int64 {
	t.Helper()
	var id int64
	err := h.store.WithTenant(context.Background(), h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `
			SELECT id
			FROM outbox
			WHERE tenant_id = $1
			  AND destination = 'external-ca.issue'
			  AND idempotency_key = $2
		`, h.tenant, key).Scan(&id)
	})
	if err != nil {
		t.Fatalf("read external CA intent outbox id: %v", err)
	}
	return id
}

func forceExternalCAOutboxDue(t *testing.T, h *servedHarness, key string) {
	t.Helper()
	err := h.store.WithTenant(context.Background(), h.tenant, func(tx pgx.Tx) error {
		tag, err := tx.Exec(context.Background(), `
			UPDATE outbox
			SET status = 'pending', next_attempt_at = now(), worker_id = NULL, lease_until = NULL
			WHERE tenant_id = $1
			  AND destination = 'external-ca.issue'
			  AND idempotency_key = $2
		`, h.tenant, key)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("updated %d external-ca.issue rows for %q, want 1", tag.RowsAffected(), key)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("force external CA outbox due: %v", err)
	}
}

func hasExternalCA(items []externalCAListItem, id, typ string) bool {
	for _, item := range items {
		if item.ID == id && item.Type == typ && item.Name != "" {
			return true
		}
	}
	return false
}

type caDiscoveryInventoryResponse struct {
	Items   []caDiscoveryInventoryItem `json:"items"`
	Summary struct {
		PublicCount           int `json:"public_count"`
		PrivateCount          int `json:"private_count"`
		ExternalRegistryCount int `json:"external_registry_count"`
		AuthorityCount        int `json:"authority_count"`
	} `json:"summary"`
}

type caDiscoveryInventoryItem struct {
	ID     string `json:"id"`
	Scope  string `json:"scope"`
	Source string `json:"source"`
}

func hasCADiscoveryItem(items []caDiscoveryInventoryItem, id, scope, source string) bool {
	for _, item := range items {
		if item.ID == id && item.Scope == scope && item.Source == source {
			return true
		}
	}
	return false
}
