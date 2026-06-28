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
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/digicert"
	"trstctl.com/trstctl/internal/ca/digicert/digicertfake"
	"trstctl.com/trstctl/internal/ca/letsencrypt"
	"trstctl.com/trstctl/internal/ca/letsencrypt/acmefake"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
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
	le, err := letsencrypt.NewPlugin("lets-encrypt", acme.DirectoryURL())
	if err != nil {
		t.Fatalf("letsencrypt plugin: %v", err)
	}

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

	digi := issueExternalCA(t, h, "digicert", "svc.digicert.served.test", "clm-03-digicert")
	assertServedCert(t, digi, "digicert", "svc.digicert.served.test")
	if got := externalCAOutboxCount(t, h, "clm-03-digicert:external-ca:digicert"); got != 1 {
		t.Fatalf("DigiCert ca.issue outbox rows = %d, want 1", got)
	}
	digiReplay := issueExternalCA(t, h, "digicert", "svc.digicert.served.test", "clm-03-digicert")
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
	if issued.Serial != "spine-001-serial" {
		t.Fatalf("guarded external CA serial = %q", issued.Serial)
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
		d.ExternalCAs = []ExternalCA{{ID: caID, Type: "crashy", CA: upstream}}
	})

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

	first := issueExternalCA(t, h, caID, dnsName, idemKey)
	second := issueExternalCA(t, h, caID, dnsName, idemKey)
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
	serial := fmt.Sprintf("%s-serial-%d", f.name, f.mints)
	cert := ca.Certificate{
		CertificatePEM: []byte("-----BEGIN CERTIFICATE-----\nred-003\n-----END CERTIFICATE-----\n"),
		Serial:         serial,
		NotAfter:       time.Now().Add(24 * time.Hour).UTC(),
		Issuer:         f.Name(),
	}
	f.issued[req.ProviderIdempotencyKey] = cert
	f.lastSerial = serial
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
	return ca.Certificate{
		CertificatePEM: []byte("-----BEGIN CERTIFICATE-----\nspine-001\n-----END CERTIFICATE-----\n"),
		Serial:         "spine-001-serial",
		NotAfter:       time.Now().Add(24 * time.Hour).UTC(),
		Issuer:         g.Name(),
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
	csrDER := externalCACSR(t, dnsName)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	code, body := doExternalCARequest(t, h, http.MethodPost, "/api/v1/external-cas/"+caID+"/issue", idem, map[string]any{
		"csr_pem":     string(csrPEM),
		"dns_names":   []string{dnsName},
		"ttl_seconds": int64((24 * time.Hour).Seconds()),
	})
	if code != http.StatusCreated {
		t.Fatalf("issue through %s = %d, want 201; body=%s", caID, code, body)
	}
	var got externalCAIssueResponse
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode issue response from %s: %v body=%s", caID, err, body)
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
	req.Header.Set("X-Subject", "clm-03-admin")
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
			WHERE destination = 'ca.issue'
			  AND idempotency_key = $1
		`, ca.IssueRecordIdempotencyKey(key)).Scan(&count)
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
			WHERE destination = 'external-ca.issue'
			  AND idempotency_key = $1
		`, key).Scan(&count)
	})
	if err != nil {
		t.Fatalf("count external CA intent outbox rows: %v", err)
	}
	return count
}

func forceExternalCAOutboxDue(t *testing.T, h *servedHarness, key string) {
	t.Helper()
	err := h.store.WithTenant(context.Background(), h.tenant, func(tx pgx.Tx) error {
		tag, err := tx.Exec(context.Background(), `
			UPDATE outbox
			SET status = 'pending', next_attempt_at = now(), worker_id = NULL, lease_until = NULL
			WHERE destination = 'external-ca.issue'
			  AND idempotency_key = $1
		`, key)
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
