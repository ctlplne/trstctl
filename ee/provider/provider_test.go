package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/license"
)

func TestTenantBandExhaustionIsProvisionOnly(t *testing.T) {
	ctx := context.Background()
	clock := fixedClock()
	audit := &captureAudit{}
	svc := NewService(Config{License: providerLicense(t, 2), Store: NewMemStore(), Audit: audit, Clock: clock})
	op := providerOperator("op-1")

	alpha, err := svc.Provision(ctx, op, ProvisionRequest{Slug: "alpha", Name: "Alpha"})
	if err != nil {
		t.Fatalf("provision alpha: %v", err)
	}
	beta, err := svc.Provision(ctx, op, ProvisionRequest{Slug: "beta", Name: "Beta"})
	if err != nil {
		t.Fatalf("provision beta: %v", err)
	}

	if _, err := svc.Provision(ctx, op, ProvisionRequest{Slug: "gamma", Name: "Gamma"}); !errors.Is(err, ErrTenantBandExhausted) {
		t.Fatalf("third provision error = %v, want ErrTenantBandExhausted", err)
	}
	if err := svc.Suspend(ctx, op, alpha.ID); err != nil {
		t.Fatalf("suspend alpha: %v", err)
	}
	if _, err := svc.Provision(ctx, op, ProvisionRequest{Slug: "gamma", Name: "Gamma"}); !errors.Is(err, ErrTenantBandExhausted) {
		t.Fatalf("suspended tenants must still consume the band; got %v", err)
	}
	if err := svc.Offboard(ctx, op, beta.ID); err != nil {
		t.Fatalf("offboard beta: %v", err)
	}
	if _, err := svc.Provision(ctx, op, ProvisionRequest{Slug: "gamma", Name: "Gamma"}); err != nil {
		t.Fatalf("provision after offboard should use the freed band slot: %v", err)
	}

	tenants, err := svc.ListTenants(ctx)
	if err != nil {
		t.Fatalf("list tenants: %v", err)
	}
	status := map[string]TenantStatus{}
	for _, tenant := range tenants {
		status[tenant.Slug] = tenant.Status
	}
	if status["alpha"] != TenantSuspended || status["gamma"] != TenantActive {
		t.Fatalf("running tenants were not preserved after band exhaustion: %+v", status)
	}
	if !audit.Contains(AuditTenantProvisioned) || !audit.Contains(AuditTenantSuspended) || !audit.Contains(AuditTenantOffboarded) {
		t.Fatalf("provider lifecycle audit incomplete: %+v", audit.Types())
	}
}

func TestProviderHandlerRendersTenantBandProblemCode(t *testing.T) {
	handler := NewHandler(Config{
		License: providerLicense(t, 1),
		Store:   NewMemStore(),
		Audit:   &captureAudit{},
		Clock:   fixedClock(),
	})

	postTenant := func(slug string) (int, map[string]any) {
		body, _ := json.Marshal(map[string]string{"slug": slug, "name": slug})
		req := httptest.NewRequest(http.MethodPost, "/provider/v1/tenants", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer provider:op-1:provider@example.test")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		var payload map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &payload)
		return rec.Code, payload
	}

	if code, body := postTenant("alpha"); code != http.StatusCreated {
		t.Fatalf("first tenant = %d body=%v, want 201", code, body)
	}
	code, body := postTenant("beta")
	if code != http.StatusForbidden {
		t.Fatalf("band exhaustion = %d body=%v, want 403", code, body)
	}
	if body["code"] != CodeTenantBandExhausted {
		t.Fatalf("problem code = %v, want %q; body=%v", body["code"], CodeTenantBandExhausted, body)
	}
}

func TestBreakGlassRequiresConsentAndAuditsBeforeTenantData(t *testing.T) {
	ctx := context.Background()
	audit := &captureAudit{}
	telemetry := &auditCheckingTelemetry{audit: audit}
	svc := NewService(Config{
		License:   providerLicense(t, 2),
		Store:     NewMemStore(),
		Audit:     audit,
		Telemetry: telemetry,
		Clock:     fixedClock(),
	})
	op := providerOperator("op-1")
	tenant, err := svc.Provision(ctx, op, ProvisionRequest{Slug: "alpha", Name: "Alpha"})
	if err != nil {
		t.Fatalf("provision: %v", err)
	}

	if _, err := svc.DirectTenantSnapshot(ctx, op, tenant.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("direct provider read error = %v, want ErrForbidden", err)
	}
	grant, err := svc.RequestBreakGlass(ctx, op, BreakGlassRequest{
		TenantID: tenant.ID,
		Reason:   "tenant requested emergency fleet diagnosis",
		TTL:      time.Hour,
	})
	if err != nil {
		t.Fatalf("request break-glass: %v", err)
	}
	if _, err := svc.BreakGlassResults(ctx, op, grant.ID); !errors.Is(err, ErrBreakGlassNotConsented) {
		t.Fatalf("unconsented break-glass error = %v, want ErrBreakGlassNotConsented", err)
	}
	if _, err := svc.ConsentBreakGlass(ctx, tenant.ID, grant.ID, "tenant-admin@example.test", true); err != nil {
		t.Fatalf("tenant consent: %v", err)
	}
	if _, err := svc.BreakGlassResults(ctx, providerOperator("op-2"), grant.ID); !errors.Is(err, ErrBreakGlassWrongOperator) {
		t.Fatalf("wrong operator error = %v, want ErrBreakGlassWrongOperator", err)
	}

	snapshot, err := svc.BreakGlassResults(ctx, op, grant.ID)
	if err != nil {
		t.Fatalf("consented break-glass results: %v", err)
	}
	if snapshot.TenantID != tenant.ID || snapshot.Health != "degraded" || snapshot.ActiveCertificates != 7 {
		t.Fatalf("snapshot = %+v, want tenant-scoped telemetry", snapshot)
	}
	if !telemetry.SawAccessAuditBeforeRead {
		t.Fatal("break-glass returned tenant data before provider.breakglass_access was audited")
	}
	got := audit.Types()
	if len(got) < 2 || !equalStrings(got[len(got)-2:], []string{AuditBreakGlassConsented, AuditBreakGlassAccessed}) {
		t.Fatalf("final audit order = %v, want consent before access", got)
	}
}

type captureAudit struct {
	events []AuditEvent
}

func (a *captureAudit) RecordProviderAudit(_ context.Context, event AuditEvent) error {
	a.events = append(a.events, event)
	return nil
}

func (a *captureAudit) Contains(typ string) bool {
	for _, event := range a.events {
		if event.Type == typ {
			return true
		}
	}
	return false
}

func (a *captureAudit) Types() []string {
	out := make([]string, len(a.events))
	for i, event := range a.events {
		out[i] = event.Type
	}
	return out
}

type auditCheckingTelemetry struct {
	audit                    *captureAudit
	SawAccessAuditBeforeRead bool
}

func (t *auditCheckingTelemetry) TenantSnapshot(_ context.Context, tenantID string) (TenantSnapshot, error) {
	t.SawAccessAuditBeforeRead = t.audit.Contains(AuditBreakGlassAccessed)
	return TenantSnapshot{TenantID: tenantID, Health: "degraded", ActiveCertificates: 7}, nil
}

func providerOperator(id string) Operator {
	return Operator{ID: id, Email: id + "@provider.example.test", Role: OperatorAdmin, MFA: true}
}

func providerLicense(t *testing.T, tenantBand int) *license.Manager {
	t.Helper()
	priv, pub, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	raw, err := license.Sign(license.Claims{
		V:          1,
		ID:         "provider-test",
		Customer:   "Provider Test",
		Tier:       license.TierProvider,
		TenantBand: tenantBand,
		IssuedAt:   now.Add(-time.Hour),
		ExpiresAt:  now.Add(time.Hour),
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "license.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	lm, err := license.Load(path, [][]byte{pub})
	if err != nil {
		t.Fatal(err)
	}
	return lm
}

func fixedClock() func() time.Time {
	return func() time.Time { return time.Date(2026, 6, 27, 12, 0, 0, 0, time.UTC) }
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
