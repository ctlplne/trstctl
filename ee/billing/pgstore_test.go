// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/ee/billing"
	"trstctl.com/trstctl/internal/crypto/jose"
	corestore "trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/usage"
)

// The durable half of L2, against real PostgreSQL: quotas that survive,
// recounts that come from the transitions projection, and the full
// meter-vs-log agreement gate in front of the signature.

const (
	quotaTenant = "33333333-3333-3333-3333-333333333333"
	otherTenant = "44444444-4444-4444-4444-444444444444"
)

var billingTestDSN string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "trstctl-billing-pg")
	if err != nil {
		panic(err)
	}
	port := billingFreePort()
	pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).
		Port(port).
		RuntimePath(dir + "/rt").
		DataPath(dir + "/data").
		BinariesPath(dir + "/bin").
		Logger(io.Discard).
		StartTimeout(60 * time.Second))
	if err := pg.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "embedded postgres start:", err)
		_ = os.RemoveAll(dir)
		os.Exit(1)
	}
	billingTestDSN = fmt.Sprintf("postgres://postgres:postgres@localhost:%d/postgres", port)
	code := m.Run()
	_ = pg.Stop()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func billingFreePort() uint32 {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer func() { _ = l.Close() }()
	p := l.Addr().(*net.TCPAddr).Port
	if p <= 0 || p > math.MaxUint16 {
		panic(fmt.Sprintf("freePort: out-of-range TCP port %d", p))
	}
	return uint32(p)
}

func newBillingStoreOn(t *testing.T, dbName string) (*billing.PGStore, *corestore.Store) {
	t.Helper()
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, billingTestDSN)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer func() { _ = admin.Close(ctx) }()
	_, _ = admin.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{dbName}.Sanitize())
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{dbName}.Sanitize()); err != nil {
		t.Fatalf("create db: %v", err)
	}
	dsn := strings.TrimSuffix(billingTestDSN, "/postgres") + "/" + dbName
	cs, err := corestore.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("core store open: %v", err)
	}
	t.Cleanup(cs.Close)
	if err := cs.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return billing.NewPGStore(cs), cs
}

// seedQuota writes a read-model fixture under the tenant's RLS context. Quota
// command/projection behavior is proved in ee/provider/eventsource_test.go;
// this package owns only durable quota reads and enforcement.
func seedQuota(t *testing.T, st *corestore.Store, q billing.Quota) {
	t.Helper()
	err := st.WithTenant(t.Context(), q.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(t.Context(), `INSERT INTO provider_tenant_quotas
			(tenant_id, max_agents, max_tenants, max_certificates_stored, max_secrets_stored, updated_by, updated_at)
			VALUES ($1, $2, $3, $4, $5, nullif($6, ''), now())`, q.TenantID, q.MaxAgents,
			q.MaxTenants, q.MaxCertificatesStored, q.MaxSecretsStored, q.UpdatedBy)
		return err
	})
	if err != nil {
		t.Fatalf("seed quota view: %v", err)
	}
}

func TestQuotaSurvivesInPostgresAndNullMeansNoLimit(t *testing.T) {
	pgStore, st := newBillingStoreOn(t, "billing_quota_roundtrip")
	ctx := context.Background()

	// No row: the zero quota, in which nothing is limited.
	q, err := pgStore.QuotaFor(ctx, quotaTenant)
	if err != nil {
		t.Fatal(err)
	}
	if q.LimitFor(usage.MeterCertificatesStored) != nil {
		t.Fatal("an uncapped tenant reported a certificate limit; NULL must mean the ABSENCE of a cap")
	}

	limit := 5
	seedQuota(t, st, billing.Quota{
		TenantID: quotaTenant, MaxCertificatesStored: &limit, UpdatedBy: "ops@provider",
	})
	q, err = pgStore.QuotaFor(ctx, quotaTenant)
	if err != nil {
		t.Fatal(err)
	}
	got := q.LimitFor(usage.MeterCertificatesStored)
	if got == nil || *got != 5 {
		t.Fatalf("stored cap = %v, want 5. Before this table existed SetQuota silently DISCARDED "+
			"the limit, so a provider believed their customer was capped when nothing was", got)
	}
	if q.LimitFor(usage.MeterAgents) != nil {
		t.Fatal("an unset agent cap came back as a limit; a cap of zero and no cap are opposite instructions")
	}
	if q.UpdatedBy != "ops@provider" {
		t.Fatalf("updated_by = %q; the row must say who set the cap", q.UpdatedBy)
	}

	// Another tenant's quota is invisible under RLS.
	other, err := pgStore.QuotaFor(ctx, otherTenant)
	if err != nil {
		t.Fatal(err)
	}
	if other.LimitFor(usage.MeterCertificatesStored) != nil {
		t.Fatal("tenant B read tenant A's cap")
	}
}

func TestQuotaCheckerRefusesAtTheCapAgainstTheDurableStore(t *testing.T) {
	pgStore, st := newBillingStoreOn(t, "billing_quota_enforce")
	ctx := context.Background()

	limit := 2
	seedQuota(t, st, billing.Quota{TenantID: quotaTenant, MaxCertificatesStored: &limit})
	current := int64(0)
	counter := func(context.Context, string) (billing.TenantCounts, error) {
		return billing.TenantCounts{usage.MeterCertificatesStored: current}, nil
	}
	checker := billing.NewQuotaChecker(pgStore, counter, time.Millisecond)

	current = 1
	if err := checker.AllowCreate(ctx, quotaTenant, usage.MeterCertificatesStored); err != nil {
		t.Fatalf("under the cap: %v", err)
	}
	current = 2
	time.Sleep(2 * time.Millisecond) // let the cached quota expire
	err := checker.AllowCreate(ctx, quotaTenant, usage.MeterCertificatesStored)
	if err == nil {
		t.Fatal("at the cap the checker allowed another create; the durable limit decided nothing")
	}
	if !strings.Contains(err.Error(), "2 of 2") {
		t.Fatalf("refusal %q does not state current/limit; the caller cannot act on it", err)
	}
	// Core classifies the refusal through the usage sentinel — the handler
	// that turns this into a 429 cannot import this package (AN-9).
	if !billingErrIsUsageQuota(err) {
		t.Fatal("the refusal does not match usage.ErrQuotaExhausted; core handlers could not " +
			"classify it and the caller would get a 500 instead of a structured 429")
	}
}

func billingErrIsUsageQuota(err error) bool {
	return errors.Is(err, usage.ErrQuotaExhausted)
}

// seedIssuedTransition writes one issuance into the transitions projection.
func seedIssuedTransition(t *testing.T, cs *corestore.Store, tenantID string, seq int64, at time.Time) {
	t.Helper()
	if err := cs.WithTenant(context.Background(), tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(),
			`INSERT INTO identity_transitions (tenant_id, identity_id, seq, from_state, to_state, event_type, occurred_at)
			 VALUES ($1, gen_random_uuid(), $2, 'pending', 'issued', 'identity.issued', $3)`,
			tenantID, seq, at)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestEvidenceSignsOnlyWhenMeterAndLogAgree(t *testing.T) {
	pgStore, cs := newBillingStoreOn(t, "billing_reconcile")
	ctx := context.Background()

	period := billing.EvidencePeriod{
		CustomerID: quotaTenant,
		Start:      time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		End:        time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
	}
	mid := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)

	// Three issuances: three meter increments and three transitions.
	if err := pgStore.AddCounters(ctx, []billing.CounterDelta{
		{TenantID: quotaTenant, Meter: usage.MeterCertificatesIssued, Period: mid, Delta: 3},
	}); err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		seedIssuedTransition(t, cs, quotaTenant, int64(i+1), mid.Add(time.Duration(i)*time.Minute))
	}
	// A neighbouring tenant's issuance must not leak into the recount.
	seedIssuedTransition(t, cs, otherTenant, 1, mid)
	// Coverage must span the period or MaySign refuses before reconciliation.
	if err := pgStore.AddCounters(ctx, []billing.CounterDelta{
		{TenantID: quotaTenant, Meter: usage.MeterCertificatesIssued, Period: period.Start.Add(-time.Hour), Delta: 1},
	}); err != nil {
		t.Fatal(err)
	}
	if err := pgStore.SetGauge(ctx, quotaTenant, usage.MeterAgents, period.End.Add(time.Hour), 2); err != nil {
		t.Fatal(err)
	}

	key, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatal(err)
	}
	signer := &billing.AuditKeySigner{Key: key}
	now := period.End.Add(48 * time.Hour)

	coverage, err := pgStore.CoverageFor(ctx, quotaTenant)
	if err != nil {
		t.Fatal(err)
	}
	records, err := pgStore.Query(ctx, period.Start, period.End, quotaTenant)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := billing.BuildSignedEvidence(ctx, period, coverage, records, pgStore, signer, now)
	if err != nil {
		t.Fatal(err)
	}
	if !doc.Signable {
		t.Fatalf("meter and log agree (3 = 3) and the document is unsignable: %s", doc.Reason)
	}
	if doc.Signature == nil || doc.Signature.JWS == "" || doc.Signature.KeyID != "audit-export" {
		t.Fatalf("signable document carries no signature: %+v", doc.Signature)
	}
	var checked bool
	for _, r := range doc.Reconciliation {
		if r.Meter == usage.MeterCertificatesIssued {
			checked = r.Checked && r.Matches && r.EventHistory == 3
		}
	}
	if !checked {
		t.Fatalf("the reconciliation line does not record the agreement: %+v", doc.Reconciliation)
	}

	// Now skew the meter: one increment the log never saw. The next document
	// must refuse to be signed and NAME both numbers.
	if err := pgStore.AddCounters(ctx, []billing.CounterDelta{
		{TenantID: quotaTenant, Meter: usage.MeterCertificatesIssued, Period: mid, Delta: 1},
	}); err != nil {
		t.Fatal(err)
	}
	records, err = pgStore.Query(ctx, period.Start, period.End, quotaTenant)
	if err != nil {
		t.Fatal(err)
	}
	doc, err = billing.BuildSignedEvidence(ctx, period, coverage, records, pgStore, signer, now)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Signable || doc.Signature != nil {
		t.Fatal("the meter reads 4 while the log records 3, and the document was signed anyway.\n\n" +
			"A counter that disagrees with the event history is exactly the quietly-wrong number " +
			"the signable gate exists to keep off invoices, and the signature just attested it.")
	}
	if !strings.Contains(doc.Reason, "4") || !strings.Contains(doc.Reason, "3") {
		t.Fatalf("the refusal %q does not name both numbers; an operator cannot reconcile what "+
			"they cannot see", doc.Reason)
	}
}

func TestUnsignableDocumentsNeverCarryASignature(t *testing.T) {
	// Coverage refuses (period not closed); a signer is present and must not
	// be consulted into signing anyway.
	key, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatal(err)
	}
	period := billing.EvidencePeriod{
		CustomerID: quotaTenant,
		Start:      time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		End:        time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
	}
	doc, err := billing.BuildSignedEvidence(context.Background(), period,
		billing.Coverage{Durable: true}, nil, nil, &billing.AuditKeySigner{Key: key},
		period.End.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Signable || doc.Signature != nil {
		t.Fatal("an open period produced a signed document; the signature is the claim the figure " +
			"is final, and the period is still accruing")
	}
}

func TestSignableCoverageWithoutReconcilerIsServedUnsignable(t *testing.T) {
	key, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatal(err)
	}
	period := billing.EvidencePeriod{
		CustomerID: quotaTenant,
		Start:      time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		End:        time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
	}
	coverage := billing.Coverage{Durable: true,
		ObservedFrom: period.Start.Add(-time.Hour), ObservedTo: period.End.Add(time.Hour)}
	doc, err := billing.BuildSignedEvidence(context.Background(), period, coverage, nil,
		nil, &billing.AuditKeySigner{Key: key}, period.End.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Signable || doc.Signature != nil {
		t.Fatal("a deployment with NO reconciliation source signed evidence anyway. 'We could not " +
			"check' must never be signed as 'we checked'.")
	}
	if !strings.Contains(doc.Reason, "reconcil") {
		t.Fatalf("the refusal %q does not say reconciliation is what is missing", doc.Reason)
	}
}
