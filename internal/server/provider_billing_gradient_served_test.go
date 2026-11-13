// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/psa/psatest"
	"trstctl.com/trstctl/internal/store"
)

// usageOnlyHarness is a served harness with one usage-only target and two
// customers mapped to it.
type usageOnlyHarness struct {
	h         *servedHarness
	target    string
	customerB string
}

func newUsageOnlyHarness(t *testing.T, target config.ProviderBillingTarget, customerB, companyA, companyB string) usageOnlyHarness {
	t.Helper()
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.BillingSync = config.ProviderBillingSync{Targets: []config.ProviderBillingTarget{target}}
	})
	registerServedTenant(t, h, target.ID+" customer A")
	registerServedTenantID(t, h, customerB, target.ID+" customer B")
	u := usageOnlyHarness{h: h, target: target.ID, customerB: customerB}
	u.mapCompany(t, h.tenant, companyA)
	u.mapCompany(t, customerB, companyB)
	return u
}

func (u usageOnlyHarness) mapCompany(t *testing.T, tenant, company string) {
	t.Helper()
	if _, err := u.h.store.SystemPool().Exec(context.Background(), `INSERT INTO provider_billing_companies (tenant_id, target_id, external_company_id, mapped_by, mapped_at)
		VALUES ($1, $2, $3, 'operator@example.test', now())
		ON CONFLICT (tenant_id, target_id) DO UPDATE SET external_company_id = EXCLUDED.external_company_id`, tenant, u.target, company); err != nil {
		t.Fatal(err)
	}
}

func (u usageOnlyHarness) push(month time.Month, company string, certs int64) projections.BillingSyncPushEvent {
	s := time.Date(2026, month, 1, 0, 0, 0, 0, time.UTC)
	return projections.BillingSyncPushEvent{TargetID: u.target, PeriodStart: s, PeriodEnd: s.AddDate(0, 1, 0), ExternalCompanyID: company,
		EvidenceDigest: "sha256:" + strings.ToLower(month.String()), EvidenceJWS: "eyJhbGciOiJSUzI1NiJ9.e30.c2ln",
		Lines: []projections.BillingUsageLine{{Meter: "certificates_current", Kind: "gauge", Value: certs}}}
}

func (u usageOnlyHarness) queue(t *testing.T, tenant string, p projections.BillingSyncPushEvent) {
	t.Helper()
	if queued, err := u.h.srv.orch.QueueBillingSyncPush(context.Background(), tenant, p); err != nil || !queued {
		t.Fatalf("queue %s = %v %v", p.PeriodStart.Format("2006-01"), queued, err)
	}
}

func (u usageOnlyHarness) status(tenant string, month time.Month) string {
	p, found, _ := u.h.store.BillingSyncPushFor(context.Background(), tenant, u.target, time.Date(2026, month, 1, 0, 0, 0, 0, time.UTC))
	if !found {
		return ""
	}
	return p.Status
}

func (u usageOnlyHarness) drainUntil(t *testing.T, what string, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for !done() {
		if err := u.h.srv.Drain(context.Background()); err != nil {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s did not happen", what)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// attempted waits for an outbox row to be tried once.
func (u usageOnlyHarness) attempted(t *testing.T, tenant string, month time.Month) {
	t.Helper()
	var attempts int
	deadline := time.Now().Add(45 * time.Second)
	for attempts == 0 {
		if err := u.h.srv.Drain(context.Background()); err != nil {
			t.Fatal(err)
		}
		_ = u.h.store.SystemPool().QueryRow(context.Background(), `SELECT attempts FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`, tenant,
			orchestrator.BillingSyncPushKey(u.target, time.Date(2026, month, 1, 0, 0, 0, 0, time.UTC))).Scan(&attempts)
		if time.Now().After(deadline) {
			t.Fatalf("%s %s was never attempted", tenant, month)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func captureDebugLog(t *testing.T) *p6MoveLog {
	t.Helper()
	logs := &p6MoveLog{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return logs
}

// MSP-7 Done-when (served, Gradient stand-in written from the public vendor
// API reference): each customer's signed period posts its own account's
// absolute service count (A's under A's account, B's under B's), a lost
// answer retried without changing the count; a period for an account the MSP
// has not mapped in Gradient counts nothing and is not recorded delivered; a
// held period never reaches Gradient; a remapped customer's period sends
// nothing; the token never appears in the debug log.
func TestServedGradientCountsPerAccountMSP7(t *testing.T) {
	logs := captureDebugLog(t)
	const token = "gradient-served-token" // #nosec G101 -- a test-only value (CWE-798)
	g := psatest.NewGradient(token)
	t.Cleanup(g.Close)
	g.MapAccount("trstctl-certificates", "alpha-dental")
	g.MapAccount("trstctl-certificates", "beta-logistics")
	target := config.ProviderBillingTarget{ID: "gradient", Type: "gradient", Endpoint: g.URL(), AllowInsecureLoopback: true,
		Gradient: &config.GradientBillingTarget{TokenRef: writeServedCredentialFile(t, "gradient-token", token),
			Services: map[string]string{"certificates_current": "trstctl-certificates"}}}
	const customerB = "5b0e7b52-3c1d-4d63-9a2b-7f0e2c9a1b07"
	u := newUsageOnlyHarness(t, target, customerB, "alpha-dental", "beta-logistics")
	u.queue(t, u.h.tenant, u.push(time.October, "alpha-dental", 42))
	u.queue(t, u.h.tenant, u.push(time.September, "alpha-dental", 40))
	u.queue(t, customerB, u.push(time.October, "beta-logistics", 7))
	g.FailWritesAfterApplying(1)
	u.drainUntil(t, "the three periods", func() bool {
		return u.status(u.h.tenant, time.September) == store.BillingSyncDelivered && u.status(u.h.tenant, time.October) == store.BillingSyncDelivered &&
			u.status(customerB, time.October) == store.BillingSyncDelivered
	})
	if n, _ := g.Count("trstctl-certificates", "alpha-dental"); n != 42 {
		t.Fatalf("Alpha's count = %d, want October's 42", n)
	}
	if n, _ := g.Count("trstctl-certificates", "beta-logistics"); n != 7 {
		t.Fatalf("Beta's count = %d, want its own 7", n)
	}

	// An account Gradient has not mapped: nothing is counted.
	u.mapCompany(t, customerB, "beta-unmapped")
	u.queue(t, customerB, u.push(time.November, "beta-unmapped", 9))
	u.attempted(t, customerB, time.November)
	if _, found := g.Count("trstctl-certificates", "beta-unmapped"); found || u.status(customerB, time.November) == store.BillingSyncDelivered {
		t.Fatal("an unmapped Gradient account was counted or recorded delivered")
	}

	// A held period never reaches Gradient.
	posts, _ := g.Counts()
	held := u.push(time.December, "alpha-dental", 1)
	held.EvidenceJWS, held.Lines, held.Reason = "", nil, "metering coverage has a gap in this period"
	if ok, err := u.h.srv.orch.HoldBillingSyncPush(context.Background(), u.h.tenant, held); err != nil || !ok {
		t.Fatalf("hold December = %v %v", ok, err)
	}
	if err := u.h.srv.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if after, _ := g.Counts(); after != posts {
		t.Fatal("a held period reached Gradient")
	}
	if strings.Contains(logs.String(), token) {
		t.Fatal("the debug log carries the GRADIENT-TOKEN")
	}
	if _, refused := g.Counts(); refused != 0 {
		t.Fatalf("Gradient refused %d requests' token", refused)
	}
}
