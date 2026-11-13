// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/branding"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/psa/psatest"
	"trstctl.com/trstctl/internal/store"
)

// MSP-6 Done-when (served, Syncro stand-in written from the vendor's public
// OpenAPI description): each customer's signed period sets the line
// quantities of its own customer's recurring invoice schedule (A's on A's,
// B's on B's), applied oldest first, a lost answer retried without a second
// line; a held period never reaches Syncro; a customer's alert opens one
// ticket for its own customer with the alert as a hidden comment (with the
// "Powered by" line for a white-labeled tenant), a later alert adds one
// comment and the close resolves it once; a remapped customer's work sends
// nothing; the API token never appears in a URL or the debug log.
func TestServedSyncroUsageAndTicketsMSP6(t *testing.T) {
	logs := &p6MoveLog{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })

	ctx := context.Background()
	const token = "syncro-served-api-token" // #nosec G101 -- a test-only value (CWE-798)
	account := psatest.NewSyncro(token)
	t.Cleanup(account.Close)
	account.AddCustomer(psatest.SyncroCustomer{ID: 401, BusinessName: "Alpha Dental"})
	account.AddCustomer(psatest.SyncroCustomer{ID: 402, BusinessName: "Beta Logistics"})
	account.AddSchedule(psatest.SyncroSchedule{ID: 41, CustomerID: 401, Name: "Managed PKI", Status: "active"})
	account.AddSchedule(psatest.SyncroSchedule{ID: 42, CustomerID: 402, Name: "Managed PKI", Status: "active"})
	target := config.ProviderBillingTarget{ID: "syncro", Type: "syncro", Endpoint: account.URL(), AllowInsecureLoopback: true,
		Syncro: &config.SyncroBillingTarget{APITokenRef: writeServedCredentialFile(t, "syncro-token", token),
			Products: map[string]int64{"certificates_current": 901},
			Tickets:  &config.SyncroTickets{ProblemType: "Certificates"}}}
	const customerB = "5b0e7b52-3c1d-4d63-9a2b-7f0e2c9a1b06"
	observer := &servedTicketObserver{companies: map[string]string{}, target: "syncro"}
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.BillingSync = config.ProviderBillingSync{Targets: []config.ProviderBillingTarget{target}}
		d.AlertObservers = []AlertObserver{observer}
	})
	observer.orch.Store(h.srv.orch)
	observer.companies[h.tenant], observer.companies[customerB] = "401", "402"
	registerServedTenant(t, h, "syncro customer A")
	registerServedTenantID(t, h, customerB, "syncro customer B")
	branding.SetSource(tenantBrandSource{tenant: h.tenant, brand: branding.Brand{TokenOverrides: map[string]string{"--background": "0 0% 100%"}}})
	t.Cleanup(func() { branding.SetSource(nil) })
	mapCompany := func(tenant, company string) {
		t.Helper()
		if _, err := h.store.SystemPool().Exec(ctx, `INSERT INTO provider_billing_companies (tenant_id, target_id, external_company_id, mapped_by, mapped_at)
			VALUES ($1, 'syncro', $2, 'operator@example.test', now())
			ON CONFLICT (tenant_id, target_id) DO UPDATE SET external_company_id = EXCLUDED.external_company_id`, tenant, company); err != nil {
			t.Fatal(err)
		}
	}
	mapCompany(h.tenant, "401")
	mapCompany(customerB, "402")
	push := func(month time.Month, company string, certs int64) projections.BillingSyncPushEvent {
		s := time.Date(2026, month, 1, 0, 0, 0, 0, time.UTC)
		return projections.BillingSyncPushEvent{TargetID: "syncro", PeriodStart: s, PeriodEnd: s.AddDate(0, 1, 0), ExternalCompanyID: company,
			EvidenceDigest: "sha256:" + strings.ToLower(month.String()), EvidenceJWS: "eyJhbGciOiJSUzI1NiJ9.e30.c2ln",
			Lines: []projections.BillingUsageLine{{Meter: "certificates_current", Kind: "gauge", Value: certs}}}
	}
	queue := func(tenant string, p projections.BillingSyncPushEvent) {
		t.Helper()
		if queued, err := h.srv.orch.QueueBillingSyncPush(ctx, tenant, p); err != nil || !queued {
			t.Fatalf("queue %s = %v %v", p.PeriodStart.Format("2006-01"), queued, err)
		}
	}
	drainUntil := func(what string, done func() bool) {
		t.Helper()
		deadline := time.Now().Add(90 * time.Second)
		for !done() {
			if err := h.srv.Drain(ctx); err != nil {
				t.Fatal(err)
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s did not happen; Syncro saw %v", what, account.Seen())
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	delivered := func(tenant string, month time.Month) bool {
		p, found, _ := h.store.BillingSyncPushFor(ctx, tenant, "syncro", time.Date(2026, month, 1, 0, 0, 0, 0, time.UTC))
		return found && p.Status == store.BillingSyncDelivered
	}
	quantity := func(schedule int64) (float64, int) {
		sc := account.Schedule(schedule)
		var q float64
		for _, l := range sc.Lines {
			q += l.Quantity
		}
		return q, len(sc.Lines)
	}

	queue(h.tenant, push(time.October, "401", 42))
	queue(h.tenant, push(time.September, "401", 40))
	queue(customerB, push(time.October, "402", 7))
	account.FailWritesAfterApplying(1)
	drainUntil("the three periods", func() bool {
		return delivered(h.tenant, time.September) && delivered(h.tenant, time.October) && delivered(customerB, time.October)
	})
	if q, n := quantity(41); q != 42 || n != 1 {
		t.Fatalf("A's schedule holds %v over %d lines, want October's 42 on one line", q, n)
	}
	if q, n := quantity(42); q != 7 || n != 1 {
		t.Fatalf("B's schedule holds %v over %d lines, want its own 7 on one line", q, n)
	}
	held := push(time.November, "401", 1)
	held.EvidenceJWS, held.Lines, held.Reason = "", nil, "metering coverage has a gap in this period"
	requests, _, _ := account.Counts()
	if ok, err := h.srv.orch.HoldBillingSyncPush(ctx, h.tenant, held); err != nil || !ok {
		t.Fatalf("hold November = %v %v", ok, err)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	if after, _, _ := account.Counts(); after != requests {
		t.Fatal("a held period reached Syncro")
	}

	alert := func(tenant, identity, key, detail string) {
		t.Helper()
		payload, _ := json.Marshal(notify.Alert{Kind: notify.KindRenewalFailed, TenantID: tenant, IdentityID: identity,
			Subject: "api." + identity[:4] + ".example", Detail: detail})
		if err := h.store.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			_, err := h.srv.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{TenantID: tenant, Destination: notify.DestinationRenewalFailure,
				IdempotencyKey: key, Payload: payload})
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	const identityA, identityB = "a1a1a1a1-0000-4000-8000-0000000006a1", "b2b2b2b2-0000-4000-8000-0000000006b2"
	ticketOf := func(tenant, identity string) store.PSATicket {
		p, _, _ := h.store.PSATicketFor(ctx, tenant, "syncro", "identity.renewal_failed:"+identity)
		return p
	}
	alert(h.tenant, identityA, "renewal-failure:sy-a-1", "A renewal attempt failed. Why: the CA refused the request.")
	alert(customerB, identityB, "renewal-failure:sy-b-1", "A renewal attempt failed. Why: the endpoint was unreachable.")
	drainUntil("the two tickets", func() bool {
		return ticketOf(h.tenant, identityA).Status == store.PSATicketOpen && ticketOf(customerB, identityB).Status == store.PSATicketOpen
	})
	for _, tk := range account.Tickets() {
		if len(tk.Comments) != 1 || !tk.Comments[0].Hidden || !tk.Comments[0].DoNotEmail {
			t.Fatalf("a ticket's first comment = %+v", tk)
		}
		switch tk.CustomerID {
		case 401:
			if !strings.Contains(tk.Comments[0].Body, branding.PoweredBy) || tk.ProblemType != "Certificates" || !strings.HasSuffix(tk.Subject, "]") {
				t.Fatalf("A's ticket = %+v", tk)
			}
		case 402:
			if strings.Contains(tk.Comments[0].Body, branding.PoweredBy) || strings.Contains(tk.Comments[0].Body, "the CA refused") {
				t.Fatalf("B's ticket = %+v", tk)
			}
		default:
			t.Fatalf("a ticket for customer %d", tk.CustomerID)
		}
	}
	alert(h.tenant, identityA, "renewal-failure:sy-a-2", "A renewal attempt failed again.")
	drainUntil("A's comment", func() bool { return ticketOf(h.tenant, identityA).Notes == 1 })
	if queued, err := h.srv.orch.QueuePSATicketClose(ctx, h.tenant, "syncro", "identity.renewal_failed:"+identityA, 1, "a renewal succeeded"); err != nil || !queued {
		t.Fatalf("queue the close = %v %v", queued, err)
	}
	drainUntil("A's close", func() bool { return ticketOf(h.tenant, identityA).Status == store.PSATicketClosed })
	for _, tk := range account.Tickets() {
		if tk.CustomerID == 401 && (tk.Status != "Resolved" || len(tk.Comments) != 3 || !strings.Contains(tk.Comments[2].Body, "a renewal succeeded")) {
			t.Fatalf("A's ticket after the close = %+v", tk)
		}
		if tk.CustomerID == 402 && (tk.Status != "New" || len(tk.Comments) != 1) {
			t.Fatalf("B's ticket was touched: %+v", tk)
		}
	}

	requests, _, _ = account.Counts()
	mapCompany(customerB, "499")
	queue(customerB, push(time.November, "402", 9))
	var attempts int
	deadline := time.Now().Add(45 * time.Second)
	for attempts == 0 {
		if err := h.srv.Drain(ctx); err != nil {
			t.Fatal(err)
		}
		_ = h.store.SystemPool().QueryRow(ctx, `SELECT attempts FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`, customerB,
			orchestrator.BillingSyncPushKey("syncro", time.Date(2026, time.November, 1, 0, 0, 0, 0, time.UTC))).Scan(&attempts)
		if time.Now().After(deadline) {
			t.Fatal("B's November was never attempted")
		}
		time.Sleep(200 * time.Millisecond)
	}
	if after, _, _ := account.Counts(); after != requests {
		t.Fatalf("a remapped customer's period reached Syncro (%d→%d requests)", requests, after)
	}
	for _, seen := range account.Seen() {
		if strings.Contains(seen, "api_key") || strings.Contains(seen, token) {
			t.Fatalf("the token reached a URL: %s", seen)
		}
	}
	if out := logs.String(); strings.Contains(out, token) {
		t.Fatal("the debug log carries the API token")
	}
	if _, _, refused := account.Counts(); refused != 0 {
		t.Fatalf("Syncro refused %d requests' credentials", refused)
	}
}
