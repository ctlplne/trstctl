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
	"trstctl.com/trstctl/internal/psa/autotask"
	"trstctl.com/trstctl/internal/psa/psatest"
	"trstctl.com/trstctl/internal/store"
)

// MSP-4 Done-when (served, Autotask stand-in written from the vendor's
// public REST entity reference): each customer's signed period becomes the
// whole units of its own company's Recurring Service contract services (A's
// on A's contract, B's on B's), applied oldest first and set by adjusting
// only the difference, so a lost answer is retried without doubling and the
// same figure again adjusts nothing; a held period never reaches Autotask;
// a customer's alert opens one ticket under its own company (with the
// "Powered by" line for a white-labeled tenant), a later alert adds one note
// and the close completes it once; a remapped customer's work sends nothing;
// no credential is logged.
func TestServedAutotaskUsageAndTicketsMSP4(t *testing.T) {
	logs := &p6MoveLog{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })

	ctx := context.Background()
	const user, secret, code = "trstctl-api@alpha-msp.example", "at-served-secret", "at-served-tracking-identifier"
	zone := psatest.NewAutotask(user, secret, code)
	t.Cleanup(zone.Close)
	start, end := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC), time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC)
	zone.AddCompany(psatest.ATCompany{ID: 301, Name: "Alpha Dental", Active: true})
	zone.AddCompany(psatest.ATCompany{ID: 302, Name: "Beta Logistics", Active: true})
	zone.AddContract(psatest.ATContract{ID: 31, CompanyID: 301, Name: "Managed PKI", Type: autotask.RecurringServiceContract, Start: start, End: end})
	zone.AddContract(psatest.ATContract{ID: 32, CompanyID: 302, Name: "Managed PKI", Type: autotask.RecurringServiceContract, Start: start, End: end})
	for _, cs := range []psatest.ATContractService{{ID: 3101, ContractID: 31, ServiceID: 9001}, {ID: 3201, ContractID: 32, ServiceID: 9001}} {
		zone.AddContractService(cs)
	}
	target := config.ProviderBillingTarget{ID: "at", Type: "autotask", Endpoint: zone.URL(), AllowInsecureLoopback: true,
		Autotask: &config.AutotaskBillingTarget{Username: user,
			SecretRef:          writeServedCredentialFile(t, "at-secret", secret),
			IntegrationCodeRef: writeServedCredentialFile(t, "at-code", code),
			Services:           map[string]int64{"certificates_current": 9001},
			Tickets:            &config.AutotaskTickets{StatusNew: 1, StatusComplete: 5, Priority: 2}}}
	const customerB = "5b0e7b52-3c1d-4d63-9a2b-7f0e2c9a1b04"
	observer := &servedTicketObserver{companies: map[string]string{}, target: "at"}
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.BillingSync = config.ProviderBillingSync{Targets: []config.ProviderBillingTarget{target}}
		d.AlertObservers = []AlertObserver{observer}
	})
	observer.orch.Store(h.srv.orch)
	observer.companies[h.tenant], observer.companies[customerB] = "301", "302"
	registerServedTenant(t, h, "autotask customer A")
	registerServedTenantID(t, h, customerB, "autotask customer B")
	branding.SetSource(tenantBrandSource{tenant: h.tenant, brand: branding.Brand{TokenOverrides: map[string]string{"--background": "0 0% 100%"}}})
	t.Cleanup(func() { branding.SetSource(nil) })
	mapCompany := func(tenant, company string) {
		t.Helper()
		if _, err := h.store.SystemPool().Exec(ctx, `INSERT INTO provider_billing_companies (tenant_id, target_id, external_company_id, mapped_by, mapped_at)
			VALUES ($1, 'at', $2, 'operator@example.test', now())
			ON CONFLICT (tenant_id, target_id) DO UPDATE SET external_company_id = EXCLUDED.external_company_id`, tenant, company); err != nil {
			t.Fatal(err)
		}
	}
	mapCompany(h.tenant, "301")
	mapCompany(customerB, "302")
	push := func(month time.Month, company string, certs int64) projections.BillingSyncPushEvent {
		s := time.Date(2026, month, 1, 0, 0, 0, 0, time.UTC)
		return projections.BillingSyncPushEvent{TargetID: "at", PeriodStart: s, PeriodEnd: s.AddDate(0, 1, 0), ExternalCompanyID: company,
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
				t.Fatalf("%s did not happen; Autotask saw %v", what, zone.Seen())
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	delivered := func(tenant string, month time.Month) bool {
		p, found, _ := h.store.BillingSyncPushFor(ctx, tenant, "at", time.Date(2026, month, 1, 0, 0, 0, 0, time.UTC))
		return found && p.Status == store.BillingSyncDelivered
	}

	// Usage: A's October before its September, B's October alongside; the
	// first adjustment's answer is lost.
	queue(h.tenant, push(time.October, "301", 42))
	queue(h.tenant, push(time.September, "301", 40))
	queue(customerB, push(time.October, "302", 7))
	zone.FailWritesAfterApplying(1)
	drainUntil("the three periods", func() bool {
		return delivered(h.tenant, time.September) && delivered(h.tenant, time.October) && delivered(customerB, time.October)
	})
	december := time.Date(2026, time.December, 1, 0, 0, 0, 0, time.UTC)
	if a, b := zone.Units(3101, december), zone.Units(3201, december); a != 42 || b != 7 {
		t.Fatalf("units in force after October: A %d, B %d; want 42 and 7", a, b)
	}
	var sum, adjustmentsA int64
	for _, adj := range zone.Adjustments() {
		if adj.ContractServiceID == 3101 {
			sum += adj.UnitChange
			adjustmentsA++
		}
	}
	if sum != 42 || adjustmentsA != 2 {
		t.Fatalf("A's adjustments sum to %d over %d, want 40 then +2 (no double)", sum, adjustmentsA)
	}
	held := push(time.November, "301", 1)
	held.EvidenceJWS, held.Lines, held.Reason = "", nil, "metering coverage has a gap in this period"
	requests, _, _ := zone.Counts()
	if ok, err := h.srv.orch.HoldBillingSyncPush(ctx, h.tenant, held); err != nil || !ok {
		t.Fatalf("hold November = %v %v", ok, err)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	if after, _, _ := zone.Counts(); after != requests {
		t.Fatal("a held period reached Autotask")
	}

	// Tickets: A's failure opens one ticket under A's company with the
	// Powered-by line; B's under B's without it; A's second failure adds a
	// note; the close completes A's ticket once.
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
	const identityA, identityB = "a1a1a1a1-0000-4000-8000-0000000004a1", "b2b2b2b2-0000-4000-8000-0000000004b2"
	ticketOf := func(tenant, identity string) store.PSATicket {
		p, _, _ := h.store.PSATicketFor(ctx, tenant, "at", "identity.renewal_failed:"+identity)
		return p
	}
	alert(h.tenant, identityA, "renewal-failure:at-a-1", "A renewal attempt failed. Why: the CA refused the request.")
	alert(customerB, identityB, "renewal-failure:at-b-1", "A renewal attempt failed. Why: the endpoint was unreachable.")
	drainUntil("the two tickets", func() bool {
		return ticketOf(h.tenant, identityA).Status == store.PSATicketOpen && ticketOf(customerB, identityB).Status == store.PSATicketOpen
	})
	for _, tk := range zone.Tickets() {
		switch tk.CompanyID {
		case 301:
			if !strings.Contains(tk.Description, branding.PoweredBy) || tk.Status != 1 || tk.Priority != 2 {
				t.Fatalf("A's ticket = %+v", tk)
			}
		case 302:
			if strings.Contains(tk.Description, branding.PoweredBy) || strings.Contains(tk.Description, "the CA refused") {
				t.Fatalf("B's ticket = %+v", tk)
			}
		default:
			t.Fatalf("a ticket under company %d", tk.CompanyID)
		}
	}
	alert(h.tenant, identityA, "renewal-failure:at-a-2", "A renewal attempt failed again.")
	drainUntil("A's note", func() bool { return ticketOf(h.tenant, identityA).Notes == 1 && len(zone.Notes()) == 1 })
	if queued, err := h.srv.orch.QueuePSATicketClose(ctx, h.tenant, "at", "identity.renewal_failed:"+identityA, 1, "a renewal succeeded"); err != nil || !queued {
		t.Fatalf("queue the close = %v %v", queued, err)
	}
	drainUntil("A's close", func() bool { return ticketOf(h.tenant, identityA).Status == store.PSATicketClosed })
	for _, tk := range zone.Tickets() {
		if (tk.CompanyID == 301) != (tk.Status == 5) {
			t.Fatalf("after A's close: %+v", tk)
		}
	}
	if notes := zone.Notes(); len(notes) != 2 || !strings.Contains(notes[1].Description, "a renewal succeeded") ||
		!strings.Contains(notes[1].Description, branding.PoweredBy) {
		t.Fatalf("notes = %+v", notes)
	}

	// B remapped: B's next period sends nothing.
	requests, _, _ = zone.Counts()
	mapCompany(customerB, "399")
	queue(customerB, push(time.November, "302", 9))
	var attempts int
	deadline := time.Now().Add(45 * time.Second)
	for attempts == 0 {
		if err := h.srv.Drain(ctx); err != nil {
			t.Fatal(err)
		}
		_ = h.store.SystemPool().QueryRow(ctx, `SELECT attempts FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`, customerB,
			orchestrator.BillingSyncPushKey("at", time.Date(2026, time.November, 1, 0, 0, 0, 0, time.UTC))).Scan(&attempts)
		if time.Now().After(deadline) {
			t.Fatal("B's November was never attempted")
		}
		time.Sleep(200 * time.Millisecond)
	}
	if after, _, _ := zone.Counts(); after != requests {
		t.Fatalf("a remapped customer's period reached Autotask (%d→%d requests)", requests, after)
	}
	if out := logs.String(); strings.Contains(out, secret) || strings.Contains(out, code) {
		t.Fatalf("the debug log carries a credential")
	}
	if _, _, refused := zone.Counts(); refused != 0 {
		t.Fatalf("Autotask refused %d requests' credentials", refused)
	}
}
