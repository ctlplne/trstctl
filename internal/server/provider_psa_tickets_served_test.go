// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/branding"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/psa/psatest"
	"trstctl.com/trstctl/internal/store"
)

// servedTicketObserver stands in for the Provider's ticket observer: every
// renewal failure of a mapped customer becomes a ticket alert. It is bound
// to the orchestrator once the server is assembled.
type servedTicketObserver struct {
	orch      atomic.Pointer[orchestrator.Orchestrator]
	companies map[string]string
	seen      atomic.Int32
}

func (o *servedTicketObserver) ObserveAlert(ctx context.Context, tenantID, alertRef string, alert notify.Alert) error {
	o.seen.Add(1)
	orch := o.orch.Load()
	if orch == nil {
		return errors.New("observer not bound")
	}
	company, mapped := o.companies[tenantID]
	if alert.Kind != notify.KindRenewalFailed || !mapped {
		return nil
	}
	_, err := orch.QueuePSATicketAlert(ctx, tenantID, orchestrator.PSATicketAlert{TargetID: "cw", AlertKey: "identity.renewal_failed:" + alert.IdentityID,
		Kind: alert.Kind, ExternalCompanyID: company, Summary: "Renewal failed: " + alert.Subject, Note: alert.Detail, AlertRef: alertRef})
	return err
}

// MSP-3 Done-when (tickets, served, ConnectWise stand-in written from the
// vendor's public REST descriptions): a customer's alert, observed on the
// notification surface before any channel (none is configured), opens one
// service ticket under the customer's own company — with the "Powered by"
// line for a white-labeled tenant, without it for a tenant on the built-in
// brand — and a lost answer is retried without a second ticket; the same
// alert row retried adds nothing; a later alert of the same subject adds one
// note; the close (its condition cleared) notes the resolution and closes the
// ticket, once; B's alert lands only under B's company; a customer remapped
// to another company sends nothing; neither API key is logged.
func TestServedConnectWiseAlertTicketsOpenNoteAndCloseMSP3(t *testing.T) {
	logs := &p6MoveLog{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })

	ctx := context.Background()
	const login, clientID = "trstctl_msp", "6c1a3e1e-58e3-4d1b-9f0e-3b8f5a0c2d71"
	const publicKey, privateKey = "cw-ticket-public-key", "cw-ticket-private-key"
	cw := psatest.NewConnectWise(login, clientID, publicKey, privateKey)
	t.Cleanup(cw.Close)
	cw.AddCompany(psatest.CWCompany{ID: 101, Identifier: "ALPHA", Name: "Alpha Dental"})
	cw.AddCompany(psatest.CWCompany{ID: 202, Identifier: "BETA", Name: "Beta Logistics"})
	cw.AddBoard("Managed PKI", ">Closed")
	target := config.ProviderBillingTarget{ID: "cw", Type: "connectwise", Endpoint: cw.URL(), AllowInsecureLoopback: true,
		ConnectWise: &config.ConnectWiseBillingTarget{CompanyID: login, ClientID: clientID,
			PublicKeyRef:  writeServedCredentialFile(t, "cw-public", publicKey),
			PrivateKeyRef: writeServedCredentialFile(t, "cw-private", privateKey),
			AgreementType: "Managed PKI", Products: map[string]string{"agents": "TRST-AGENT"},
			Tickets: &config.ConnectWiseTickets{Board: "Managed PKI", ClosedStatus: ">Closed"}}}
	const customerB = "5b0e7b52-3c1d-4d63-9a2b-7f0e2c9a1b03"
	observer := &servedTicketObserver{companies: map[string]string{}}
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.BillingSync = config.ProviderBillingSync{Targets: []config.ProviderBillingTarget{target}}
		d.AlertObservers = []AlertObserver{observer}
	})
	observer.orch.Store(h.srv.orch)
	observer.companies[h.tenant], observer.companies[customerB] = "101", "BETA"
	registerServedTenant(t, h, "ticket customer A")
	registerServedTenantID(t, h, customerB, "ticket customer B")
	branding.SetSource(tenantBrandSource{tenant: h.tenant, brand: branding.Brand{TokenOverrides: map[string]string{"--background": "0 0% 100%"}}})
	t.Cleanup(func() { branding.SetSource(nil) })
	mapCompany := func(tenant, company string) {
		t.Helper()
		if _, err := h.store.SystemPool().Exec(ctx, `INSERT INTO provider_billing_companies (tenant_id, target_id, external_company_id, mapped_by, mapped_at)
			VALUES ($1, 'cw', $2, 'operator@example.test', now())
			ON CONFLICT (tenant_id, target_id) DO UPDATE SET external_company_id = EXCLUDED.external_company_id`, tenant, company); err != nil {
			t.Fatal(err)
		}
	}
	mapCompany(h.tenant, "101")
	mapCompany(customerB, "BETA")
	const identityA, identityB = "a1a1a1a1-0000-4000-8000-0000000000a1", "b2b2b2b2-0000-4000-8000-0000000000b2"
	alert := func(tenant, identity, key, detail string) {
		t.Helper()
		payload, _ := json.Marshal(notify.Alert{Kind: notify.KindRenewalFailed, TenantID: tenant, IdentityID: identity,
			Subject: "api." + identity[:4] + ".example", Detail: detail, Severity: notify.AlertSeverityWarning})
		if err := h.store.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			_, err := h.srv.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{TenantID: tenant, Destination: notify.DestinationRenewalFailure,
				IdempotencyKey: key, Payload: payload})
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	ticket := func(tenant, identity string) store.PSATicket {
		t.Helper()
		p, found, err := h.store.PSATicketFor(ctx, tenant, "cw", "identity.renewal_failed:"+identity)
		if err != nil || !found {
			t.Fatalf("ticket %s/%s: found=%v err=%v", tenant, identity, found, err)
		}
		return p
	}
	drainUntil := func(what string, done func() bool) {
		t.Helper()
		deadline := time.Now().Add(60 * time.Second)
		for !done() {
			if err := h.srv.Drain(ctx); err != nil {
				t.Fatal(err)
			}
			if time.Now().After(deadline) {
				rows, _ := h.store.SystemPool().Query(ctx, `SELECT tenant_id::text, destination, idempotency_key, status, attempts, coalesce(last_error, '') FROM outbox ORDER BY id`)
				var dump []string
				for rows.Next() {
					var a, b, c, d, f string
					var e int
					_ = rows.Scan(&a, &b, &c, &d, &e, &f)
					dump = append(dump, strings.Join([]string{a[:8], b, c, d, f}, " | "))
				}
				rows.Close()
				t.Fatalf("%s did not happen; observer saw %d; outbox:\n%s\nConnectWise saw: %v\nlog tail: %s", what, observer.seen.Load(),
					strings.Join(dump, "\n"), cw.Seen(), tail(logs.String(), 3000))
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	opened := func(tenant, identity string) func() bool {
		return func() bool {
			p, found, _ := h.store.PSATicketFor(ctx, tenant, "cw", "identity.renewal_failed:"+identity)
			return found && p.Status == store.PSATicketOpen
		}
	}

	// A's first failure opens a ticket under A's company; the answer to the
	// create is lost once. B's opens one under B's.
	cw.FailWritesAfterApplying(1)
	alert(h.tenant, identityA, "renewal-failure:a-1", "A renewal attempt failed. Why: the CA refused the request.")
	alert(customerB, identityB, "renewal-failure:b-1", "A renewal attempt failed. Why: the endpoint was unreachable.")
	drainUntil("A's and B's tickets opening", func() bool { return opened(h.tenant, identityA)() && opened(customerB, identityB)() })
	if observer.seen.Load() < 2 {
		t.Fatalf("the observer saw %d alerts, want both before any channel", observer.seen.Load())
	}
	tickets := cw.Tickets()
	if len(tickets) != 2 {
		t.Fatalf("ConnectWise holds %d tickets, want one per customer: %+v", len(tickets), tickets)
	}
	for _, tk := range tickets {
		switch tk.CompanyID {
		case 101:
			if !strings.Contains(tk.Description, "the CA refused") || !strings.Contains(tk.Description, branding.PoweredBy) ||
				ticket(h.tenant, identityA).ExternalTicketID == "" || tk.Board != "Managed PKI" {
				t.Fatalf("A's ticket = %+v (record %+v)", tk, ticket(h.tenant, identityA))
			}
		case 202:
			if !strings.Contains(tk.Description, "unreachable") || strings.Contains(tk.Description, branding.PoweredBy) ||
				strings.Contains(tk.Description, "the CA refused") {
				t.Fatalf("B's ticket = %+v", tk)
			}
		default:
			t.Fatalf("a ticket opened under company %d", tk.CompanyID)
		}
	}

	// The same alert row again changes nothing; A's second failure adds one
	// note to A's ticket.
	if _, err := h.srv.orch.QueuePSATicketAlert(ctx, h.tenant, orchestrator.PSATicketAlert{TargetID: "cw",
		AlertKey: "identity.renewal_failed:" + identityA, Kind: notify.KindRenewalFailed, ExternalCompanyID: "101",
		Summary: "again", Note: "again", AlertRef: "renewal-failure:a-1"}); err != nil {
		t.Fatal(err)
	}
	alert(h.tenant, identityA, "renewal-failure:a-2", "A renewal attempt failed again. Why: the CA refused the request.")
	drainUntil("A's note", func() bool {
		for _, tk := range cw.Tickets() {
			if tk.CompanyID == 101 && len(tk.Notes) == 1 {
				return true
			}
		}
		return false
	})
	if p := ticket(h.tenant, identityA); p.Notes != 1 || p.Generation != 1 {
		t.Fatalf("A's record after the note = %+v", p)
	}

	// The condition cleared: the close notes the resolution and closes A's
	// ticket; queuing the close again changes nothing.
	if queued, err := h.srv.orch.QueuePSATicketClose(ctx, h.tenant, "cw", "identity.renewal_failed:"+identityA, 1, "a renewal succeeded"); err != nil || !queued {
		t.Fatalf("queue the close = %v %v", queued, err)
	}
	drainUntil("A's close", func() bool { return ticket(h.tenant, identityA).Status == store.PSATicketClosed })
	if queued, err := h.srv.orch.QueuePSATicketClose(ctx, h.tenant, "cw", "identity.renewal_failed:"+identityA, 1, "a renewal succeeded"); err != nil || queued {
		t.Fatalf("closing a closed ticket = %v %v, want nothing", queued, err)
	}
	for _, tk := range cw.Tickets() {
		if tk.CompanyID == 101 && (!tk.Closed || tk.Status != ">Closed" || len(tk.Notes) != 2 || !tk.Notes[1].Resolution ||
			!strings.Contains(tk.Notes[1].Text, "a renewal succeeded") || !strings.Contains(tk.Notes[1].Text, branding.PoweredBy)) {
			t.Fatalf("A's ticket after the close = %+v", tk)
		}
		if tk.CompanyID == 202 && (tk.Closed || len(tk.Notes) != 0) {
			t.Fatalf("B's ticket was touched by A's close: %+v", tk)
		}
	}

	// B remapped: B's next failure (a note for its open ticket) sends nothing.
	requests, _, _ := cw.Counts()
	mapCompany(customerB, "BETA-2")
	alert(customerB, identityB, "renewal-failure:b-2", "A renewal attempt failed again.")
	var attempts int
	deadline := time.Now().Add(45 * time.Second)
	for attempts == 0 {
		if err := h.srv.Drain(ctx); err != nil {
			t.Fatal(err)
		}
		_ = h.store.SystemPool().QueryRow(ctx, `SELECT coalesce(max(attempts), 0) FROM outbox WHERE tenant_id = $1 AND destination = $2 AND idempotency_key LIKE '%:update:%'`,
			customerB, orchestrator.DestinationPSATicket).Scan(&attempts)
		if time.Now().After(deadline) {
			t.Fatal("B's note was never attempted")
		}
		time.Sleep(200 * time.Millisecond)
	}
	if after, _, _ := cw.Counts(); after != requests {
		t.Fatalf("a remapped customer's note reached ConnectWise (%d→%d requests)", requests, after)
	}

	if out := logs.String(); strings.Contains(out, publicKey) || strings.Contains(out, privateKey) {
		t.Fatalf("the debug log carries an API key:\n%s", out)
	}
	var leaked int
	if err := h.store.SystemPool().QueryRow(ctx, `SELECT
		(SELECT count(*) FROM outbox WHERE coalesce(last_error, '') LIKE '%' || $1 || '%' OR coalesce(last_error, '') LIKE '%' || $2 || '%') +
		(SELECT count(*) FROM provider_psa_tickets WHERE reason LIKE '%' || $1 || '%' OR reason LIKE '%' || $2 || '%')`,
		publicKey, privateKey).Scan(&leaked); err != nil || leaked != 0 {
		t.Fatalf("a recorded error or reason carries an API key (%d rows, %v)", leaked, err)
	}
	if _, _, refused := cw.Counts(); refused != 0 {
		t.Fatalf("ConnectWise refused %d requests' credentials", refused)
	}
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
