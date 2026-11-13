// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing_test

import (
	"context"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/ee/billing"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/orchestrator"
)

type ticketQueuer struct {
	mu     sync.Mutex
	alerts []orchestrator.PSATicketAlert
	closes []string
}

func (q *ticketQueuer) QueuePSATicketAlert(_ context.Context, tenantID string, a orchestrator.PSATicketAlert) (string, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	a.TargetID = tenantID[:8] + "/" + a.TargetID
	q.alerts = append(q.alerts, a)
	return "open", nil
}

func (q *ticketQueuer) QueuePSATicketClose(_ context.Context, tenantID, targetID, alertKey string, generation int, reason string) (bool, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.closes = append(q.closes, tenantID[:8]+"/"+targetID+"/"+alertKey+"/"+reason)
	return true, nil
}

func ticketTarget(id string, kinds ...string) config.ProviderBillingTarget {
	return config.ProviderBillingTarget{ID: id, Type: "connectwise", ConnectWise: &config.ConnectWiseBillingTarget{
		Tickets: &config.ConnectWiseTickets{Board: "Managed PKI", ClosedStatus: ">Closed", Kinds: kinds}}}
}

// MSP-3 Done-when (tickets, observer): each ticketed alert kind of a mapped
// customer becomes ticket work for its company in every target that tickets
// that kind — keyed by its subject, with a summary and a note naming it —
// and nothing else does: an unmapped customer, a kind the target does not
// ticket, an alert kind no ticket follows, an alert with no subject, or an
// observer not yet bound.
func TestTicketObserverQueuesMappedCustomersAlertsMSP3(t *testing.T) {
	ctx := context.Background()
	_, cs := newBillingStoreOn(t, "billing_tickets_observer_msp3")
	const customerA, customerB = "1a2b3c4d-0000-4000-8000-00000000001a", "1a2b3c4d-0000-4000-8000-00000000001b"
	if _, err := cs.SystemPool().Exec(ctx, `INSERT INTO provider_billing_companies (tenant_id, target_id, external_company_id, mapped_by, mapped_at)
		VALUES ($1, 'cw', 'ALPHA', 'op', now()), ($1, 'cw-expiry', '101', 'op', now())`, customerA); err != nil {
		t.Fatal(err)
	}
	observer := &billing.TicketObserver{Store: cs, Targets: []config.ProviderBillingTarget{ticketTarget("cw"), ticketTarget("cw-expiry", "certificate.expiry")}}
	days := 14
	notAfter := time.Date(2026, time.December, 1, 0, 0, 0, 0, time.UTC)
	alerts := []notify.Alert{
		{Kind: notify.KindCertificateExpiry, CertificateID: "c-1", Subject: "api.alpha.example", Serial: "0A", NotAfter: notAfter, ThresholdDays: &days, OwnerEmail: "owner@alpha.example"},
		{Kind: notify.KindRenewalFailed, IdentityID: "i-1", Subject: "orders-api", Detail: "A renewal attempt failed. Why: the CA refused the request."},
		{Kind: notify.KindRevocationHealth, CertificateID: "c-2", EndpointAddress: "http://crl.alpha.example/ca.crl", Mismatch: "stale", Subject: "api2.alpha.example", Serial: "0B"},
		{Kind: notify.KindCredentialDrift, Subject: "/etc/ssl/private/api.key", Detail: "mode changed to 0644"},
	}
	if err := observer.ObserveAlert(ctx, customerA, "ref-0", alerts[0]); err != nil {
		t.Fatal(err)
	}
	q := &ticketQueuer{}
	observer.Bind(q)
	for i, a := range alerts {
		if err := observer.ObserveAlert(ctx, customerA, "ref-"+string(rune('a'+i)), a); err != nil {
			t.Fatal(err)
		}
	}
	for _, ignored := range []notify.Alert{
		{Kind: notify.KindCAHorizon, AuthorityID: "ca-1"},
		{Kind: notify.KindRenewalFailed},
		{Kind: notify.KindCredentialDrift, Subject: "  "},
	} {
		if err := observer.ObserveAlert(ctx, customerA, "ref-ignored", ignored); err != nil {
			t.Fatal(err)
		}
	}
	if err := observer.ObserveAlert(ctx, customerB, "ref-b", alerts[1]); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, a := range q.alerts {
		got = append(got, a.TargetID+" "+a.AlertKey+" "+a.ExternalCompanyID)
		if a.Summary == "" || !strings.Contains(a.Note, "Alert: "+a.Kind) || strings.Contains(a.Note, "owner@alpha.example") || a.AlertRef == "" {
			t.Fatalf("ticket alert = %+v", a)
		}
	}
	sort.Strings(got)
	want := []string{
		"1a2b3c4d/cw certificate.expiry:c-1 ALPHA",
		"1a2b3c4d/cw credential.drift:/etc/ssl/private/api.key ALPHA",
		"1a2b3c4d/cw identity.renewal_failed:i-1 ALPHA",
		"1a2b3c4d/cw revocation.health:c-2|http://crl.alpha.example/ca.crl ALPHA",
		"1a2b3c4d/cw-expiry certificate.expiry:c-1 101",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("queued:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if q.alerts[0].Summary != "Certificate expires in 14 days: api.alpha.example" {
		t.Fatalf("expiry summary = %q", q.alerts[0].Summary)
	}
}

// MSP-3 Done-when (tickets, close sweep): an open ticket whose condition
// cleared is closed with the reason — a certificate no longer active, an
// identity gone, a revocation endpoint with no unhealthy observation, a path
// with no untriaged drift in its latest scan — while one whose certificate
// is still active stays open; tickets not open, and customers no longer
// mapped, are left alone; nothing runs before Bind.
func TestTicketCloserClosesClearedConditionsMSP3(t *testing.T) {
	ctx := context.Background()
	_, cs := newBillingStoreOn(t, "billing_tickets_closer_msp3")
	const customerA, customerB = "1a2b3c4d-0000-4000-8000-00000000002a", "1a2b3c4d-0000-4000-8000-00000000002b"
	const activeCert = "c0c0c0c0-0000-4000-8000-0000000000c1"
	if _, err := cs.SystemPool().Exec(ctx, `INSERT INTO provider_billing_companies (tenant_id, target_id, external_company_id, mapped_by, mapped_at)
		VALUES ($1, 'cw', 'ALPHA', 'op', now())`, customerA); err != nil {
		t.Fatal(err)
	}
	if err := cs.WithTenant(ctx, customerA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO certificates (id, tenant_id, subject, fingerprint, status)
			VALUES ($1, $2, 'api.alpha.example', 'fp-active', 'active')`, activeCert, customerA)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	ticket := func(tenant, key, status string) {
		t.Helper()
		if _, err := cs.SystemPool().Exec(ctx, `INSERT INTO provider_psa_tickets (tenant_id, target_id, alert_key, generation, kind, status,
			external_company_id, external_ticket_id, summary, event_sequence, updated_at)
			VALUES ($1, 'cw', $2, 1, split_part($2, ':', 1), $3, 'ALPHA', '501', 's', 1, now())`, tenant, key, status); err != nil {
			t.Fatal(err)
		}
	}
	ticket(customerA, "certificate.expiry:c0c0c0c0-0000-4000-8000-0000000000c9", "open")
	ticket(customerA, "certificate.expiry:"+activeCert, "open")
	ticket(customerA, "identity.renewal_failed:d0d0d0d0-0000-4000-8000-0000000000d1", "open")
	ticket(customerA, "revocation.health:"+activeCert+"|http://crl.alpha.example/ca.crl", "open")
	ticket(customerA, "credential.drift:/etc/ssl/private/api.key", "open")
	ticket(customerA, "identity.renewal_failed:d0d0d0d0-0000-4000-8000-0000000000d2", "opening")
	ticket(customerB, "identity.renewal_failed:d0d0d0d0-0000-4000-8000-0000000000d3", "open")
	closer := &billing.TicketCloser{Store: cs, Targets: []config.ProviderBillingTarget{ticketTarget("cw")}}
	if n, err := closer.Sweep(ctx); err != nil || n != 0 {
		t.Fatalf("an unbound sweep = %d %v", n, err)
	}
	q := &ticketQueuer{}
	closer.Bind(q)
	n, err := closer.Sweep(ctx)
	if err != nil || n != 4 {
		t.Fatalf("sweep = %d %v, want four closes; queued %v", n, err, q.closes)
	}
	joined := strings.Join(q.closes, "\n")
	for _, want := range []string{
		"certificate.expiry:c0c0c0c0-0000-4000-8000-0000000000c9/the certificate is no longer active",
		"identity.renewal_failed:d0d0d0d0-0000-4000-8000-0000000000d1/the identity no longer exists",
		"revocation.health:" + activeCert + "|http://crl.alpha.example/ca.crl/the revocation endpoint answers fresh again",
		"credential.drift:/etc/ssl/private/api.key/the latest scan no longer reports the drift",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("closes:\n%s\nmissing %q", joined, want)
		}
	}
	if strings.Contains(joined, "certificate.expiry:"+activeCert) || strings.Contains(joined, "0000000000d2") || strings.Contains(joined, "1a2b3c4d/cw/identity.renewal_failed:d0d0d0d0-0000-4000-8000-0000000000d3") {
		t.Fatalf("a ticket that must stay open was closed:\n%s", joined)
	}
}

// MSP-4: ticket targets are every vendor target whose settings open tickets,
// with that vendor's kinds; a target without ticket settings is not one.
func TestTicketTargetsFollowEveryVendorMSP4(t *testing.T) {
	targets := billing.TicketTargets(config.ProviderBillingSync{Targets: []config.ProviderBillingTarget{
		ticketTarget("cw"),
		{ID: "at", Type: "autotask", Autotask: &config.AutotaskBillingTarget{Tickets: &config.AutotaskTickets{StatusNew: 1, StatusComplete: 5,
			Priority: 2, Kinds: []string{"credential.drift"}}}},
		{ID: "at-usage-only", Type: "autotask", Autotask: &config.AutotaskBillingTarget{}},
		{ID: "json", Type: "json"},
	}})
	if len(targets) != 2 || targets[0].ID != "cw" || targets[1].ID != "at" {
		t.Fatalf("ticket targets = %+v", targets)
	}
	if kinds := targets[1].TicketKinds(); len(kinds) != 1 || kinds[0] != "credential.drift" {
		t.Fatalf("autotask kinds = %v", kinds)
	}
}
