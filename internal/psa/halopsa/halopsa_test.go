// SPDX-License-Identifier: BUSL-1.1

package halopsa_test

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/psa"
	"trstctl.com/trstctl/internal/psa/halopsa"
	"trstctl.com/trstctl/internal/psa/psatest"
)

const (
	haloClientID = "trstctl-integration"
	haloSecret   = "halo-client-secret value+/=" // #nosec G101 -- a test-only value, with characters a form must escape (CWE-798)
	haloTenant   = "alphamsp"
)

func newInstance(t *testing.T) *psatest.HaloPSA {
	t.Helper()
	s := psatest.NewHaloPSA(haloClientID, haloSecret, haloTenant)
	t.Cleanup(s.Close)
	s.AddClient(psatest.HaloClient{ID: 501, Name: "Alpha Dental"})
	s.AddClient(psatest.HaloClient{ID: 502, Name: "Beta Logistics"})
	s.AddClient(psatest.HaloClient{ID: 503, Name: "Gone Ltd", Inactive: true})
	s.AddRecurringInvoice(psatest.HaloRecurringInvoice{ID: 51, ClientID: 501, InvoiceName: "Managed PKI",
		Lines: []psatest.HaloLine{{ID: 5100, ItemID: 77, QtyOrder: 1}}})
	s.AddRecurringInvoice(psatest.HaloRecurringInvoice{ID: 52, ClientID: 502, InvoiceName: "Managed PKI"})
	return s
}

func newClient(t *testing.T, s *psatest.HaloPSA, secret string, tickets *halopsa.TicketConfig) *halopsa.Client {
	t.Helper()
	c, err := halopsa.New(halopsa.Config{BaseURL: s.URL(), Tenant: haloTenant, ClientID: haloClientID,
		Items: map[string]int64{"certificates_current": 901, "agents": 902}, Tickets: tickets},
		http.DefaultClient, halopsa.Credentials{ClientSecret: []byte(secret)})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func period(company string, certs, agents int64) psa.UsagePeriod {
	start := time.Date(2026, time.October, 1, 0, 0, 0, 0, time.UTC)
	return psa.UsagePeriod{CustomerID: "customer", ExternalCompanyID: company, PeriodStart: start, PeriodEnd: start.AddDate(0, 1, 0),
		Lines: []psa.UsageLine{{Meter: "certificates_current", Value: certs}, {Meter: "agents", Value: agents}}}
}

func quantities(s *psatest.HaloPSA, invoice int64) (map[int64]float64, int) {
	out := map[int64]float64{}
	inv := s.RecurringInvoice(invoice)
	for _, l := range inv.Lines {
		out[l.ItemID] += l.QtyOrder
	}
	return out, len(inv.Lines)
}

func noSecret(t *testing.T, err error) {
	t.Helper()
	if err != nil && strings.Contains(err.Error(), "halo-client-secret") {
		t.Fatalf("an error carries the client secret: %v", err)
	}
}

// MSP-5 Done-when (usage, connector): after a client-credentials sign-in for
// the hosted tenant, a period lands as the qty_order of the client's
// recurring invoice lines, one line per save: the same period again writes
// nothing, a changed figure updates the line, a lost answer is retried
// without a second line, another item's line and another client's invoice
// are left alone.
func TestPushUsageSetsRecurringInvoiceLinesMSP5(t *testing.T) {
	ctx := context.Background()
	s := newInstance(t)
	s.FailWritesAfterApplying(1)
	_, err := newClient(t, s, haloSecret, nil).PushUsage(ctx, period("501", 42, 3))
	if err == nil || errors.Is(err, psa.ErrBeforeWrite) {
		t.Fatalf("a lost answer = %v, want an unknown outcome", err)
	}
	noSecret(t, err)
	c := newClient(t, s, haloSecret, nil)
	if _, err := c.PushUsage(ctx, period("501", 42, 3)); err != nil {
		t.Fatal(err)
	}
	if q, n := quantities(s, 51); n != 3 || q[901] != 42 || q[902] != 3 || q[77] != 1 {
		t.Fatalf("invoice 51 = %+v", s.RecurringInvoice(51).Lines)
	}
	_, writes, _ := s.Counts()
	if _, err := c.PushUsage(ctx, period("501", 42, 3)); err != nil {
		t.Fatal(err)
	}
	if _, again, _ := s.Counts(); again != writes {
		t.Fatalf("the same period again wrote %d times", again-writes)
	}
	if _, err := c.PushUsage(ctx, period("501", 40, 3)); err != nil {
		t.Fatal(err)
	}
	if q, n := quantities(s, 51); n != 3 || q[901] != 40 {
		t.Fatalf("a changed figure: %+v", s.RecurringInvoice(51).Lines)
	}
	if _, n := quantities(s, 52); n != 0 {
		t.Fatal("another client's invoice was touched")
	}
}

// MSP-5: anything that cannot be resolved unambiguously refuses the period
// before any write, a refused sign-in included, and no error names the
// secret.
func TestPushUsageRefusesBeforeAnyWriteMSP5(t *testing.T) {
	ctx := context.Background()
	s := newInstance(t)
	s.AddClient(psatest.HaloClient{ID: 504, Name: "Two Invoices"})
	s.AddRecurringInvoice(psatest.HaloRecurringInvoice{ID: 54, ClientID: 504, InvoiceName: "A"})
	s.AddRecurringInvoice(psatest.HaloRecurringInvoice{ID: 55, ClientID: 504, InvoiceName: "B"})
	s.AddClient(psatest.HaloClient{ID: 505, Name: "Duplicate Lines"})
	s.AddRecurringInvoice(psatest.HaloRecurringInvoice{ID: 56, ClientID: 505, InvoiceName: "Managed PKI",
		Lines: []psatest.HaloLine{{ID: 5601, ItemID: 901, QtyOrder: 1}, {ID: 5602, ItemID: 901, QtyOrder: 2}}})
	c := newClient(t, s, haloSecret, nil)
	for _, company := range []string{"ALPHA", "999", "503", "504", "505"} {
		_, err := c.PushUsage(ctx, period(company, 1, 1))
		if !errors.Is(err, psa.ErrBeforeWrite) {
			t.Fatalf("client %q = %v, want a refusal before any write", company, err)
		}
		noSecret(t, err)
	}
	if _, writes, _ := s.Counts(); writes != 0 {
		t.Fatalf("%d writes reached the instance", writes)
	}
	_, err := newClient(t, s, "not-the-secret", nil).PushUsage(ctx, period("501", 1, 1))
	if !errors.Is(err, psa.ErrBeforeWrite) || !strings.Contains(err.Error(), "sign in answered 400") || strings.Contains(err.Error(), "not-the-secret") {
		t.Fatalf("a wrong secret = %v", err)
	}
}

// MSP-5 Done-when (tickets, connector): a ticket opens for the client with
// its reference at the end of its summary; opening it again (a retry after a
// lost answer) finds it; another client's ticket with the same reference is
// never found; notes are private actions added once; closing adds the
// resolution and sets the closed status once; a ticket gone is left alone.
func TestTicketsOpenNoteAndCloseOnceMSP5(t *testing.T) {
	ctx := context.Background()
	s := newInstance(t)
	c := newClient(t, s, haloSecret, &halopsa.TicketConfig{TicketTypeID: 21, StatusNewID: 1, StatusClosedID: 9})
	open := psa.TicketOpen{ExternalCompanyID: "501", Reference: "trstctl-0123456789abcdef01234567", Summary: "Renewal failed: orders-api",
		Description: "first alert\n\nPowered by trstctl"}
	s.FailWritesAfterApplying(1)
	if _, err := c.OpenTicket(ctx, open); err == nil || errors.Is(err, psa.ErrBeforeWrite) {
		t.Fatalf("a lost answer on open = %v", err)
	}
	id, err := c.OpenTicket(ctx, open)
	if err != nil {
		t.Fatal(err)
	}
	tickets := s.Tickets()
	if len(tickets) != 1 || strconv.FormatInt(tickets[0].ID, 10) != id || tickets[0].ClientID != 501 || tickets[0].TicketTypeID != 21 ||
		tickets[0].Summary != "Renewal failed: orders-api [trstctl-0123456789abcdef01234567]" || !strings.Contains(tickets[0].Details, "Powered by trstctl") {
		t.Fatalf("tickets = %+v (id %s)", tickets, id)
	}
	betaOpen := open
	betaOpen.ExternalCompanyID = "502"
	if betaID, err := c.OpenTicket(ctx, betaOpen); err != nil || betaID == id {
		t.Fatalf("Beta's ticket = %s %v, want its own", betaID, err)
	}
	for i := 0; i < 2; i++ {
		if err := c.AddNote(ctx, psa.TicketNote{TicketID: id, Reference: "n-1", Text: "second alert"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.CloseTicket(ctx, psa.TicketClose{TicketID: id, Reference: "c-1", Resolution: "Resolved: a renewal succeeded"}); err != nil {
		t.Fatal(err)
	}
	_, writes, _ := s.Counts()
	if err := c.CloseTicket(ctx, psa.TicketClose{TicketID: id, Reference: "c-1", Resolution: "Resolved: a renewal succeeded"}); err != nil {
		t.Fatal(err)
	}
	if _, again, _ := s.Counts(); again != writes {
		t.Fatalf("closing a closed ticket wrote %d times", again-writes)
	}
	for _, tk := range s.Tickets() {
		if strconv.FormatInt(tk.ID, 10) != id {
			if tk.StatusID != 1 || len(tk.Actions) != 0 {
				t.Fatalf("Beta's ticket was touched: %+v", tk)
			}
			continue
		}
		if tk.StatusID != 9 || len(tk.Actions) != 2 || !tk.Actions[0].HiddenFromUser || !strings.Contains(tk.Actions[1].Note, "a renewal succeeded") {
			t.Fatalf("Alpha's ticket after the note and close = %+v", tk)
		}
	}
	if err := c.CloseTicket(ctx, psa.TicketClose{TicketID: "999999", Reference: "c-x", Resolution: "gone"}); err != nil {
		t.Fatalf("closing a ticket gone = %v", err)
	}
	if _, _, refused := s.Counts(); refused != 0 {
		t.Fatalf("%d requests were refused", refused)
	}
}
