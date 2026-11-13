// SPDX-License-Identifier: BUSL-1.1

package syncro_test

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/psa"
	"trstctl.com/trstctl/internal/psa/psatest"
	"trstctl.com/trstctl/internal/psa/syncro"
)

const syncroToken = "syncro-api-token-value" // #nosec G101 -- a test-only value (CWE-798)

func product(id int64) *int64 { return &id }

func newAccount(t *testing.T) *psatest.Syncro {
	t.Helper()
	s := psatest.NewSyncro(syncroToken)
	t.Cleanup(s.Close)
	s.AddCustomer(psatest.SyncroCustomer{ID: 401, BusinessName: "Alpha Dental"})
	s.AddCustomer(psatest.SyncroCustomer{ID: 402, BusinessName: "Beta Logistics"})
	s.AddCustomer(psatest.SyncroCustomer{ID: 403, BusinessName: "Gone Ltd", Disabled: true})
	s.AddSchedule(psatest.SyncroSchedule{ID: 41, CustomerID: 401, Name: "Managed PKI", Status: "active",
		Lines: []psatest.SyncroLine{{ID: 4100, ProductID: product(77), Quantity: 1, Name: "Backup"}}})
	s.AddSchedule(psatest.SyncroSchedule{ID: 42, CustomerID: 402, Name: "Managed PKI", Status: "active"})
	s.AddSchedule(psatest.SyncroSchedule{ID: 43, CustomerID: 402, Name: "Old", Status: "active", Paused: true})
	return s
}

func newClient(t *testing.T, s *psatest.Syncro, token string, tickets *syncro.TicketConfig) *syncro.Client {
	t.Helper()
	c, err := syncro.New(syncro.Config{BaseURL: s.URL(), Products: map[string]int64{"certificates_current": 901, "agents": 902}, Tickets: tickets},
		http.DefaultClient, syncro.Credentials{APIToken: []byte(token)})
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

func lineQuantities(s *psatest.Syncro, schedule int64) map[int64]float64 {
	out := map[int64]float64{}
	for _, l := range s.Schedule(schedule).Lines {
		if l.ProductID != nil {
			out[*l.ProductID] += l.Quantity
		}
	}
	return out
}

func noToken(t *testing.T, err error) {
	t.Helper()
	if err != nil && strings.Contains(err.Error(), syncroToken) {
		t.Fatalf("an error carries the API token: %v", err)
	}
}

// MSP-6 Done-when (usage, connector): a period lands as the quantities of
// the customer's one active schedule's lines, one per configured product,
// set rather than added to: the same period again writes nothing, a changed
// figure updates the line, a lost answer is retried without a second line,
// and a line for another product and another customer's schedule are left
// alone.
func TestPushUsageSetsScheduleLineQuantitiesMSP6(t *testing.T) {
	ctx := context.Background()
	s := newAccount(t)
	c := newClient(t, s, syncroToken, nil)
	s.FailWritesAfterApplying(1)
	_, err := c.PushUsage(ctx, period("401", 42, 3))
	if err == nil || errors.Is(err, psa.ErrBeforeWrite) {
		t.Fatalf("a lost answer = %v, want an unknown outcome", err)
	}
	noToken(t, err)
	out, err := c.PushUsage(ctx, period("401", 42, 3))
	if err != nil || strings.Join(out.Set, ",") != "agents,certificates_current" {
		t.Fatalf("retry = %+v %v", out, err)
	}
	if q := lineQuantities(s, 41); len(s.Schedule(41).Lines) != 3 || q[901] != 42 || q[902] != 3 || q[77] != 1 {
		t.Fatalf("schedule 41 = %+v", s.Schedule(41).Lines)
	}
	_, writes, _ := s.Counts()
	if _, err := c.PushUsage(ctx, period("401", 42, 3)); err != nil {
		t.Fatal(err)
	}
	if _, again, _ := s.Counts(); again != writes {
		t.Fatalf("the same period again wrote %d times", again-writes)
	}
	if _, err := c.PushUsage(ctx, period("401", 40, 3)); err != nil {
		t.Fatal(err)
	}
	if q := lineQuantities(s, 41); len(s.Schedule(41).Lines) != 3 || q[901] != 40 {
		t.Fatalf("a changed figure: %+v", s.Schedule(41).Lines)
	}
	if len(s.Schedule(42).Lines) != 0 || len(s.Schedule(43).Lines) != 0 {
		t.Fatal("another customer's schedule was touched")
	}
}

// MSP-6: anything that cannot be resolved unambiguously refuses the period
// before any write, and no error names the token.
func TestPushUsageRefusesBeforeAnyWriteMSP6(t *testing.T) {
	ctx := context.Background()
	s := newAccount(t)
	s.AddCustomer(psatest.SyncroCustomer{ID: 404, BusinessName: "Two Schedules"})
	s.AddSchedule(psatest.SyncroSchedule{ID: 44, CustomerID: 404, Name: "A", Status: "active"})
	s.AddSchedule(psatest.SyncroSchedule{ID: 45, CustomerID: 404, Name: "B", Status: "active"})
	s.AddCustomer(psatest.SyncroCustomer{ID: 405, BusinessName: "Duplicate Lines"})
	s.AddSchedule(psatest.SyncroSchedule{ID: 46, CustomerID: 405, Name: "Managed PKI", Status: "active",
		Lines: []psatest.SyncroLine{{ID: 4601, ProductID: product(901), Quantity: 1, Name: "a"}, {ID: 4602, ProductID: product(901), Quantity: 2, Name: "b"}}})
	s.AddCustomer(psatest.SyncroCustomer{ID: 406, BusinessName: "Paused Only"})
	s.AddSchedule(psatest.SyncroSchedule{ID: 47, CustomerID: 406, Name: "Managed PKI", Status: "active", Paused: true})
	c := newClient(t, s, syncroToken, nil)
	for _, company := range []string{"ALPHA", "999", "403", "404", "405", "406"} {
		_, err := c.PushUsage(ctx, period(company, 1, 1))
		if !errors.Is(err, psa.ErrBeforeWrite) {
			t.Fatalf("customer %q = %v, want a refusal before any write", company, err)
		}
		noToken(t, err)
	}
	if _, writes, _ := s.Counts(); writes != 0 {
		t.Fatalf("%d writes reached the account", writes)
	}
	wrong := newClient(t, s, "not-the-token", nil)
	_, err := wrong.PushUsage(ctx, period("401", 1, 1))
	if !errors.Is(err, psa.ErrBeforeWrite) || !strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "not-the-token") {
		t.Fatalf("wrong token = %v", err)
	}
	for _, seen := range s.Seen() {
		if strings.Contains(seen, "api_key") || strings.Contains(seen, syncroToken) {
			t.Fatalf("the token reached a URL: %s", seen)
		}
	}
}

// MSP-6 Done-when (tickets, connector): a ticket opens for the customer with
// its reference at the end of its subject and the alert as a hidden,
// un-emailed first comment; opening it again (a retry after a lost answer)
// finds it; another customer's ticket with the same reference is never
// found; notes are added once even past a page of comments; closing adds the
// resolution and sets the closed status once; a ticket gone is left alone.
func TestTicketsOpenNoteAndCloseOnceMSP6(t *testing.T) {
	ctx := context.Background()
	s := newAccount(t)
	c := newClient(t, s, syncroToken, &syncro.TicketConfig{ProblemType: "Other", StatusNew: "New", StatusClosed: "Resolved"})
	open := psa.TicketOpen{ExternalCompanyID: "401", Reference: "trstctl-0123456789abcdef01234567", Summary: "Renewal failed: orders-api",
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
	if len(tickets) != 1 || strconv.FormatInt(tickets[0].ID, 10) != id || tickets[0].CustomerID != 401 ||
		tickets[0].Subject != "Renewal failed: orders-api [trstctl-0123456789abcdef01234567]" || tickets[0].ProblemType != "Other" ||
		len(tickets[0].Comments) != 1 || !tickets[0].Comments[0].Hidden || !tickets[0].Comments[0].DoNotEmail ||
		!strings.Contains(tickets[0].Comments[0].Body, "Powered by trstctl") {
		t.Fatalf("tickets = %+v (id %s)", tickets, id)
	}
	betaOpen := open
	betaOpen.ExternalCompanyID = "402"
	if betaID, err := c.OpenTicket(ctx, betaOpen); err != nil || betaID == id {
		t.Fatalf("Beta's ticket = %s %v, want its own", betaID, err)
	}
	s.SetPageSize(1)
	for i := 0; i < 3; i++ {
		if err := c.AddNote(ctx, psa.TicketNote{TicketID: id, Reference: "n-" + strconv.Itoa(i), Text: "alert " + strconv.Itoa(i)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.AddNote(ctx, psa.TicketNote{TicketID: id, Reference: "n-0", Text: "alert 0 again"}); err != nil {
		t.Fatal(err)
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
			if tk.Status != "New" || len(tk.Comments) != 1 {
				t.Fatalf("Beta's ticket was touched: %+v", tk)
			}
			continue
		}
		if tk.Status != "Resolved" || len(tk.Comments) != 5 || !strings.Contains(tk.Comments[4].Body, "a renewal succeeded") {
			t.Fatalf("Alpha's ticket after notes and close = %+v", tk)
		}
	}
	if err := c.CloseTicket(ctx, psa.TicketClose{TicketID: "999999", Reference: "c-x", Resolution: "gone"}); err != nil {
		t.Fatalf("closing a ticket gone = %v", err)
	}
	if _, err := c.OpenTicket(ctx, psa.TicketOpen{ExternalCompanyID: "401", Reference: "has space", Summary: "s"}); !errors.Is(err, psa.ErrBeforeWrite) {
		t.Fatalf("a reference with a space = %v", err)
	}
	if _, _, refused := s.Counts(); refused != 0 {
		t.Fatalf("%d requests were refused", refused)
	}
}
