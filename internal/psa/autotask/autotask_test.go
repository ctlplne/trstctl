// SPDX-License-Identifier: BUSL-1.1

package autotask_test

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/psa"
	"trstctl.com/trstctl/internal/psa/autotask"
	"trstctl.com/trstctl/internal/psa/psatest"
)

const (
	atUser   = "trstctl-api@alpha-msp.example"
	atSecret = "at-api-secret-value"
	atCode   = "at-tracking-identifier"
)

var (
	contractStart = time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	contractEnd   = time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC)
)

func newZone(t *testing.T) *psatest.Autotask {
	t.Helper()
	s := psatest.NewAutotask(atUser, atSecret, atCode)
	t.Cleanup(s.Close)
	s.AddCompany(psatest.ATCompany{ID: 301, Name: "Alpha Dental", Active: true})
	s.AddCompany(psatest.ATCompany{ID: 302, Name: "Beta Logistics", Active: true})
	s.AddCompany(psatest.ATCompany{ID: 303, Name: "Gone Ltd"})
	s.AddContract(psatest.ATContract{ID: 31, CompanyID: 301, Name: "Managed PKI", Type: autotask.RecurringServiceContract, Start: contractStart, End: contractEnd})
	s.AddContract(psatest.ATContract{ID: 32, CompanyID: 302, Name: "Managed PKI", Type: autotask.RecurringServiceContract, Start: contractStart, End: contractEnd})
	s.AddContract(psatest.ATContract{ID: 33, CompanyID: 302, Name: "Old PKI", Type: autotask.RecurringServiceContract,
		Start: time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC), End: contractStart})
	for _, cs := range []psatest.ATContractService{
		{ID: 3101, ContractID: 31, ServiceID: 9001}, {ID: 3102, ContractID: 31, ServiceID: 9002},
		{ID: 3201, ContractID: 32, ServiceID: 9001}, {ID: 3202, ContractID: 32, ServiceID: 9002},
	} {
		s.AddContractService(cs)
	}
	return s
}

func newClient(t *testing.T, s *psatest.Autotask, secret string, tickets *autotask.TicketConfig) *autotask.Client {
	t.Helper()
	c, err := autotask.New(autotask.Config{BaseURL: s.URL(), Username: atUser, Services: map[string]int64{"certificates_current": 9001, "agents": 9002},
		Tickets: tickets}, http.DefaultClient, autotask.Credentials{Secret: []byte(secret), IntegrationCode: []byte(atCode)})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func period(month time.Month, company string, certs, agents int64) psa.UsagePeriod {
	start := time.Date(2026, month, 1, 0, 0, 0, 0, time.UTC)
	return psa.UsagePeriod{CustomerID: "customer", ExternalCompanyID: company, PeriodStart: start, PeriodEnd: start.AddDate(0, 1, 0),
		Lines: []psa.UsageLine{{Meter: "certificates_current", Value: certs}, {Meter: "agents", Value: agents}}}
}

func noKeys(t *testing.T, err error) {
	t.Helper()
	if err != nil && (strings.Contains(err.Error(), atSecret) || strings.Contains(err.Error(), atCode)) {
		t.Fatalf("an error carries a credential: %v", err)
	}
}

// MSP-4 Done-when (usage, connector): a period sets its contract services'
// whole units, effective from the period's end, through adjustments of the
// difference: the same period again adjusts nothing, a lower figure adjusts
// down, and a lost answer is retried by reading the units already set, so a
// line is never doubled; another company's contract is never touched.
func TestPushUsageSetsContractServiceUnitsMSP4(t *testing.T) {
	ctx := context.Background()
	s := newZone(t)
	c := newClient(t, s, atSecret, nil)
	if _, err := c.PushUsage(ctx, period(time.September, "301", 40, 3)); err != nil {
		t.Fatal(err)
	}
	october := time.Date(2026, time.October, 1, 0, 0, 0, 0, time.UTC)
	if s.Units(3101, october) != 40 || s.Units(3102, october) != 3 {
		t.Fatalf("units after September = %d/%d", s.Units(3101, october), s.Units(3102, october))
	}
	_, writes, _ := s.Counts()
	if _, err := c.PushUsage(ctx, period(time.September, "301", 40, 3)); err != nil {
		t.Fatal(err)
	}
	if _, again, _ := s.Counts(); again != writes {
		t.Fatalf("the same period again wrote %d times", again-writes)
	}
	s.FailWritesAfterApplying(1)
	_, err := c.PushUsage(ctx, period(time.October, "301", 37, 3))
	if err == nil || errors.Is(err, psa.ErrBeforeWrite) {
		t.Fatalf("a lost answer = %v, want an unknown outcome", err)
	}
	noKeys(t, err)
	if _, err := c.PushUsage(ctx, period(time.October, "301", 37, 3)); err != nil {
		t.Fatal(err)
	}
	november := time.Date(2026, time.November, 1, 0, 0, 0, 0, time.UTC)
	if s.Units(3101, november) != 37 || s.Units(3102, november) != 3 {
		t.Fatalf("units after October's retry = %d/%d, want 37/3", s.Units(3101, november), s.Units(3102, november))
	}
	for _, a := range s.Adjustments() {
		if a.ContractServiceID == 3201 || a.ContractServiceID == 3202 {
			t.Fatalf("another company's contract was adjusted: %+v", a)
		}
	}
}

// MSP-4: anything that cannot be resolved unambiguously refuses the period
// before any write: a non-numeric or unknown company, an inactive one, no
// contract in force (or two), a service missing from the contract, wrong
// credentials; no error names a credential.
func TestPushUsageRefusesBeforeAnyWriteMSP4(t *testing.T) {
	ctx := context.Background()
	s := newZone(t)
	s.AddCompany(psatest.ATCompany{ID: 304, Name: "Two Contracts", Active: true})
	s.AddContract(psatest.ATContract{ID: 41, CompanyID: 304, Name: "A", Type: autotask.RecurringServiceContract, Start: contractStart, End: contractEnd})
	s.AddContract(psatest.ATContract{ID: 42, CompanyID: 304, Name: "B", Type: autotask.RecurringServiceContract, Start: contractStart, End: contractEnd})
	s.AddCompany(psatest.ATCompany{ID: 305, Name: "No Service", Active: true})
	s.AddContract(psatest.ATContract{ID: 51, CompanyID: 305, Name: "Managed PKI", Type: autotask.RecurringServiceContract, Start: contractStart, End: contractEnd})
	c := newClient(t, s, atSecret, nil)
	for _, company := range []string{"ALPHA", "999", "303", "304", "305"} {
		_, err := c.PushUsage(ctx, period(time.October, company, 1, 1))
		if !errors.Is(err, psa.ErrBeforeWrite) {
			t.Fatalf("company %q = %v, want a refusal before any write", company, err)
		}
		noKeys(t, err)
	}
	if _, writes, _ := s.Counts(); writes != 0 {
		t.Fatalf("%d writes reached the zone", writes)
	}
	wrong := newClient(t, s, "not-the-secret", nil)
	_, err := wrong.PushUsage(ctx, period(time.October, "301", 1, 1))
	if !errors.Is(err, psa.ErrBeforeWrite) || !strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "not-the-secret") {
		t.Fatalf("wrong secret = %v", err)
	}
}

// MSP-4 Done-when (tickets, connector): a ticket opens under the company
// with its externalID and the configured status, priority and queue, and
// opening it again (a retry after a lost answer) finds it; notes are added
// once; closing adds the resolution and sets the complete status once; a
// ticket gone is left alone; paging through notes past one page still finds
// a note's reference.
func TestTicketsOpenNoteAndCloseOnceMSP4(t *testing.T) {
	ctx := context.Background()
	s := newZone(t)
	tickets := &autotask.TicketConfig{QueueID: 29682833, StatusNew: 1, StatusComplete: 5, Priority: 2, NoteType: 1, NotePublish: 1}
	c := newClient(t, s, atSecret, tickets)
	open := psa.TicketOpen{ExternalCompanyID: "301", Reference: "trstctl-0123456789abcdef01234567", Summary: "Renewal failed: orders-api",
		Description: "first alert\n\nPowered by trstctl"}
	s.FailWritesAfterApplying(1)
	if _, err := c.OpenTicket(ctx, open); err == nil || errors.Is(err, psa.ErrBeforeWrite) {
		t.Fatalf("a lost answer on open = %v", err)
	}
	id, err := c.OpenTicket(ctx, open)
	if err != nil {
		t.Fatal(err)
	}
	all := s.Tickets()
	if len(all) != 1 || strconv.FormatInt(all[0].ID, 10) != id || all[0].CompanyID != 301 || all[0].Status != 1 || all[0].Priority != 2 ||
		all[0].QueueID != 29682833 || all[0].ExternalID != open.Reference {
		t.Fatalf("tickets = %+v (id %s)", all, id)
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
	if notes := s.Notes(); len(notes) != 3 || notes[0].NoteType != 1 || notes[0].Publish != 1 || !strings.Contains(notes[0].Description, psa.NoteMarker("n-0")) {
		t.Fatalf("notes = %+v", notes)
	}
	if err := c.CloseTicket(ctx, psa.TicketClose{TicketID: id, Reference: "c-1", Resolution: "Resolved: a renewal succeeded"}); err != nil {
		t.Fatal(err)
	}
	_, writes, _ := s.Counts()
	if err := c.CloseTicket(ctx, psa.TicketClose{TicketID: id, Reference: "c-1", Resolution: "Resolved: a renewal succeeded"}); err != nil {
		t.Fatal(err)
	}
	if _, again, _ := s.Counts(); again != writes || s.Tickets()[0].Status != 5 || len(s.Notes()) != 4 {
		t.Fatalf("after closing twice: %d more writes, %+v, %d notes", again-writes, s.Tickets()[0], len(s.Notes()))
	}
	if err := c.CloseTicket(ctx, psa.TicketClose{TicketID: "999999", Reference: "c-x", Resolution: "gone"}); err != nil {
		t.Fatalf("closing a ticket gone = %v", err)
	}
	if _, err := c.OpenTicket(ctx, psa.TicketOpen{ExternalCompanyID: "302", Reference: strings.Repeat("x", 51), Summary: "s"}); !errors.Is(err, psa.ErrBeforeWrite) {
		t.Fatalf("an externalID over 50 characters = %v", err)
	}
	if _, _, refused := s.Counts(); refused != 0 {
		t.Fatalf("%d requests were refused", refused)
	}
}
