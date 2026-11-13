// SPDX-License-Identifier: BUSL-1.1

package connectwise_test

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/psa"
	"trstctl.com/trstctl/internal/psa/connectwise"
	"trstctl.com/trstctl/internal/psa/psatest"
)

const (
	cwLogin   = "trstctl_msp"
	cwClient  = "6c1a3e1e-58e3-4d1b-9f0e-3b8f5a0c2d71"
	cwPublic  = "cw-public-member-key"
	cwPrivate = "cw-private-member-key"
)

func newStandIn(t *testing.T) *psatest.ConnectWise {
	t.Helper()
	s := psatest.NewConnectWise(cwLogin, cwClient, cwPublic, cwPrivate)
	t.Cleanup(s.Close)
	s.AddCompany(psatest.CWCompany{ID: 101, Identifier: "ALPHA", Name: "Alpha Dental"})
	s.AddCompany(psatest.CWCompany{ID: 202, Identifier: "BETA", Name: "Beta Logistics"})
	s.AddCompany(psatest.CWCompany{ID: 303, Identifier: "GONE", Name: "Gone Ltd", Deleted: true})
	s.AddAgreement(psatest.CWAgreement{ID: 11, CompanyID: 101, TypeName: "Managed PKI", Status: "Active"})
	s.AddAgreement(psatest.CWAgreement{ID: 12, CompanyID: 101, TypeName: "Backup", Status: "Active"})
	s.AddAgreement(psatest.CWAgreement{ID: 21, CompanyID: 202, TypeName: "Managed PKI", Status: "Active"})
	s.AddAgreement(psatest.CWAgreement{ID: 22, CompanyID: 202, TypeName: "Managed PKI", Status: "Cancelled", Cancelled: true})
	return s
}

func newClient(t *testing.T, s *psatest.ConnectWise, public, private string, products map[string]string) *connectwise.Client {
	t.Helper()
	if products == nil {
		products = map[string]string{"certificates_current": "TRST-CERT", "agents": "TRST-AGENT"}
	}
	c, err := connectwise.New(connectwise.Config{BaseURL: s.URL(), CompanyID: cwLogin, ClientID: cwClient,
		AgreementType: "Managed PKI", Products: products}, http.DefaultClient,
		connectwise.Credentials{PublicKey: []byte(public), PrivateKey: []byte(private)})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func october(company string, certs, agents, secrets int64) psa.UsagePeriod {
	start := time.Date(2026, time.October, 1, 0, 0, 0, 0, time.UTC)
	return psa.UsagePeriod{CustomerID: "customer", ExternalCompanyID: company, PeriodStart: start, PeriodEnd: start.AddDate(0, 1, 0),
		EvidenceDigest: "sha256:0123", Lines: []psa.UsageLine{{Meter: "agents", Value: agents},
			{Meter: "certificates_current", Value: certs}, {Meter: "secrets_stored", Value: secrets}}}
}

func noKeys(t *testing.T, err error) {
	t.Helper()
	if err != nil && (strings.Contains(err.Error(), cwPublic) || strings.Contains(err.Error(), cwPrivate)) {
		t.Fatalf("an error carries an API key: %v", err)
	}
}

// MSP-3 Done-when (usage, connector): a signed period lands as additions of
// the company's one active agreement of the configured type, one per
// configured product with the period's figure (a meter without a product is
// not pushed); the same period again writes nothing; a changed figure
// patches the quantity rather than adding a line.
func TestPushUsageSetsAgreementAdditionsMSP3(t *testing.T) {
	ctx := context.Background()
	s := newStandIn(t)
	c := newClient(t, s, cwPublic, cwPrivate, nil)
	out, err := c.PushUsage(ctx, october("101", 42, 3, 9))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(out.Set, ",") != "agents,certificates_current" || out.Status != http.StatusCreated {
		t.Fatalf("outcome = %+v", out)
	}
	adds := s.Additions(11)
	if len(adds) != 2 || adds[0].Product != "TRST-AGENT" || adds[0].Quantity != 3 || adds[1].Product != "TRST-CERT" ||
		adds[1].Quantity != 42 || adds[1].BillCustomer != "Billable" || adds[1].EffectiveDate != "2026-10-01T00:00:00Z" {
		t.Fatalf("additions = %+v", adds)
	}
	if len(s.Additions(12)) != 0 || len(s.Additions(21)) != 0 {
		t.Fatal("a push touched another agreement")
	}
	_, writes, _ := s.Counts()
	if _, err := c.PushUsage(ctx, october("101", 42, 3, 9)); err != nil {
		t.Fatal(err)
	}
	if _, again, _ := s.Counts(); again != writes {
		t.Fatalf("the same period again wrote %d times", again-writes)
	}
	if _, err := c.PushUsage(ctx, october("ALPHA", 40, 3, 9)); err != nil {
		t.Fatal(err)
	}
	adds = s.Additions(11)
	if len(adds) != 2 || adds[1].Quantity != 40 {
		t.Fatalf("a changed figure: %+v", adds)
	}
}

// MSP-3 Done-when (retry): a write that took effect but whose answer was lost
// fails the attempt with an unknown outcome; the retry finds the addition
// and sets the same figure, so nothing is doubled.
func TestPushUsageRetryAfterALostAnswerDoesNotDoubleMSP3(t *testing.T) {
	ctx := context.Background()
	s := newStandIn(t)
	c := newClient(t, s, cwPublic, cwPrivate, nil)
	s.FailWritesAfterApplying(1)
	_, err := c.PushUsage(ctx, october("BETA", 7, 1, 0))
	if err == nil || errors.Is(err, psa.ErrBeforeWrite) || errors.Is(err, psa.ErrRefused) {
		t.Fatalf("a lost answer = %v, want an unknown outcome", err)
	}
	noKeys(t, err)
	if _, err := c.PushUsage(ctx, october("BETA", 7, 1, 0)); err != nil {
		t.Fatal(err)
	}
	adds := s.Additions(21)
	if len(adds) != 2 || adds[0].Quantity != 1 || adds[1].Quantity != 7 {
		t.Fatalf("after the retry: %+v", adds)
	}
}

// MSP-3: anything that cannot be resolved unambiguously refuses the period
// before any write, and no error names an API key.
func TestPushUsageRefusesBeforeAnyWriteMSP3(t *testing.T) {
	ctx := context.Background()
	s := newStandIn(t)
	s.AddCompany(psatest.CWCompany{ID: 404, Identifier: "NOAGREEMENT", Name: "No Agreement"})
	s.AddCompany(psatest.CWCompany{ID: 505, Identifier: "TWOAGREEMENTS", Name: "Two Agreements"})
	s.AddAgreement(psatest.CWAgreement{ID: 51, CompanyID: 505, TypeName: "Managed PKI", Status: "Active"})
	s.AddAgreement(psatest.CWAgreement{ID: 52, CompanyID: 505, TypeName: "Managed PKI", Status: "Active"})
	s.AddCompany(psatest.CWCompany{ID: 606, Identifier: "DUPLICATE", Name: "Duplicate Lines"})
	s.AddAgreement(psatest.CWAgreement{ID: 61, CompanyID: 606, TypeName: "Managed PKI", Status: "Active"})
	s.AddAddition(psatest.CWAddition{ID: 1, AgreementID: 61, Product: "TRST-CERT", Quantity: 1, BillCustomer: "Billable"})
	s.AddAddition(psatest.CWAddition{ID: 2, AgreementID: 61, Product: "TRST-CERT", Quantity: 2, BillCustomer: "Billable"})
	c := newClient(t, s, cwPublic, cwPrivate, nil)
	for _, company := range []string{"999", "GONE", "303", "NOAGREEMENT", "TWOAGREEMENTS", "DUPLICATE", `ALPHA" or identifier="BETA`} {
		_, err := c.PushUsage(ctx, october(company, 1, 1, 1))
		if !errors.Is(err, psa.ErrBeforeWrite) {
			t.Fatalf("company %q: %v, want a refusal before any write", company, err)
		}
		noKeys(t, err)
	}
	if _, writes, _ := s.Counts(); writes != 0 {
		t.Fatalf("%d writes reached the stand-in", writes)
	}
	for _, seen := range s.Seen() {
		if strings.Contains(seen, "BETA") {
			t.Fatalf("an identifier that needs escaping reached a query: %s", seen)
		}
	}

	// Wrong keys: the lookup is refused, and the error names neither key.
	wrong := newClient(t, s, "not-the-public-key", "not-the-private-key", nil)
	_, err := wrong.PushUsage(ctx, october("101", 1, 1, 1))
	if !errors.Is(err, psa.ErrBeforeWrite) || !strings.Contains(err.Error(), "401") {
		t.Fatalf("wrong keys = %v", err)
	}
	if strings.Contains(err.Error(), "not-the-p") {
		t.Fatalf("the error echoes a key: %v", err)
	}
	if _, _, refused := s.Counts(); refused == 0 {
		t.Fatal("the stand-in did not see the wrong keys")
	}
}

// MSP-3: a figure the catalog refuses fails as the system's definitive
// answer; a configured meter with no reading in the signed period is 0.
func TestPushUsageRefusedWriteAndMissingMeterMSP3(t *testing.T) {
	ctx := context.Background()
	s := newStandIn(t)
	s.RejectProduct("TRST-SECRET")
	c := newClient(t, s, cwPublic, cwPrivate, map[string]string{"secrets_stored": "TRST-SECRET"})
	_, err := c.PushUsage(ctx, october("101", 1, 1, 5))
	if !errors.Is(err, psa.ErrRefused) || !strings.Contains(err.Error(), "TRST-SECRET was not found") {
		t.Fatalf("refused write = %v", err)
	}
	noKeys(t, err)

	c = newClient(t, s, cwPublic, cwPrivate, map[string]string{"agents": "TRST-AGENT"})
	period := october("202", 1, 1, 1)
	period.Lines = []psa.UsageLine{{Meter: "certificates_current", Value: 4}}
	if _, err := c.PushUsage(ctx, period); err != nil {
		t.Fatal(err)
	}
	if adds := s.Additions(21); len(adds) != 1 || adds[0].Product != "TRST-AGENT" || adds[0].Quantity != 0 {
		t.Fatalf("a meter with no reading: %+v", adds)
	}
}

func newTicketClient(t *testing.T, s *psatest.ConnectWise) *connectwise.Client {
	t.Helper()
	c, err := connectwise.New(connectwise.Config{BaseURL: s.URL(), CompanyID: cwLogin, ClientID: cwClient,
		Tickets: &connectwise.TicketConfig{Board: "Managed PKI", NewStatus: "New (trstctl)", ClosedStatus: ">Closed"}},
		http.DefaultClient, connectwise.Credentials{PublicKey: []byte(cwPublic), PrivateKey: []byte(cwPrivate)})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// MSP-3 Done-when (tickets, connector): a ticket opens on the board under
// the mapped company with its reference, and opening it again (a retry after
// a lost answer) finds it instead of opening a second; a note is added once
// however often it is retried; closing notes the resolution and moves it to
// the closed status, and closing it again (or a ticket gone at the PSA)
// changes nothing; another company's ticket with the same reference is never
// touched.
func TestTicketsOpenNoteAndCloseOnceMSP3(t *testing.T) {
	ctx := context.Background()
	s := newStandIn(t)
	s.AddBoard("Managed PKI", ">Closed")
	c := newTicketClient(t, s)
	open := psa.TicketOpen{ExternalCompanyID: "ALPHA", Reference: "trstctl-0123456789abcdef01234567",
		Summary: strings.Repeat("Certificate expires in 14 days: api.alpha.example ", 4), Description: "first alert\nPowered by trstctl"}
	s.FailWritesAfterApplying(1)
	if _, err := c.OpenTicket(ctx, open); err == nil || errors.Is(err, psa.ErrBeforeWrite) {
		t.Fatalf("a lost answer on open = %v, want an unknown outcome", err)
	}
	id, err := c.OpenTicket(ctx, open)
	if err != nil {
		t.Fatal(err)
	}
	tickets := s.Tickets()
	if len(tickets) != 1 || strconv.FormatInt(tickets[0].ID, 10) != id || tickets[0].CompanyID != 101 || tickets[0].Board != "Managed PKI" ||
		tickets[0].Status != "New (trstctl)" || len([]rune(tickets[0].Summary)) != 100 || !strings.Contains(tickets[0].Description, "Powered by trstctl") {
		t.Fatalf("tickets after open + retry = %+v (id %s)", tickets, id)
	}
	// Beta holds a ticket with the same reference: Alpha's open never finds it.
	betaOpen := open
	betaOpen.ExternalCompanyID = "202"
	betaID, err := c.OpenTicket(ctx, betaOpen)
	if err != nil || betaID == id {
		t.Fatalf("Beta's ticket = %s (%v), want its own", betaID, err)
	}
	if again, err := c.OpenTicket(ctx, open); err != nil || again != id {
		t.Fatalf("opening Alpha's ticket again = %s (%v), want %s", again, err, id)
	}
	note := psa.TicketNote{TicketID: id, Reference: "n-111", Text: "second alert: 7 days left"}
	s.FailWritesAfterApplying(1)
	if err := c.AddNote(ctx, note); err == nil {
		t.Fatal("a lost answer on a note did not fail the attempt")
	}
	for i := 0; i < 2; i++ {
		if err := c.AddNote(ctx, note); err != nil {
			t.Fatal(err)
		}
	}
	closing := psa.TicketClose{TicketID: id, Reference: "c-222", Resolution: "the certificate was renewed"}
	if err := c.CloseTicket(ctx, closing); err != nil {
		t.Fatal(err)
	}
	_, writes, _ := s.Counts()
	if err := c.CloseTicket(ctx, closing); err != nil {
		t.Fatal(err)
	}
	if _, again, _ := s.Counts(); again != writes {
		t.Fatalf("closing a closed ticket wrote %d times", again-writes)
	}
	for _, ticket := range s.Tickets() {
		if strconv.FormatInt(ticket.ID, 10) == id {
			if !ticket.Closed || ticket.Status != ">Closed" || len(ticket.Notes) != 2 || !ticket.Notes[1].Resolution ||
				!strings.Contains(ticket.Notes[0].Text, psa.NoteMarker("n-111")) {
				t.Fatalf("Alpha's ticket after notes and close = %+v", ticket)
			}
		} else if ticket.Closed || len(ticket.Notes) != 0 {
			t.Fatalf("Beta's ticket was touched: %+v", ticket)
		}
	}
	if err := c.CloseTicket(ctx, psa.TicketClose{TicketID: "999999", Reference: "c-x", Resolution: "gone"}); err != nil {
		t.Fatalf("closing a ticket gone at the PSA = %v, want nothing to do", err)
	}
	if _, err := c.OpenTicket(ctx, psa.TicketOpen{ExternalCompanyID: "ALPHA", Reference: `ref" or externalXRef="x`, Summary: "s"}); !errors.Is(err, psa.ErrBeforeWrite) {
		t.Fatalf("a reference that needs escaping = %v", err)
	}
	if _, _, refused := s.Counts(); refused != 0 {
		t.Fatalf("%d requests were refused", refused)
	}
}
