package projections_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/ctlog"
	"trstctl.com/trstctl/internal/discovery/ctmonitor"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/orchestrator"
)

// ctFakeFetcher serves a fixed set of CT entries (the parsing of real RFC 6962
// responses is covered in internal/crypto/ctlog).
type ctFakeFetcher struct {
	entries []ctlog.Entry
}

func (f *ctFakeFetcher) TreeSize(context.Context, string) (int64, error) {
	return int64(len(f.entries)), nil
}

func (f *ctFakeFetcher) Entries(_ context.Context, _ string, start, end int64) ([]ctlog.Entry, error) {
	var out []ctlog.Entry
	for i := start; i < end && i < int64(len(f.entries)); i++ {
		out = append(out, f.entries[i])
	}
	return out, nil
}

// TestCTUnexpectedIssuanceReachesNotificationSurface is the S6.5 acceptance over
// real embedded PostgreSQL: a newly logged certificate for a watched domain that
// is not in the inventory raises an alert on the shared notification surface,
// while a known-good certificate for the same domain does not.
func TestCTUnexpectedIssuanceReachesNotificationSurface(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	exp := time.Now().Add(720 * time.Hour)

	// A certificate trstctl already knows about (it is in the inventory).
	known := sampleCert(tenantA, "known-fp", "CN=known.example.com", exp)
	known.Issuer = "CN=Acme Root"
	known.Serial = "01"
	if _, err := s.UpsertCertificate(ctx, known); err != nil {
		t.Fatalf("seed known cert: %v", err)
	}

	fetch := &ctFakeFetcher{entries: []ctlog.Entry{
		{ // known-good: fingerprint matches the inventory row -> no alert
			Index: 0, Subject: "CN=known.example.com", Issuer: "CN=Acme Root",
			SerialHex: "01", FingerprintSHA256: "known-fp",
			DNSNames: []string{"known.example.com"}, NotAfter: exp,
		},
		{ // unexpected: a rogue issuer for a watched domain -> alert
			Index: 1, Subject: "CN=shadow.example.com", Issuer: "CN=Rogue CA",
			SerialHex: "deadbeef", FingerprintSHA256: "rogue-fp",
			DNSNames: []string{"shadow.example.com"}, NotAfter: exp,
		},
	}}

	ob := orchestrator.NewOutbox(s)
	m := ctmonitor.New(fetch, ctmonitor.NewStoreKnownGood(s), ctmonitor.NewStoreAlerter(s, ob),
		ctmonitor.Config{WatchedDomains: []string{"example.com"}})

	state, findings, err := m.Poll(ctx, tenantA, ctmonitor.LogState{URL: "https://ct.example/log"})
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if state.Checkpoint != 2 {
		t.Errorf("checkpoint = %d, want 2", state.Checkpoint)
	}
	if len(findings) != 1 || findings[0].Subject != "CN=shadow.example.com" {
		t.Fatalf("findings = %+v, want one for shadow.example.com", findings)
	}

	// Exactly one alert is on the shared notification surface, and it is the
	// unexpected certificate — the known-good one raised nothing.
	pending, err := ob.Pending(ctx, tenantA)
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	var ctAlerts []notify.Alert
	for _, rec := range pending {
		if rec.Destination != notify.DestinationCTLog {
			continue
		}
		var a notify.Alert
		if err := json.Unmarshal(rec.Payload, &a); err != nil {
			t.Fatalf("decode alert: %v", err)
		}
		ctAlerts = append(ctAlerts, a)
	}
	if len(ctAlerts) != 1 {
		t.Fatalf("notification.ct alerts = %d, want 1", len(ctAlerts))
	}
	a := ctAlerts[0]
	if a.Kind != notify.KindUnexpectedIssuance {
		t.Errorf("alert kind = %q, want %q", a.Kind, notify.KindUnexpectedIssuance)
	}
	if a.Subject != "CN=shadow.example.com" || a.Serial != "deadbeef" {
		t.Errorf("alert = %+v, want the shadow certificate", a)
	}
}

// TestCTKnownGoodIssuanceRaisesNoAlert isolates the suppression half: when every
// logged certificate for the watched domain is already inventoried, no alert is
// raised.
func TestCTKnownGoodIssuanceRaisesNoAlert(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	exp := time.Now().Add(720 * time.Hour)

	c := sampleCert(tenantA, "fp-app", "CN=app.example.com", exp)
	if _, err := s.UpsertCertificate(ctx, c); err != nil {
		t.Fatalf("seed cert: %v", err)
	}

	fetch := &ctFakeFetcher{entries: []ctlog.Entry{{
		Index: 0, Subject: "CN=app.example.com", Issuer: c.Issuer,
		SerialHex: c.Serial, FingerprintSHA256: "fp-app",
		DNSNames: []string{"app.example.com"}, NotAfter: exp,
	}}}

	ob := orchestrator.NewOutbox(s)
	m := ctmonitor.New(fetch, ctmonitor.NewStoreKnownGood(s), ctmonitor.NewStoreAlerter(s, ob),
		ctmonitor.Config{WatchedDomains: []string{"example.com"}})

	_, findings, err := m.Poll(ctx, tenantA, ctmonitor.LogState{URL: "https://ct.example/log"})
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("known-good issuance produced %d findings, want 0", len(findings))
	}
	pending, err := ob.Pending(ctx, tenantA)
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	for _, rec := range pending {
		if rec.Destination == notify.DestinationCTLog {
			t.Errorf("known-good issuance must raise no CT alert, found: %s", rec.Payload)
		}
	}
}
