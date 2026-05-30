package projections_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"certctl.io/certctl/internal/crypto/certinfo"
	"certctl.io/certctl/internal/crypto/ctlog/ctlogtest"
	"certctl.io/certctl/internal/discovery/ctmonitor"
	"certctl.io/certctl/internal/notify"
	"certctl.io/certctl/internal/orchestrator"
	"certctl.io/certctl/internal/store"
)

// TestCTMonitorEndToEndOverHTTP exercises the whole CT path with nothing faked
// but the log itself: a real HTTP fetcher pulls RFC 6962 responses from a
// faithful in-process CT log, the certificates are parsed through the crypto
// boundary, the known-good check and the alert both hit embedded PostgreSQL, and
// the scheduler loads watched domains and persists its checkpoint from the
// store. A logged certificate that certctl already inventoried raises nothing; a
// rogue one for a watched domain raises exactly one alert on the shared
// notification surface; and the persisted checkpoint stops it re-alerting.
func TestCTMonitorEndToEndOverHTTP(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	exp := time.Now().Add(720 * time.Hour)

	// A certificate certctl already knows: issue it, then inventory it by the
	// exact fingerprint the CT parser will compute.
	knownDER, _, err := ctlogtest.IssueCert("known", "known.example.com")
	if err != nil {
		t.Fatal(err)
	}
	knownInfo, err := certinfo.Inspect(knownDER)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpsertCertificate(ctx, store.Certificate{
		TenantID: tenantA, Subject: knownInfo.Subject, SANs: knownInfo.DNSNames,
		Issuer: knownInfo.Issuer, Serial: knownInfo.SerialNumber, Fingerprint: knownInfo.SHA256Fingerprint,
		KeyAlgorithm: "ECDSA", NotBefore: tptr(exp.Add(-24 * time.Hour)), NotAfter: tptr(exp),
		Source: "import", Status: "active",
	}); err != nil {
		t.Fatalf("seed known cert: %v", err)
	}

	// A rogue certificate for the same watched domain, served as a precert entry.
	shadowDER, shadowTBS, err := ctlogtest.IssueCert("shadow", "shadow.example.com")
	if err != nil {
		t.Fatal(err)
	}

	logSrv := ctlogtest.NewServer(
		ctlogtest.X509Entry(knownDER),
		ctlogtest.PrecertEntry(shadowDER, shadowTBS),
	)
	defer logSrv.Close()

	// Persist what to watch and which log to read.
	if err := s.AddWatchedDomain(ctx, tenantA, "example.com"); err != nil {
		t.Fatalf("add watched domain: %v", err)
	}
	if err := s.RegisterCTLog(ctx, tenantA, logSrv.URL()); err != nil {
		t.Fatalf("register log: %v", err)
	}

	ob := orchestrator.NewOutbox(s)
	sched := ctmonitor.NewScheduler(
		ctmonitor.NewStorePersistence(s),
		ctmonitor.NewHTTPFetcher(),
		ctmonitor.NewStoreKnownGood(s),
		ctmonitor.NewStoreAlerter(s, ob),
	)

	findings, err := sched.RunOnce(ctx, tenantA)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(findings) != 1 || findings[0].DNSNames[0] != "shadow.example.com" {
		t.Fatalf("findings = %+v, want one for shadow.example.com", findings)
	}

	// Exactly one alert on the shared surface, for the rogue certificate.
	ctAlerts := ctAlertsOnSurface(t, ctx, ob)
	if len(ctAlerts) != 1 {
		t.Fatalf("notification.ct alerts = %d, want 1", len(ctAlerts))
	}
	if ctAlerts[0].Kind != notify.KindUnexpectedIssuance || ctAlerts[0].Subject != "CN=shadow" {
		t.Errorf("alert = %+v", ctAlerts[0])
	}

	// The checkpoint advanced past both entries and was persisted.
	cps, err := s.ListCTLogCheckpoints(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	if len(cps) != 1 || cps[0].LogURL != logSrv.URL() || cps[0].NextIndex != 2 {
		t.Fatalf("checkpoints = %+v, want one at index 2", cps)
	}

	// A second run reads nothing new and raises no duplicate alert.
	findings2, err := sched.RunOnce(ctx, tenantA)
	if err != nil {
		t.Fatalf("second RunOnce: %v", err)
	}
	if len(findings2) != 0 {
		t.Errorf("second run findings = %d, want 0", len(findings2))
	}
	if got := ctAlertsOnSurface(t, ctx, ob); len(got) != 1 {
		t.Errorf("ct alerts after second run = %d, want 1 (no duplicate)", len(got))
	}
}

func ctAlertsOnSurface(t *testing.T, ctx context.Context, ob *orchestrator.Outbox) []notify.Alert {
	t.Helper()
	pending, err := ob.Pending(ctx, tenantA)
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	var out []notify.Alert
	for _, rec := range pending {
		if rec.Destination != notify.DestinationCTLog {
			continue
		}
		var a notify.Alert
		if err := json.Unmarshal(rec.Payload, &a); err != nil {
			t.Fatalf("decode alert: %v", err)
		}
		out = append(out, a)
	}
	return out
}
