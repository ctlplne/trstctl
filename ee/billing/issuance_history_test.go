// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing_test

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	corestore "trstctl.com/trstctl/internal/store"
)

// The recount must follow successful certificate mints, not how often an
// identity entered its initial issued state. Real certificate events, NATS and
// PostgreSQL exercise the distinction; no served CA or connector is simulated.
func TestIssuanceHistoryCountsRenewalsWithoutCountingObservations(t *testing.T) {
	pgStore, cs := newBillingStoreOn(t, "billing_issuance_history")
	ctx := t.Context()
	log, projector, orch := billingHistory(t, cs)
	from := time.Now().UTC().Add(-time.Second)
	check := func(name, tenant string, want int64) {
		t.Helper()
		got, known, err := pgStore.IssuedInPeriod(ctx, tenant, from, time.Now().UTC().Add(time.Second))
		if err != nil || !known || got != want {
			t.Errorf("%s: issued=%d known=%t error=%v; want %d confirmed mints", name, got, known, err, want)
		}
	}
	check("empty history", quotaTenant, 0)
	first := billingMintedCertificate(t, "issued", "issue:transition:first")
	stored, err := orch.RecordCertificate(ctx, quotaTenant, first)
	if err != nil {
		t.Fatal(err)
	}
	// The ordinary first-issuance lifecycle also records this transition. It
	// is not repeated when that same identity receives a renewed certificate.
	seedIssuedTransition(t, cs, quotaTenant, 1, stored.CreatedAt)
	check("first mint", quotaTenant, 1)
	firstEnd := stored.CreatedAt.Add(time.Microsecond)

	renewal := billingMintedCertificate(t, "issued", "issue:transition:renewal")
	renewed, err := orch.RecordSuccessorCertificate(ctx, quotaTenant, renewal, stored.ID)
	if err != nil {
		t.Fatal(err)
	}
	check("renewal", quotaTenant, 2)
	if _, err := orch.RecordSuccessorCertificate(ctx, quotaTenant, renewal, stored.ID); err != nil {
		t.Fatal(err)
	}
	check("exact renewal retry", quotaTenant, 2)

	protocol := billingMintedCertificate(t, "protocol:acme", "acme:history-order")
	if _, err := orch.RecordCertificate(ctx, quotaTenant, protocol); err != nil {
		t.Fatal(err)
	}
	check("protocol mint", quotaTenant, 3)
	imported := billingMintedCertificate(t, "imported", "")
	if _, err := orch.RecordCertificate(ctx, quotaTenant, imported); err != nil {
		t.Fatal(err)
	}
	observation := first
	observation.Source, observation.IssuanceIdempotencyKey = "discovered", ""
	if _, err := orch.RecordCertificate(ctx, quotaTenant, observation); err != nil {
		t.Fatal(err)
	}
	check("import and rediscovery", quotaTenant, 3)
	observation.Source = "issued"
	if _, err := orch.RecordCertificate(ctx, quotaTenant, observation); err != nil {
		t.Fatal(err)
	}
	check("repeated mint observation is not a new certificate", quotaTenant, 3)
	gotFirst, knownFirst, err := pgStore.IssuedInPeriod(ctx, quotaTenant, from, firstEnd)
	if err != nil || !knownFirst || gotFirst != 1 {
		t.Fatalf("original mint period changed after later observations: count=%d known=%t error=%v", gotFirst, knownFirst, err)
	}
	if err := orch.RevokeCertificate(ctx, quotaTenant, renewed.Fingerprint, renewed.Serial, "keyCompromise", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	check("revocation preserves historical mint", quotaTenant, 3)
	if _, err := orch.RecordCertificate(ctx, otherTenant, billingMintedCertificate(t, "protocol:est", "est:other-order")); err != nil {
		t.Fatal(err)
	}
	check("neighbor cannot inflate count", quotaTenant, 3)
	check("neighbor has its own mint", otherTenant, 1)
	got, known, err := pgStore.IssuedInPeriod(context.Background(), quotaTenant, from.Add(-time.Hour), from)
	if err != nil || !known || got != 0 {
		t.Fatalf("period before all mints: count=%d known=%t error=%v", got, known, err)
	}

	// An upgraded database or old snapshot contains completion receipts but
	// no issuance summaries. It must refuse a claimed zero until source replay
	// rebuilds them, without requiring another mint to trigger recovery.
	if err := cs.WithTenant(ctx, quotaTenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE certificate_metadata_receipts
			SET issuance_status=NULL,issuance_fingerprint=NULL,issuance_time=NULL WHERE tenant_id=$1`, quotaTenant)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, known, err := pgStore.IssuedInPeriod(ctx, quotaTenant, from, time.Now().UTC().Add(time.Second)); err != nil || known {
		t.Fatalf("legacy receipts must remain unknown: known=%t error=%v", known, err)
	}
	check("legacy neighbor does not contaminate this tenant", otherTenant, 1)
	// An unavailable historical prefix cannot authorize dropping the existing
	// inventory or pretending its unknown issuance facts were verified empty.
	missingHistory, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = missingHistory.Close() })
	if err := projector.ProjectCatchUp(ctx, missingHistory); err != nil {
		t.Fatal(err)
	}
	if _, known, err := pgStore.IssuedInPeriod(ctx, quotaTenant, from, time.Now().UTC().Add(time.Second)); err != nil || known {
		t.Errorf("missing source history must remain unknown: known=%t error=%v", known, err)
	}
	if _, err := cs.GetCertificateByFingerprint(ctx, quotaTenant, renewed.Fingerprint); err != nil {
		t.Errorf("invoice-fact upgrade discarded retained inventory: %v", err)
	}
	if err := projector.ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}
	check("boot backfills immutable source history", quotaTenant, 3)
	if needed, err := cs.CertificateIssuanceReceiptsNeedBackfill(ctx); err != nil || needed {
		t.Fatalf("completed source replay still needs backfill=%t: %v", needed, err)
	}
}

func billingHistory(t *testing.T, cs *corestore.Store) (*events.Log, *projections.Projector, *orchestrator.Orchestrator) {
	t.Helper()
	ctx := t.Context()
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	projector := projections.New(cs)
	for _, tenant := range []string{quotaTenant, otherTenant} {
		e, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered,
			TenantID: tenant, Data: []byte(`{"name":"issuance-history"}`)})
		if err != nil {
			t.Fatal(err)
		}
		if err := projector.Apply(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	return log, projector, orchestrator.NewOrchestrator(log, cs, nil)
}

func TestIssuanceHistoryIncludesEachServedRecordingSource(t *testing.T) {
	pgStore, cs := newBillingStoreOn(t, "billing_issuance_sources")
	_, _, orch := billingHistory(t, cs)
	from := time.Now().UTC().Add(-time.Second)
	for i, source := range []string{"issued", "protocol:acme", "protocol:est", "attested:kubernetes", "broker:kubernetes", "ephemeral:kubernetes", "external-ca:owned-authority"} {
		c := billingMintedCertificate(t, source, "source:"+source)
		if _, err := orch.RecordCertificate(t.Context(), quotaTenant, c); err != nil {
			t.Fatal(err)
		}
		got, known, err := pgStore.IssuedInPeriod(t.Context(), quotaTenant, from, time.Now().UTC().Add(time.Second))
		if err != nil || !known || got != int64(i+1) {
			t.Errorf("source %s: count=%d known=%t error=%v; want %d", source, got, known, err, i+1)
		}
	}
}

// Only the fixture event time is supplied; the host and running lab clocks
// remain unchanged. The actual production recorder/projector writes the fact.
func billingRecordAt(t *testing.T, orch *orchestrator.Orchestrator, tenant string, at time.Time, sources ...string) {
	t.Helper()
	source := "issued"
	if len(sources) != 0 {
		source = sources[0]
	}
	c := billingMintedCertificate(t, source, "issue:transition:"+uuid.NewString())
	data, err := json.Marshal(projections.CertificateRecorded{
		ID: uuid.NewString(), Source: c.Source, Subject: c.Subject, Issuer: c.Issuer,
		Serial: c.Serial, Fingerprint: c.Fingerprint, KeyAlgorithm: c.KeyAlgorithm,
		NotBefore: c.NotBefore, NotAfter: c.NotAfter, CertificateDER: c.CertificateDER,
		CertificatePEM: c.CertificatePEM, IssuanceIdempotencyKey: c.IssuanceIdempotencyKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := orch.RecordCertificateEvent(t.Context(), events.Event{ID: events.NewID(),
		Type: projections.EventCertificateRecorded, TenantID: tenant, Time: at, Data: data}); err != nil {
		t.Fatal(err)
	}
}

func billingMintedCertificate(t *testing.T, source, key string) corestore.Certificate {
	t.Helper()
	ca, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer ca.Destroy()
	root, err := crypto.SelfSignedCACert(ca, "billing-test-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	subject, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer subject.Destroy()
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "billing.example.test"}, subject)
	if err != nil {
		t.Fatal(err)
	}
	der, err := crypto.SignLeafFromCSR(root, ca, csr, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	info, err := certinfo.Inspect(der)
	if err != nil {
		t.Fatal(err)
	}
	return corestore.Certificate{Source: source, Subject: info.Subject, Issuer: info.Issuer,
		Serial: info.SerialNumber, Fingerprint: info.SHA256Fingerprint, KeyAlgorithm: info.KeyAlgorithm,
		NotBefore: &info.NotBefore, NotAfter: &info.NotAfter, CertificateDER: der,
		CertificatePEM:         pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		IssuanceIdempotencyKey: key, KeyOrigin: "requester"}
}
