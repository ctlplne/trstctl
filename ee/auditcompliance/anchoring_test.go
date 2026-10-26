// SPDX-License-Identifier: LicenseRef-trstctl-EE

package auditcompliance_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/auditcompliance"
	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/auditanchor"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tsa"
)

type anchorTenants []string

func (t anchorTenants) ListTenants(context.Context) ([]store.Tenant, error) {
	out := make([]store.Tenant, 0, len(t))
	for _, id := range t {
		out = append(out, store.Tenant{TenantID: id})
	}
	return out, nil
}

type anchorScopes struct{ held []string }

func (s *anchorScopes) WithAuditRetentionScope(ctx context.Context, scope string, fn func(context.Context) error) error {
	s.held = append(s.held, scope)
	return fn(ctx)
}

type switchableTSA struct {
	authority *tsa.Authority
	down      bool
}

func (s *switchableTSA) Timestamp(ctx context.Context, imprint []byte) (tsa.Token, error) {
	if s.down {
		return tsa.Token{}, errors.New("injected authority outage")
	}
	return s.authority.Timestamp(ctx, imprint)
}

func anchoringAuthority(t *testing.T) (*tsa.Authority, []byte) {
	t.Helper()
	root, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(root.Destroy)
	rootDER, err := crypto.SelfSignedCACert(root, "anchoring TSA root", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "anchoring TSA"}, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := crypto.SignTimestampingCertFromCSR(rootDER, root, csr, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := tsa.New(tsa.Config{TenantID: tenantA, TSACertDER: cert, TSASigner: key})
	if err != nil {
		t.Fatal(err)
	}
	return authority, rootDER
}

// A147: the licensed worker timestamps each tenant's full audit chain that grew
// since its last anchor and appends the anchor to that tenant's own audit log.
// A quiet tenant is left alone; the next pass after new records covers them and
// the earlier anchor's record; an authority outage appends nothing and is
// reported; and an export of the tenant's history verifies offline with every
// anchor re-checked and the hourly cadence held.
func TestAnchorWorkerAnchorsGrownChainsIntoTheirOwnAuditLog(t *testing.T) {
	ctx := context.Background()
	const quiet = "99999999-9999-9999-9999-999999999999"
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	appendRecord := func(typ string) {
		t.Helper()
		if _, err := log.Append(ctx, events.Event{Type: typ, TenantID: tenantA, Data: []byte(`{}`)}); err != nil {
			t.Fatal(err)
		}
	}
	appendRecord("test.audit.issued")
	appendRecord("test.audit.renewed")
	authority, rootDER := anchoringAuthority(t)
	ts := &switchableTSA{authority: authority}
	svc := audit.NewService(log, nil)
	scopes := &anchorScopes{}
	worker := auditcompliance.NewAnchorWorker(svc, log, ts, scopes, anchorTenants{tenantA, quiet}, time.Hour)

	sum, err := worker.RunOnce(ctx)
	if err != nil || sum.TenantsAnchored != 1 || sum.TenantsUnchanged != 1 {
		t.Fatalf("first pass = %+v, %v", sum, err)
	}
	if strings.Join(scopes.held, ",") != tenantA+","+quiet {
		t.Fatalf("anchoring did not hold each tenant's audit scope: %v", scopes.held)
	}
	if sum, err := worker.RunOnce(ctx); err != nil || sum.TenantsAnchored != 0 {
		t.Fatalf("a pass with nothing new anchored again: %+v, %v", sum, err)
	}
	appendRecord("test.audit.revoked")
	if sum, err := worker.RunOnce(ctx); err != nil || sum.TenantsAnchored != 1 {
		t.Fatalf("a pass after new records = %+v, %v", sum, err)
	}
	ts.down = true
	appendRecord("test.audit.deployed")
	if _, err := worker.RunOnce(ctx); err == nil || !strings.Contains(err.Error(), "injected authority outage") {
		t.Fatalf("an authority outage = %v", err)
	}
	ts.down = false

	records, seed, err := svc.SearchWithSeed(ctx, audit.Query{TenantID: tenantA})
	if err != nil {
		t.Fatal(err)
	}
	var anchors []audit.Record
	for _, record := range records {
		if record.Type == auditanchor.EventTypeAnchored {
			anchors = append(anchors, record)
		}
	}
	if len(records) != 6 || len(anchors) != 2 || anchors[0].Sequence != 3 || anchors[1].Sequence != 5 {
		t.Fatalf("tenant log = %d records, anchors at %+v", len(records), anchors)
	}
	exportAnchor, err := auditanchor.AnchorHead(ctx, authority, records[len(records)-1].Hash)
	if err != nil {
		t.Fatal(err)
	}
	result, err := auditanchor.VerifySeries(records, seed, audit.FullChain(audit.Query{TenantID: tenantA}, records), exportAnchor.AnchoredAt, rootDER, auditanchor.SeriesPolicy{Cadence: time.Hour})
	if err != nil || result.Anchors != 2 || result.Verified != 2 {
		t.Fatalf("offline series = %+v, %v", result, err)
	}
	if quietRecords, err := svc.Search(ctx, audit.Query{TenantID: quiet}); err != nil || len(quietRecords) != 0 {
		t.Fatalf("a quiet tenant was written to: %+v, %v", quietRecords, err)
	}

	// The projection serves the series from the event log alone.
	st := newAuditTestStore(t)
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "anchoring"}); err != nil {
		t.Fatal(err)
	}
	if err := projections.New(st).Project(ctx, log); err != nil {
		t.Fatal(err)
	}
	rows, err := st.ListAuditAnchors(ctx, tenantA, 10)
	if err != nil || len(rows) != 2 || rows[0].ThroughSequence != 4 || rows[1].ThroughSequence != 2 || rows[0].CadenceSeconds != 3600 {
		t.Fatalf("projected anchors = %+v, %v", rows, err)
	}
	if count, err := st.CountAuditAnchors(ctx, tenantA); err != nil || count != 2 {
		t.Fatalf("anchor count = %d, %v", count, err)
	}
}

// The licensed factory attaches the worker only with a cadence, a timestamp
// authority, checkpoints and a tenant list.
func TestLicensedFactoryAttachesAnchoringOnlyWithACadence(t *testing.T) {
	authority, _ := anchoringAuthority(t)
	log, err := events.Open(context.Background(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	st := newAuditTestStore(t)
	deps := editionseam.AuditComplianceDeps{
		Audit: audit.NewService(log, nil), Log: log, Checkpoints: st, Timestamper: authority, Tenants: st,
	}
	if auditcompliance.Build(deps).Anchoring != nil {
		t.Fatal("anchoring attached without a cadence")
	}
	deps.AnchorInterval = 15 * time.Minute
	runtime := auditcompliance.Build(deps)
	if runtime.Anchoring == nil || runtime.Anchoring.Interval() != 15*time.Minute {
		t.Fatalf("anchoring = %+v", runtime.Anchoring)
	}
}
