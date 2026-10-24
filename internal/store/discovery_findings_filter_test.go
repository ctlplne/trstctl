// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/discovery"
	"trstctl.com/trstctl/internal/store"
)

// A105: one source kind's findings page by id and count on the server, even
// when more than a page of other findings sorts before them, and a finding
// never triaged counts as unmanaged.
func TestDiscoveryFindingFilterPagesAndCountsOneSourceKind(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	type source struct {
		id, kind string
		first    int
		count    int
		findKind string
		meta     func(int) string
	}
	sources := []source{
		{id: uuid(tenantA, 901), kind: "agent", first: 1000, count: 120, findKind: "certificate", meta: func(int) string { return `{}` }},
		{id: uuid(tenantA, 902), kind: "ct_log", first: 5000, count: 3, findKind: "ct_unexpected_issuance", meta: func(int) string { return `{}` }},
		{id: uuid(tenantA, 903), kind: "drift", first: 6000, count: 3, findKind: "credential_drift", meta: func(i int) string {
			return []string{`{"type":"replaced","class":"certificate"}`, `{"type":"deleted","class":"ssh_key"}`, `{"type":"replaced","class":"certificate"}`}[i]
		}},
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		for n, src := range sources {
			if err := s.ApplyDiscoverySourceUpsertedTx(ctx, tx, store.DiscoverySource{
				ID: src.id, TenantID: tenantA, Kind: src.kind, Name: "a105-" + src.kind, Config: []byte(`{}`), CreatedAt: now, UpdatedAt: now,
			}); err != nil {
				return err
			}
			runID := uuid(tenantA, 950+n)
			if err := s.ApplyDiscoveryRunQueuedTx(ctx, tx, store.DiscoveryRun{ID: runID, TenantID: tenantA, SourceID: src.id, Status: "queued", CreatedAt: now}); err != nil {
				return err
			}
			for i := 0; i < src.count; i++ {
				id := uuid(tenantA, src.first+i)
				if err := s.ApplyDiscoveryFindingRecordedTx(ctx, tx, store.DiscoveryFinding{
					ID: id, TenantID: tenantA, RunID: runID, SourceID: src.id, Kind: src.findKind, Ref: "ref-" + id,
					Provenance: "a105", Fingerprint: "fp-" + id, RiskScore: 40, Metadata: []byte(src.meta(i)), DiscoveredAt: now,
				}); err != nil {
					return err
				}
			}
		}
		if err := s.ApplyDiscoveryFindingTriageChangedTx(ctx, tx, store.DiscoveryFindingTriageChange{
			TenantID: tenantA, FindingID: uuid(tenantA, 5002), Status: string(discovery.TriageDismissed),
			Actor: "alice@example.test", Reason: "expected issuance", ChangedAt: now,
		}); err != nil {
			return err
		}
		// A finding recorded before triage existed carries an empty status.
		_, err := tx.Exec(ctx, `UPDATE discovery_findings SET triage_status = '' WHERE tenant_id = $1 AND id = $2`, tenantA, uuid(tenantA, 5001))
		return err
	}); err != nil {
		t.Fatalf("seed findings: %v", err)
	}

	ct := store.DiscoveryFindingFilter{SourceKind: "ct_log"}
	first, err := s.ListDiscoveryFindingsFiltered(ctx, tenantA, ct, store.ZeroUUID, 2)
	if err != nil || len(first) != 2 || first[0].ID != uuid(tenantA, 5000) || first[1].ID != uuid(tenantA, 5001) {
		t.Fatalf("first CT page = %+v (%v)", first, err)
	}
	second, err := s.ListDiscoveryFindingsFiltered(ctx, tenantA, ct, first[1].ID, 2)
	if err != nil || len(second) != 1 || second[0].ID != uuid(tenantA, 5002) {
		t.Fatalf("second CT page = %+v (%v)", second, err)
	}
	open, err := s.ListDiscoveryFindingsFiltered(ctx, tenantA, store.DiscoveryFindingFilter{SourceKind: "ct_log", TriageStatus: "unmanaged"}, store.ZeroUUID, 100)
	if err != nil || len(open) != 2 {
		t.Fatalf("open CT findings = %d (%v); want the untriaged and the never-triaged one", len(open), err)
	}
	drift, err := s.ListDiscoveryFindingsFiltered(ctx, tenantA, store.DiscoveryFindingFilter{Kind: "credential_drift"}, store.ZeroUUID, 100)
	if err != nil || len(drift) != 3 {
		t.Fatalf("drift findings by kind = %d (%v)", len(drift), err)
	}

	tallies, err := s.TallyDiscoveryFindings(ctx, tenantA, ct, now)
	if err != nil {
		t.Fatal(err)
	}
	byTriage := map[string]int{}
	for _, tally := range tallies {
		if tally.Kind != "ct_unexpected_issuance" {
			t.Fatalf("CT tally counted another kind: %+v", tally)
		}
		byTriage[tally.TriageStatus] += tally.Count
	}
	if byTriage["unmanaged"] != 2 || byTriage["dismissed"] != 1 || len(byTriage) != 2 {
		t.Fatalf("CT tally by triage = %v", byTriage)
	}
	tallies, err = s.TallyDiscoveryFindings(ctx, tenantA, store.DiscoveryFindingFilter{SourceKind: "drift"}, now)
	if err != nil {
		t.Fatal(err)
	}
	groups := map[string]int{}
	for _, tally := range tallies {
		groups[tally.Type+"/"+tally.Class] += tally.Count
	}
	if groups["replaced/certificate"] != 2 || groups["deleted/ssh_key"] != 1 || len(groups) != 2 {
		t.Fatalf("drift tally by type/class = %v", groups)
	}

	if srcs, err := s.ListDiscoverySourcesOfKind(ctx, tenantA, "ct_log"); err != nil || len(srcs) != 1 || srcs[0].ID != sources[1].id {
		t.Fatalf("CT sources = %+v (%v)", srcs, err)
	}
	if rows, err := s.ListDiscoveryFindingsFiltered(ctx, tenantB, ct, store.ZeroUUID, 100); err != nil || len(rows) != 0 {
		t.Fatalf("tenant B read tenant A's CT findings: %d (%v)", len(rows), err)
	}
	if tallies, err := s.TallyDiscoveryFindings(ctx, tenantB, ct, now); err != nil || len(tallies) != 0 {
		t.Fatalf("tenant B counted tenant A's CT findings: %+v (%v)", tallies, err)
	}
}
