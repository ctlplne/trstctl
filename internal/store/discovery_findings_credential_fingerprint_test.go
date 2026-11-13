// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// A172-L1: a leaked secret names the stored credential it holds in
// metadata.credential_fingerprint (its own fingerprint is the scanner's
// location), and the fingerprint filter selects it beside every finding whose
// fingerprint is that credential's, paged by id, through a valid index.
func TestDiscoveryFindingFilterReachesALeakHoldingTheStoredCredentialA172L1(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	const stored = "a172l1-2222222222222222222222222222222222222222222222222222222222222222"
	source, run := uuid(tenantA, 1741), uuid(tenantA, 1742)
	findings := []struct {
		id, kind, fingerprint, metadata string
	}{
		{uuid(tenantA, 1751), "secret_store_api_key", stored, `{"rule":"gitlab_token"}`},
		{uuid(tenantA, 1752), "leaked_secret", "c0ffee:ci/deploy.env:gitlab-pat:2", `{"credential_fingerprint":"` + stored + `","credential_rule":"gitlab_token"}`},
		{uuid(tenantA, 1753), "leaked_secret", "c0ffee:app.env:gitlab-pat:1", `{"credential_fingerprint":"a172l1-other"}`},
		{uuid(tenantA, 1754), "leaked_secret", "c0ffee:notes.txt:generic-api-key:3", `{}`},
		{uuid(tenantA, 1755), "secret_store_api_key", stored, `{"rule":"gitlab_token","field":"token"}`},
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if err := s.ApplyDiscoverySourceUpsertedTx(ctx, tx, store.DiscoverySource{
			ID: source, TenantID: tenantA, Kind: "secret_repo", Name: "a172l1-" + source, Config: []byte(`{}`), CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			return err
		}
		if err := s.ApplyDiscoveryRunQueuedTx(ctx, tx, store.DiscoveryRun{ID: run, TenantID: tenantA, SourceID: source, Status: "queued", CreatedAt: now}); err != nil {
			return err
		}
		for _, f := range findings {
			if err := s.ApplyDiscoveryFindingRecordedTx(ctx, tx, store.DiscoveryFinding{
				ID: f.id, TenantID: tenantA, RunID: run, SourceID: source, Kind: f.kind, Ref: "ref-" + f.id,
				Provenance: "a172l1", Fingerprint: f.fingerprint, RiskScore: 60, Metadata: []byte(f.metadata), DiscoveredAt: now,
			}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed findings: %v", err)
	}
	page := func(after string, limit int) []string {
		t.Helper()
		rows, err := s.ListDiscoveryFindingsFiltered(ctx, tenantA, store.DiscoveryFindingFilter{Fingerprint: stored}, after, limit)
		if err != nil {
			t.Fatal(err)
		}
		ids := make([]string, 0, len(rows))
		for _, r := range rows {
			ids = append(ids, r.ID)
		}
		return ids
	}
	want := []string{findings[0].id, findings[1].id, findings[4].id}
	slices.Sort(want)
	if all := page(store.ZeroUUID, 100); !slices.Equal(all, want) {
		t.Fatalf("findings with the credential = %v; want the two stored copies and the leak holding it %v", all, want)
	}
	first := page(store.ZeroUUID, 2)
	if len(first) != 2 || !slices.Equal(append(first, page(first[1], 2)...), want) {
		t.Fatalf("pages = %v then %v; want the same three in id order", first, page(first[1], 2))
	}
	var ready bool
	if err := s.SystemPool().QueryRow(ctx, `SELECT indisvalid AND indisready FROM pg_index
		WHERE indexrelid = 'discovery_findings_credential_fingerprint_idx'::regclass`).Scan(&ready); err != nil || !ready {
		t.Fatalf("credential fingerprint index ready=%v err=%v", ready, err)
	}
}
