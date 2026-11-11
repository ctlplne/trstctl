// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

// A172-L2: the findings list filters by fingerprint. Every finding that names
// one certificate or key comes back, whatever its kind, source or run, and
// nothing else; a fingerprint written as colon-separated hex (as certificate
// viewers show it) matches the lowercase hex findings record; an overlong
// value is refused. Before, an operator could only page every finding and
// look.
func TestServedDiscoveryFindingsFilterByFingerprintA172L2(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx := t.Context()
	reader := seedScopedToken(t, h.store, h.tenant, "discovery:read")
	const fp = "a172a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e"
	now := time.Now().UTC()
	type seed struct{ source, run, finding, kind, fingerprint string }
	seeds := []seed{
		{"22222222-2222-2222-2222-2222222a1721", "22222222-2222-2222-2222-2222222a1731", "22222222-2222-2222-2222-2222222a1741", "certificate", fp},
		{"22222222-2222-2222-2222-2222222a1722", "22222222-2222-2222-2222-2222222a1732", "22222222-2222-2222-2222-2222222a1742", "private_key", fp},
		{"22222222-2222-2222-2222-2222222a1722", "22222222-2222-2222-2222-2222222a1732", "22222222-2222-2222-2222-2222222a1743", "certificate", "a172-not-this-one"},
	}
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		for _, sd := range seeds {
			if err := h.store.ApplyDiscoverySourceUpsertedTx(ctx, tx, store.DiscoverySource{
				ID: sd.source, TenantID: h.tenant, Kind: "network", Name: "a172l2-" + sd.source[len(sd.source)-4:], Config: []byte(`{}`), CreatedAt: now, UpdatedAt: now,
			}); err != nil {
				return err
			}
			if err := h.store.ApplyDiscoveryRunQueuedTx(ctx, tx, store.DiscoveryRun{ID: sd.run, TenantID: h.tenant, SourceID: sd.source, Status: "queued", CreatedAt: now}); err != nil {
				return err
			}
			if err := h.store.ApplyDiscoveryFindingRecordedTx(ctx, tx, store.DiscoveryFinding{
				ID: sd.finding, TenantID: h.tenant, RunID: sd.run, SourceID: sd.source, Kind: sd.kind, Ref: "a172l2:" + sd.finding,
				Provenance: "a172l2", Fingerprint: sd.fingerprint, RiskScore: 30, Metadata: []byte(`{}`), DiscoveredAt: now,
			}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed findings: %v", err)
	}
	list := func(fingerprint string) (int, []string) {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?limit=100&fingerprint="+url.QueryEscape(fingerprint), reader, nil)
		if status != http.StatusOK {
			return status, nil
		}
		var page struct {
			Items []struct {
				ID          string `json:"id"`
				Fingerprint string `json:"fingerprint"`
			} `json:"items"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			t.Fatal(err)
		}
		ids := []string{}
		for _, item := range page.Items {
			if item.Fingerprint != fp {
				t.Fatalf("finding %s with fingerprint %q came back for %q", item.ID, item.Fingerprint, fingerprint)
			}
			ids = append(ids, item.ID)
		}
		slices.Sort(ids)
		return status, ids
	}
	want := []string{seeds[0].finding, seeds[1].finding}
	if status, ids := list(fp); status != http.StatusOK || !slices.Equal(ids, want) {
		t.Fatalf("filter by %s = %d %v; want %v", fp, status, ids, want)
	}
	pairs := make([]string, 0, len(fp)/2)
	for i := 0; i < len(fp); i += 2 {
		pairs = append(pairs, strings.ToUpper(fp[i:i+2]))
	}
	if status, ids := list(strings.Join(pairs, ":")); status != http.StatusOK || !slices.Equal(ids, want) {
		t.Fatalf("filter by the colon-separated form = %d %v; want %v", status, ids, want)
	}
	if status, _ := list(strings.Repeat("a", 257)); status != http.StatusBadRequest {
		t.Fatalf("an overlong fingerprint = %d; want 400", status)
	}
}
