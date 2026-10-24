// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

func postureDashboardID(n int) string { return fmt.Sprintf("a1050000-0000-4000-8000-%012d", n) }

// A105: the CT-log and drift dashboards read their own source kind's findings
// a page at a time and count all of them on the server, and the findings list
// filters by source kind, kind and triage status. Before, both dashboards read
// the tenant's first 100 findings of any kind and filtered them in memory: a
// tenant whose other findings sort first saw neither its CT nor its drift
// findings, and every count described a sample.
func TestServedPostureDashboardsPageAndCountTheirOwnFindings(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx := t.Context()
	now := time.Now().UTC()
	seed := []struct {
		source, kind, findingKind string
		first, count              int
		meta                      []string
	}{
		{source: postureDashboardID(901), kind: "agent", findingKind: "certificate", first: 1000, count: 120},
		{source: postureDashboardID(902), kind: "ct_log", findingKind: "ct_unexpected_issuance", first: 5000, count: 3},
		{source: postureDashboardID(903), kind: "drift", findingKind: "credential_drift", first: 6000, count: 3, meta: []string{
			`{"type":"replaced","class":"certificate"}`, `{"type":"deleted","class":"ssh_key"}`, `{"type":"replaced","class":"certificate"}`}},
	}
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		for n, src := range seed {
			if err := h.store.ApplyDiscoverySourceUpsertedTx(ctx, tx, store.DiscoverySource{ID: src.source, TenantID: h.tenant,
				Kind: src.kind, Name: "a105-" + src.kind, Config: []byte(`{}`), CreatedAt: now, UpdatedAt: now}); err != nil {
				return err
			}
			runID := postureDashboardID(950 + n)
			if err := h.store.ApplyDiscoveryRunQueuedTx(ctx, tx, store.DiscoveryRun{ID: runID, TenantID: h.tenant, SourceID: src.source, Status: "queued", CreatedAt: now}); err != nil {
				return err
			}
			for i := 0; i < src.count; i++ {
				meta := `{}`
				if src.meta != nil {
					meta = src.meta[i]
				}
				id := postureDashboardID(src.first + i)
				if err := h.store.ApplyDiscoveryFindingRecordedTx(ctx, tx, store.DiscoveryFinding{ID: id, TenantID: h.tenant, RunID: runID,
					SourceID: src.source, Kind: src.findingKind, Ref: "ref-" + id, Provenance: "a105", Fingerprint: "fp-" + id,
					RiskScore: 40, Metadata: []byte(meta), DiscoveredAt: now}); err != nil {
					return err
				}
			}
		}
		return h.store.ApplyDiscoveryFindingTriageChangedTx(ctx, tx, store.DiscoveryFindingTriageChange{TenantID: h.tenant,
			FindingID: postureDashboardID(5002), Status: "dismissed", Actor: "alice@example.test", Reason: "expected issuance", ChangedAt: now})
	}); err != nil {
		t.Fatalf("seed findings: %v", err)
	}
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read")
	get := func(path string, out any) int {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, path, tok, nil)
		if status == http.StatusOK {
			if err := json.Unmarshal(body, out); err != nil {
				t.Fatalf("%s: %v %s", path, err, body)
			}
		}
		return status
	}

	type ctPage struct {
		Summary struct {
			FindingCount            int            `json:"finding_count"`
			UnexpectedIssuanceCount int            `json:"unexpected_issuance_count"`
			OpenFindingCount        int            `json:"open_finding_count"`
			DismissedCount          int            `json:"dismissed_count"`
			TriageCounts            map[string]int `json:"triage_counts"`
		} `json:"summary"`
		Findings []struct {
			ID string `json:"id"`
		} `json:"findings"`
		NextCursor string `json:"next_cursor"`
	}
	var first ctPage
	if status := get("/api/v1/discovery/ct-monitoring?limit=2", &first); status != http.StatusOK || len(first.Findings) != 2 ||
		first.Findings[0].ID != postureDashboardID(5000) || first.NextCursor == "" || first.Summary.FindingCount != 3 ||
		first.Summary.UnexpectedIssuanceCount != 3 || first.Summary.OpenFindingCount != 2 || first.Summary.DismissedCount != 1 ||
		first.Summary.TriageCounts["unmanaged"] != 2 || first.Summary.TriageCounts["dismissed"] != 1 || len(first.Summary.TriageCounts) != 2 {
		t.Fatalf("CT dashboard first page = %d %+v", status, first)
	}
	var second ctPage
	if status := get("/api/v1/discovery/ct-monitoring?limit=2&cursor="+url.QueryEscape(first.NextCursor), &second); status != http.StatusOK ||
		len(second.Findings) != 1 || second.Findings[0].ID != postureDashboardID(5002) || second.NextCursor != "" {
		t.Fatalf("CT dashboard second page = %d %+v", status, second)
	}
	var dismissed ctPage
	if status := get("/api/v1/discovery/ct-monitoring?triage_status=dismissed", &dismissed); status != http.StatusOK ||
		len(dismissed.Findings) != 1 || dismissed.Summary.FindingCount != 3 {
		t.Fatalf("CT dashboard dismissed filter = %d %+v", status, dismissed)
	}
	if status := get("/api/v1/discovery/ct-monitoring?triage_status=closed", &dismissed); status != http.StatusBadRequest {
		t.Fatalf("CT dashboard unknown triage filter = %d", status)
	}

	var drift struct {
		Summary struct {
			FindingCount     int `json:"finding_count"`
			OpenFindingCount int `json:"open_finding_count"`
			ReplacedCount    int `json:"replaced_count"`
			DeletedCount     int `json:"deleted_count"`
			CertificateCount int `json:"certificate_count"`
			SSHKeyCount      int `json:"ssh_key_count"`
		} `json:"summary"`
		Findings []struct {
			FindingID string `json:"finding_id"`
			DriftType string `json:"drift_type"`
		} `json:"findings"`
	}
	if status := get("/api/v1/discovery/drift-remediation", &drift); status != http.StatusOK || len(drift.Findings) != 3 ||
		drift.Summary.FindingCount != 3 || drift.Summary.OpenFindingCount != 3 || drift.Summary.ReplacedCount != 2 ||
		drift.Summary.DeletedCount != 1 || drift.Summary.CertificateCount != 2 || drift.Summary.SSHKeyCount != 1 {
		t.Fatalf("drift dashboard = %d %+v", status, drift)
	}

	var list struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	for _, c := range []struct {
		query string
		want  int
	}{
		{"source_kind=ct_log&limit=100", 3},
		{"kind=credential_drift&limit=100", 3},
		{"source_kind=ct_log&triage_status=dismissed", 1},
		{"source_kind=agent&limit=100", 100},
	} {
		if status := get("/api/v1/discovery/findings?"+c.query, &list); status != http.StatusOK || len(list.Items) != c.want {
			t.Fatalf("findings?%s = %d with %d items, want %d", c.query, status, len(list.Items), c.want)
		}
	}
	if status := get("/api/v1/discovery/findings?source_kind=CT%20LOG", &list); status != http.StatusBadRequest {
		t.Fatalf("findings with a malformed source_kind = %d", status)
	}
}
