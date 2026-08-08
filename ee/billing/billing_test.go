// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/usage"
)

var billingT0 = time.Date(2026, 6, 27, 14, 23, 45, 0, time.UTC)

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestQuotaExhaustionBlocksCreationButDoesNotDropMetering(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	one := 1
	if err := store.SetQuota(ctx, Quota{TenantID: "tenant-a", MaxAgents: &one}); err != nil {
		t.Fatal(err)
	}
	rec := NewRecorder(store, discardLog()).WithClock(func() time.Time { return billingT0 })
	checker := NewQuotaChecker(store, func(context.Context, string) (TenantCounts, error) {
		return TenantCounts{usage.MeterAgents: 1}, nil
	}, time.Minute)

	usage.SetRecorder(rec)
	usage.SetQuotaChecker(checker)
	t.Cleanup(func() {
		usage.SetRecorder(nil)
		usage.SetQuotaChecker(nil)
	})

	err := usage.AllowCreate(ctx, "tenant-a", usage.MeterAgents)
	var quotaErr *QuotaError
	if !errors.As(err, &quotaErr) {
		t.Fatalf("quota denial = %v, want *QuotaError", err)
	}
	if quotaErr.Code != CodeQuotaExhausted || quotaErr.Resource != usage.MeterAgents || quotaErr.Current != 1 || quotaErr.Limit != 1 {
		t.Fatalf("quota error not structured enough: %+v", quotaErr)
	}

	usage.Record("tenant-a", usage.MeterCertificatesIssued, 2)
	if err := rec.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	recs, err := store.Query(ctx, billingT0.Add(-time.Hour), billingT0.Add(time.Hour), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Meter != usage.MeterCertificatesIssued || recs[0].Value != 2 {
		t.Fatalf("metering dropped after quota denial: %+v", recs)
	}
}

func TestRecorderIsLosslessAndSnapshotsStayTenantScoped(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	now := billingT0
	rec := NewRecorder(store, discardLog()).WithClock(func() time.Time { return now })

	rec.Record("tenant-a", usage.MeterCertificatesIssued, 4)
	store.FailNextAdd()
	if err := rec.Flush(ctx); err == nil {
		t.Fatal("forced flush failure must surface")
	}
	rec.Record("tenant-a", usage.MeterCertificatesIssued, 3)
	if err := rec.Flush(ctx); err != nil {
		t.Fatal(err)
	}

	seen := []string{}
	collector := NewCollector(store,
		func(context.Context) ([]string, error) { return []string{"tenant-a", "tenant-b"}, nil },
		func(_ context.Context, tenantID string) (TenantCounts, error) {
			seen = append(seen, tenantID)
			if tenantID == "tenant-a" {
				return TenantCounts{usage.MeterAgents: 2, usage.MeterSecretsStored: 5}, nil
			}
			return TenantCounts{usage.MeterAgents: 1, usage.MeterSecretsStored: 0}, nil
		}, discardLog()).WithClock(func() time.Time { return now })
	if err := collector.Snapshot(ctx); err != nil {
		t.Fatal(err)
	}

	recs, err := store.Query(ctx, billingT0.Add(-time.Hour), billingT0.Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int64{}
	for _, r := range recs {
		got[r.TenantID+"|"+r.Meter] = r.Value
	}
	if got["tenant-a|"+usage.MeterCertificatesIssued] != 7 {
		t.Fatalf("failed flush lost or doubled counter deltas: %+v", got)
	}
	if got["tenant-a|"+usage.MeterAgents] != 2 || got["tenant-b|"+usage.MeterAgents] != 1 {
		t.Fatalf("tenant-scoped agent gauges wrong: %+v", got)
	}
	if strings.Join(seen, ",") != "tenant-a,tenant-b" {
		t.Fatalf("collector did not count each tenant exactly once: %v", seen)
	}
}

func TestEvidenceCSVCarriesTheVerdictOnEveryRow(t *testing.T) {
	doc := EvidenceDocument{
		CustomerID: "tenant-a", PeriodStart: "2026-07-01T00:00:00Z", PeriodEnd: "2026-08-01T00:00:00Z",
		Signable: false,
		Reason:   "the period has a hole in it",
		Lines: []EvidenceLine{
			{Meter: usage.MeterCertificatesIssued, Kind: KindCounter, Value: 7},
			{Meter: usage.MeterAgents, Kind: KindGauge, Value: 3},
		},
		Reconciliation: []ReconciliationLine{
			{Meter: usage.MeterCertificatesIssued, Metered: 7, EventHistory: 7, Checked: true, Matches: true},
		},
		Digest: "abc123",
	}
	var buf bytes.Buffer
	if err := WriteEvidenceCSV(&buf, doc); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(strings.NewReader(buf.String())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want header + 2 lines: %q", len(rows), buf.String())
	}
	for i, row := range rows[1:] {
		if row[3] != "false" || row[4] != "the period has a hole in it" {
			t.Fatalf("row %d lost the verdict: %v.\n\nA CSV gets sliced in a spreadsheet and pasted "+
				"without its context; the verdict must survive on EVERY row or the first sort "+
				"detaches the warning from the numbers", i, row)
		}
		if row[10] != "abc123" {
			t.Fatalf("row %d lost the digest that ties it to the attested document: %v", i, row)
		}
	}
	if rows[1][8] != "true" || rows[1][9] != "7" {
		t.Fatalf("the reconciled line does not carry its cross-check: %v", rows[1])
	}
	if rows[2][8] != "" {
		t.Fatalf("an unreconciled meter claims a check that never ran: %v", rows[2])
	}

	// A period with no usage still exports its verdict.
	var empty bytes.Buffer
	if err := WriteEvidenceCSV(&empty, EvidenceDocument{
		CustomerID: "tenant-a", PeriodStart: "2026-07-01T00:00:00Z", PeriodEnd: "2026-08-01T00:00:00Z",
		Signable: true, Reason: "ok", Digest: "d"}); err != nil {
		t.Fatal(err)
	}
	emptyRows, err := csv.NewReader(strings.NewReader(empty.String())).ReadAll()
	if err != nil || len(emptyRows) != 2 {
		t.Fatalf("an empty period exported %d rows (%v); the verdict must arrive even when no "+
			"numbers do", len(emptyRows), err)
	}
}
