// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
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

func TestExportRoundTripsDeterministically(t *testing.T) {
	records := []UsageRecord{
		{TenantID: "tenant-a", TenantSlug: "acme", Meter: usage.MeterCertificatesIssued, Kind: KindCounter, PeriodStart: billingT0.Truncate(time.Hour), PeriodEnd: billingT0.Truncate(time.Hour).Add(time.Hour), Value: 7, Unit: "count"},
		{TenantID: "tenant-b", TenantSlug: "globex", Meter: usage.MeterAgents, Kind: KindGauge, PeriodStart: billingT0.Truncate(time.Hour), PeriodEnd: billingT0.Truncate(time.Hour).Add(time.Hour), Value: 3, Unit: "count"},
	}

	var csvBuf bytes.Buffer
	if err := WriteCSV(&csvBuf, records); err != nil {
		t.Fatal(err)
	}
	wantCSV := strings.Join([]string{
		"tenant_id,tenant_slug,meter,kind,period_start,period_end,value,unit",
		"tenant-a,acme,certificates_issued,counter,2026-06-27T14:00:00Z,2026-06-27T15:00:00Z,7,count",
		"tenant-b,globex,agents,gauge,2026-06-27T14:00:00Z,2026-06-27T15:00:00Z,3,count",
		"",
	}, "\n")
	if csvBuf.String() != wantCSV {
		t.Fatalf("CSV export drifted:\n got %q\nwant %q", csvBuf.String(), wantCSV)
	}
	parsed, err := csv.NewReader(strings.NewReader(csvBuf.String())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed) != 3 || parsed[1][0] != "tenant-a" || parsed[2][2] != usage.MeterAgents {
		t.Fatalf("CSV did not round-trip: %+v", parsed)
	}

	var jsonl bytes.Buffer
	if err := WriteJSONL(&jsonl, records); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(jsonl.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("jsonl line count = %d; body=%q", len(lines), jsonl.String())
	}
	var second UsageRecord
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatal(err)
	}
	if second.TenantID != "tenant-b" || second.Meter != usage.MeterAgents || second.Value != 3 {
		t.Fatalf("JSONL did not round-trip: %+v", second)
	}
}
