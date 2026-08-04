// SPDX-License-Identifier: MPL-2.0

package auditanchor_test

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/auditanchor"
	"trstctl.com/trstctl/internal/auditchain"
	"trstctl.com/trstctl/internal/eventspec"
)

// Audit export formats a SIEM can ingest (epic J1).
//
// The tests here are mostly about mappings, which sounds dull until you notice
// how they fail. A wrong timestamp format does not error — the collector accepts
// the event and stamps it with INGEST time, so the whole audit trail silently
// reads as having happened at the moment it was shipped. That is worse than a
// rejected payload, because nobody finds out.

func exportRecords(t *testing.T) ([]auditchain.Record, string) {
	t.Helper()
	at := time.Date(2026, 3, 1, 12, 0, 0, 500_000_000, time.UTC)
	recs := []auditchain.Record{
		{
			Sequence: 1, ID: "r1", Type: "identity.created", TenantID: "t1", Time: at,
			Actor: &eventspec.Actor{Subject: "alice@example.test", Roles: []string{"admin", "auditor"}},
			Data:  json.RawMessage(`{"identity":"api.example.test"}`),
		},
		{
			Sequence: 2, ID: "r2", Type: "certificate.issued", TenantID: "t1",
			Time: at.Add(time.Second),
		},
	}
	return recs, auditchain.Seal(recs)
}

// Splunk's HEC reads `time` as epoch SECONDS with a fractional part. RFC 3339
// there is accepted and silently replaced with ingest time.
func TestSplunkEventsCarryEpochSecondsNotRFC3339(t *testing.T) {
	t.Parallel()
	recs, head := exportRecords(t)
	var buf bytes.Buffer
	if err := auditanchor.WriteRecords(&buf, auditanchor.FormatSplunkHEC, recs, head, auditanchor.Anchor{}); err != nil {
		t.Fatalf("WriteRecords: %v", err)
	}
	lines := nonEmptyLines(buf.String())
	if len(lines) != len(recs)+1 {
		t.Fatalf("got %d lines, want %d records + 1 trailer", len(lines), len(recs))
	}

	var first struct {
		Time       float64 `json:"time"`
		SourceType string  `json:"sourcetype"`
		Event      struct {
			ID        string `json:"id"`
			ChainHash string `json:"chain_hash"`
		} `json:"event"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("first HEC event is not JSON: %v", err)
	}
	want := float64(time.Date(2026, 3, 1, 12, 0, 0, 500_000_000, time.UTC).UnixNano()) / float64(time.Second)
	if first.Time != want {
		t.Errorf("HEC time = %v, want %v epoch seconds; a wrong format is not rejected by the "+
			"collector — it stamps ingest time instead, so every audit record would read as "+
			"having happened when it was shipped", first.Time, want)
	}
	if first.SourceType != "trstctl:audit" {
		t.Errorf("sourcetype = %q", first.SourceType)
	}
	// The chain hash must survive into the SIEM, or an exported record stops
	// being evidence and becomes a log line.
	if first.Event.ChainHash == "" {
		t.Error("the HEC event carries no chain hash; a record lifted out of Splunk could not " +
			"be tied back to the chain that attests it")
	}
}

// Sentinel keys on TimeGenerated with PascalCase columns.
func TestSentinelRecordsUseTheTableShapeSentinelExpects(t *testing.T) {
	t.Parallel()
	recs, head := exportRecords(t)
	var buf bytes.Buffer
	if err := auditanchor.WriteRecords(&buf, auditanchor.FormatSentinel, recs, head, auditanchor.Anchor{}); err != nil {
		t.Fatal(err)
	}
	lines := nonEmptyLines(buf.String())
	var fields map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &fields); err != nil {
		t.Fatal(err)
	}
	for _, col := range []string{"TimeGenerated", "Sequence", "RecordId", "EventType", "TenantId", "ChainHash"} {
		if _, present := fields[col]; !present {
			t.Errorf("Sentinel record has no %q column; an analyst would have to rename columns "+
				"in every query", col)
		}
	}
	if ts, _ := fields["TimeGenerated"].(string); ts != "2026-03-01T12:00:00.5Z" {
		t.Errorf("TimeGenerated = %q, want RFC 3339", ts)
	}
}

// CSV parses as CSV, with a pinned header.
func TestCSVExportParsesAndPinsItsHeader(t *testing.T) {
	t.Parallel()
	recs, head := exportRecords(t)
	var buf bytes.Buffer
	if err := auditanchor.WriteRecords(&buf, auditanchor.FormatCSV, recs, head, auditanchor.Anchor{}); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("the CSV export does not parse as CSV: %v", err)
	}
	if len(rows) != len(recs)+1 {
		t.Fatalf("got %d rows, want %d records + header", len(rows), len(recs))
	}

	// The header is pinned. Reordering breaks every saved query built on a
	// previous export, and an audit export is exactly what people build saved
	// queries on.
	want := []string{"sequence", "id", "type", "tenant_id", "time",
		"actor_subject", "actor_roles", "chain_hash", "data"}
	if len(rows[0]) != len(want) {
		t.Fatalf("header = %v, want %v", rows[0], want)
	}
	for i := range want {
		if rows[0][i] != want[i] {
			t.Errorf("column %d = %q, want %q; CSV column order is a compatibility promise",
				i, rows[0][i], want[i])
		}
	}

	// Roles are carried, not dropped: "who" without "under what authorization"
	// is the half that does not answer a privilege review.
	if rows[1][6] != "admin auditor" {
		t.Errorf("actor_roles = %q, want the roles the subject acted under", rows[1][6])
	}
	// A record with no actor renders empty cells rather than breaking the shape.
	if rows[2][5] != "" || rows[2][6] != "" {
		t.Errorf("an actorless record produced %q/%q", rows[2][5], rows[2][6])
	}
}

// Every JSON stream format ends with the chain head and the anchor.
func TestJSONStreamsCarryTheChainHeadAndAnchor(t *testing.T) {
	t.Parallel()
	recs, head := exportRecords(t)
	for _, format := range []auditanchor.Format{
		auditanchor.FormatNDJSON, auditanchor.FormatSplunkHEC, auditanchor.FormatSentinel,
	} {
		format := format
		t.Run(string(format), func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			if err := auditanchor.WriteRecords(&buf, format, recs, head,
				auditanchor.Anchor{Kind: auditanchor.KindNone, Detail: "not anchored"}); err != nil {
				t.Fatal(err)
			}
			lines := nonEmptyLines(buf.String())
			var tr struct {
				Kind      string `json:"trstctl_record"`
				ChainHead string `json:"chain_head"`
				Count     int    `json:"count"`
				Anchor    struct {
					Kind   string `json:"kind"`
					Detail string `json:"detail"`
				} `json:"anchor"`
			}
			if err := json.Unmarshal([]byte(lines[len(lines)-1]), &tr); err != nil {
				t.Fatalf("trailer is not JSON: %v", err)
			}
			if tr.Kind != "chain_trailer" || tr.ChainHead != head || tr.Count != len(recs) {
				t.Errorf("trailer = %+v, want the chain head and record count", tr)
			}
			// An unanchored export must SAY it is unanchored inside the payload.
			// Metadata carried only in an HTTP header is lost the moment a log
			// pipeline forwards the body, which is the first thing it does.
			if tr.Anchor.Detail == "" {
				t.Error("the trailer does not explain the missing anchor")
			}
		})
	}
}

// An unknown format is refused rather than silently downgraded.
func TestAnUnknownFormatIsRefused(t *testing.T) {
	t.Parallel()
	if _, err := auditanchor.ParseFormat("splunk"); err == nil {
		t.Fatal("a near-miss format name was accepted; the caller would receive JWS and find " +
			"out when their ingest pipeline rejected it")
	}
	if f, err := auditanchor.ParseFormat(""); err != nil || f != auditanchor.FormatJWS {
		t.Errorf("empty format = (%q, %v), want the signed bundle by default", f, err)
	}
	for _, f := range auditanchor.Formats() {
		got, err := auditanchor.ParseFormat(string(f))
		if err != nil || got != f {
			t.Errorf("advertised format %q does not parse: (%q, %v); a format cannot be offered "+
				"and refused", f, got, err)
		}
	}
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}
