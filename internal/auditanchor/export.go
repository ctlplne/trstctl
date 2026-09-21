// SPDX-License-Identifier: BUSL-1.1

package auditanchor

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/auditchain"
	"trstctl.com/trstctl/internal/eventspec"
)

// Audit export in formats a SIEM can actually ingest (epic J1).
//
// The only export was a compact JWS: excellent evidence, and unreadable by every
// log pipeline an enterprise already runs. An auditor could verify it and a
// SOC could not search it, so in practice the audit trail was exported once for
// an audit and never fed to the tooling that would notice something at the time.
//
// CSV and NDJSON fix that, and the interesting design question is what happens
// to the chain hash. It travels in both formats, per record. That is the point:
// a row lifted out of a SIEM months later still carries the hash that binds it
// to its neighbors, so an investigator who exported to Splunk has not thereby
// downgraded their evidence to "some log lines".

// Format is a served audit export encoding.
type Format string

const (
	// FormatJWS is the signed evidence bundle. Still the default, because it is
	// the only format that is itself verifiable.
	FormatJWS Format = "jws"
	// FormatNDJSON is one JSON object per line — what every log shipper reads.
	FormatNDJSON Format = "ndjson"
	// FormatCSV is for spreadsheets and the auditors who live in them.
	FormatCSV Format = "csv"
	// FormatSplunkHEC is NDJSON wrapped in Splunk's HTTP Event Collector
	// envelope, so it can be POSTed to a collector without a translation step.
	FormatSplunkHEC Format = "splunk-hec"
	// FormatSentinel is the Azure Monitor / Sentinel table shape.
	FormatSentinel Format = "sentinel"
)

// Formats lists every served format, for the console's picker and for the
// handler's validation — one list, so a format cannot be offered and refused.
func Formats() []Format {
	return []Format{FormatJWS, FormatNDJSON, FormatCSV, FormatSplunkHEC, FormatSentinel}
}

// ParseFormat resolves a requested format name.
//
// An unknown name is an error rather than a silent fall back to the default. A
// caller who asked for "splunk" and received JWS would discover it when their
// ingest pipeline rejected the payload, which is a worse place to find out.
func ParseFormat(raw string) (Format, error) {
	if strings.TrimSpace(raw) == "" {
		return FormatJWS, nil
	}
	want := Format(strings.ToLower(strings.TrimSpace(raw)))
	for _, f := range Formats() {
		if f == want {
			return f, nil
		}
	}
	names := make([]string, 0, len(Formats()))
	for _, f := range Formats() {
		names = append(names, string(f))
	}
	return "", fmt.Errorf("unknown audit export format %q; supported formats are %s",
		raw, strings.Join(names, ", "))
}

// ContentType is the MIME type a format should be served as.
func (f Format) ContentType() string {
	switch f {
	case FormatCSV:
		return "text/csv; charset=utf-8"
	case FormatNDJSON, FormatSplunkHEC, FormatSentinel:
		return "application/x-ndjson"
	default:
		return "application/json"
	}
}

// csvColumns is the CSV header, fixed and ordered.
//
// Fixed because a CSV whose columns move between exports breaks every saved
// query built on it, and an audit export is precisely the thing people build
// saved queries on. Adding a column at the END is compatible; reordering is not,
// and a guard test pins this.
var csvColumns = []string{
	"sequence", "id", "type", "tenant_id", "time",
	"actor_subject", "actor_roles", "chain_hash", "data",
	"trstctl_record", "integrity",
}

// WriteRecords renders records in the requested format.
//
// The chain head travels with every non-JWS format too — as a trailing metadata
// line for the JSON formats and as the final RFC 4180-safe row for CSV. A format
// that dropped it would turn evidence into logging.
func WriteRecords(w io.Writer, format Format, recs []auditchain.Record, prevHash, head string, anchor Anchor) error {
	switch format {
	case FormatCSV:
		return writeCSV(w, recs, prevHash, head, anchor)
	case FormatNDJSON:
		return writeNDJSON(w, recs, prevHash, head, anchor)
	case FormatSplunkHEC:
		return writeSplunkHEC(w, recs, prevHash, head, anchor)
	case FormatSentinel:
		return writeSentinel(w, recs, prevHash, head, anchor)
	default:
		return fmt.Errorf("auditanchor: %q is not a record-stream format", format)
	}
}

// actorFields flattens the actor into two scalar columns.
//
// Roles are joined rather than dropped, because "who did this" and "under what
// authorization" are different questions and an audit export that answers only
// the first is missing the half that matters in a privilege review.
func actorFields(r auditchain.Record) (subject, roles string) {
	if r.Actor == nil {
		return "", ""
	}
	return r.Actor.Subject, strings.Join(r.Actor.Roles, " ")
}

func writeCSV(w io.Writer, recs []auditchain.Record, prevHash, head string, anchor Anchor) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(csvColumns); err != nil {
		return err
	}
	for _, r := range recs {
		subject, roles := actorFields(r)
		// The data blob is emitted as compact JSON in one cell. Flattening it
		// into columns would make the header depend on which events happened to
		// be in range, and a CSV whose shape varies per export is not a format.
		data := ""
		if len(r.Data) > 0 {
			data = string(compactJSON(r.Data))
		}
		if err := cw.Write([]string{
			strconv.FormatUint(r.Sequence, 10), r.ID, r.Type, r.TenantID,
			r.Time.UTC().Format(time.RFC3339Nano),
			subject, roles, r.Hash, data, "", "",
		}); err != nil {
			return err
		}
	}
	proof, err := json.Marshal(trailer{
		Kind: "chain_trailer", PrevHash: prevHash, ChainHead: head, Count: len(recs), Anchor: anchor,
	})
	if err != nil {
		return err
	}
	trailerRow := make([]string, len(csvColumns))
	trailerRow[len(trailerRow)-2] = "chain_trailer"
	trailerRow[len(trailerRow)-1] = string(proof)
	if err := cw.Write(trailerRow); err != nil {
		return err
	}
	cw.Flush()
	return cw.Error()
}

// ndjsonRecord is the per-line shape shared by the JSON stream formats.
type ndjsonRecord struct {
	Sequence     uint64          `json:"sequence"`
	ID           string          `json:"id"`
	Type         string          `json:"type"`
	TenantID     string          `json:"tenant_id"`
	Time         string          `json:"time"`
	ActorSubject string          `json:"actor_subject,omitempty"`
	ActorRoles   []string        `json:"actor_roles,omitempty"`
	ChainHash    string          `json:"chain_hash,omitempty"`
	Data         json.RawMessage `json:"data,omitempty"`
}

func toNDJSON(r auditchain.Record) ndjsonRecord {
	out := ndjsonRecord{
		Sequence: r.Sequence, ID: r.ID, Type: r.Type, TenantID: r.TenantID,
		Time:      r.Time.UTC().Format(time.RFC3339Nano),
		ChainHash: r.Hash, Data: r.Data,
	}
	if r.Actor != nil {
		out.ActorSubject = r.Actor.Subject
		out.ActorRoles = r.Actor.Roles
	}
	return out
}

// trailer is the final line of every JSON stream format.
//
// It carries the chain head and the anchor, so a stream ingested into a SIEM
// still contains everything needed to challenge it later. An export whose
// integrity metadata lived only in an HTTP header would lose it the moment the
// payload was forwarded, which is the first thing a log pipeline does.
type trailer struct {
	Kind      string `json:"trstctl_record"`
	PrevHash  string `json:"prev_hash"`
	ChainHead string `json:"chain_head"`
	Count     int    `json:"count"`
	Anchor    Anchor `json:"anchor"`
}

func writeTrailer(enc *json.Encoder, recs []auditchain.Record, prevHash, head string, anchor Anchor) error {
	return enc.Encode(trailer{
		Kind: "chain_trailer", PrevHash: prevHash, ChainHead: head, Count: len(recs), Anchor: anchor,
	})
}

func writeNDJSON(w io.Writer, recs []auditchain.Record, prevHash, head string, anchor Anchor) error {
	enc := json.NewEncoder(w)
	for _, r := range recs {
		if err := enc.Encode(toNDJSON(r)); err != nil {
			return err
		}
	}
	return writeTrailer(enc, recs, prevHash, head, anchor)
}

// splunkEvent is one HTTP Event Collector event.
//
// Splunk's collector requires `event` plus optional metadata at the envelope
// level, and it reads `time` as epoch SECONDS with a fractional part — not
// RFC 3339. Getting that wrong does not fail loudly; the collector accepts the
// event and stamps it with ingest time, so every audit record silently reads as
// having happened at the moment it was shipped. For an audit trail that is the
// worst possible failure, so the conversion is explicit here and pinned by test.
type splunkEvent struct {
	Time       float64      `json:"time"`
	Host       string       `json:"host,omitempty"`
	Source     string       `json:"source"`
	SourceType string       `json:"sourcetype"`
	Index      string       `json:"index,omitempty"`
	Event      ndjsonRecord `json:"event"`
}

func writeSplunkHEC(w io.Writer, recs []auditchain.Record, prevHash, head string, anchor Anchor) error {
	enc := json.NewEncoder(w)
	for _, r := range recs {
		if err := enc.Encode(splunkEvent{
			Time:       float64(r.Time.UTC().UnixNano()) / float64(time.Second),
			Source:     "trstctl",
			SourceType: "trstctl:audit",
			Event:      toNDJSON(r),
		}); err != nil {
			return err
		}
	}
	return writeTrailer(enc, recs, prevHash, head, anchor)
}

// sentinelRecord is the Azure Monitor / Sentinel custom-table shape.
//
// Sentinel keys on TimeGenerated and expects PascalCase column names; a payload
// using snake_case lands as untyped columns an analyst then has to rename in
// every query. The mapping is mechanical but has to be somewhere, and here it is
// pinned by a test rather than living in a customer's runbook.
type sentinelRecord struct {
	TimeGenerated string          `json:"TimeGenerated"`
	Sequence      uint64          `json:"Sequence"`
	RecordId      string          `json:"RecordId"`
	EventType     string          `json:"EventType"`
	TenantId      string          `json:"TenantId"`
	ActorSubject  string          `json:"ActorSubject,omitempty"`
	ActorRoles    string          `json:"ActorRoles,omitempty"`
	ChainHash     string          `json:"ChainHash,omitempty"`
	Data          json.RawMessage `json:"Data,omitempty"`
}

func writeSentinel(w io.Writer, recs []auditchain.Record, prevHash, head string, anchor Anchor) error {
	enc := json.NewEncoder(w)
	for _, r := range recs {
		subject, roles := actorFields(r)
		if err := enc.Encode(sentinelRecord{
			TimeGenerated: r.Time.UTC().Format(time.RFC3339Nano),
			Sequence:      r.Sequence, RecordId: r.ID, EventType: r.Type, TenantId: r.TenantID,
			ActorSubject: subject, ActorRoles: roles, ChainHash: r.Hash, Data: r.Data,
		}); err != nil {
			return err
		}
	}
	return writeTrailer(enc, recs, prevHash, head, anchor)
}

func compactJSON(raw json.RawMessage) []byte {
	var out bytes.Buffer
	if err := json.Compact(&out, raw); err != nil {
		return raw
	}
	return out.Bytes()
}

// VerifyCSVArtifact parses and verifies a saved CSV without relying on HTTP
// headers. The final RFC-safe row carries the exact same anchor as the JSON
// stream trailer; the preceding rows reconstruct the hash-covered records.
func VerifyCSVArtifact(raw []byte, tsaRootDER []byte, tolerance time.Duration) ([]auditchain.Record, error) {
	reader := csv.NewReader(bytes.NewReader(raw))
	rows, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("auditanchor: parse CSV: %w", err)
	}
	if len(rows) < 2 {
		return nil, errors.New("auditanchor: CSV is missing its integrity trailer")
	}
	if len(rows)-2 > maxArtifactRecords {
		return nil, fmt.Errorf("auditanchor: CSV exceeds the %d-record limit", maxArtifactRecords)
	}
	if len(rows[0]) != len(csvColumns) {
		return nil, errors.New("auditanchor: CSV header has an unsupported shape")
	}
	for i := range csvColumns {
		if rows[0][i] != csvColumns[i] {
			return nil, fmt.Errorf("auditanchor: CSV header column %d is %q, want %q", i, rows[0][i], csvColumns[i])
		}
	}
	last := rows[len(rows)-1]
	if last[len(last)-2] != "chain_trailer" || strings.TrimSpace(last[len(last)-1]) == "" {
		return nil, errors.New("auditanchor: CSV final row is not an integrity trailer; the file may be truncated")
	}
	for _, field := range last[:len(last)-2] {
		if field != "" {
			return nil, errors.New("auditanchor: CSV integrity trailer contains ambiguous record fields")
		}
	}
	var proof trailer
	if err := decodeExactJSON([]byte(last[len(last)-1]), &proof); err != nil {
		return nil, fmt.Errorf("auditanchor: decode CSV integrity trailer: %w", err)
	}
	if proof.Kind != "chain_trailer" || proof.Count != len(rows)-2 || proof.ChainHead == "" {
		return nil, errors.New("auditanchor: CSV integrity trailer count or chain head does not match the file")
	}
	records := make([]auditchain.Record, 0, len(rows)-2)
	for rowIndex, row := range rows[1 : len(rows)-1] {
		if row[len(row)-2] != "" || row[len(row)-1] != "" {
			return nil, fmt.Errorf("auditanchor: CSV record row %d contains integrity metadata", rowIndex+1)
		}
		sequence, err := strconv.ParseUint(row[0], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("auditanchor: CSV record row %d has invalid sequence: %w", rowIndex+1, err)
		}
		at, err := time.Parse(time.RFC3339Nano, row[4])
		if err != nil {
			return nil, fmt.Errorf("auditanchor: CSV record row %d has invalid time: %w", rowIndex+1, err)
		}
		record := auditchain.Record{
			Sequence: sequence, ID: row[1], Type: row[2], TenantID: row[3], Time: at.UTC(),
			Hash: row[7],
		}
		if row[5] != "" || row[6] != "" {
			record.Actor = &eventspec.Actor{Subject: row[5], Roles: strings.Fields(row[6])}
		}
		if row[8] != "" {
			if !json.Valid([]byte(row[8])) {
				return nil, fmt.Errorf("auditanchor: CSV record row %d has invalid JSON data", rowIndex+1)
			}
			record.Data = json.RawMessage(row[8])
		}
		records = append(records, record)
	}
	recomputed := append([]auditchain.Record(nil), records...)
	recomputedHead := auditchain.SealFrom(proof.PrevHash, recomputed)
	for i := range records {
		if recomputed[i].Hash != records[i].Hash {
			return nil, fmt.Errorf("auditanchor: CSV record chain is broken at row %d", i+1)
		}
	}
	if recomputedHead != proof.ChainHead || proof.Anchor.ChainHead != proof.ChainHead {
		return nil, errors.New("auditanchor: CSV records, trailer, and anchor name different chain heads")
	}
	if err := Verify(proof.Anchor, recomputedHead, tsaRootDER); err != nil {
		return nil, err
	}
	newest := time.Time{}
	for _, record := range records {
		if record.Time.After(newest) {
			newest = record.Time
		}
	}
	if err := VerifyNotBackdated(proof.Anchor, newest, tolerance); err != nil {
		return nil, err
	}
	return records, nil
}

// CSVColumns exposes the pinned header for the guard test and the console.
func CSVColumns() []string {
	// A copy, so a caller cannot reorder the pinned header in place.
	return append([]string(nil), csvColumns...)
}
