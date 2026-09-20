// SPDX-License-Identifier: BUSL-1.1

package auditanchor

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/auditchain"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/eventspec"
)

const (
	// FormatAuto asks the offline verifier to identify one served export shape.
	// It is not itself an export format and therefore is deliberately absent
	// from Formats().
	FormatAuto Format = "auto"

	// MaxArtifactBytes is the hard library boundary for one untrusted saved
	// export. The served query is far smaller; the extra headroom accommodates
	// verbose event data without letting a local file drive unbounded memory.
	MaxArtifactBytes   = 16 << 20
	maxArtifactRecords = 10_000
)

// VerificationOptions are externally pinned trust and policy inputs. Neither
// the audit signing key nor the TSA root may be learned only from the artifact
// being checked: an attacker could replace both an artifact and its authority.
type VerificationOptions struct {
	Format         Format
	AuditKeys      *jose.JWKSet
	TSARootDER     []byte
	MaxAnchorDelay time.Duration
}

// VerificationResult is the stable, non-secret receipt printed by the offline
// CLI. It states exactly what was checked, not merely that parsing succeeded.
type VerificationResult struct {
	Format         Format    `json:"format"`
	TenantID       string    `json:"tenant_id,omitempty"`
	RecordCount    int       `json:"record_count"`
	PrevHash       string    `json:"prev_hash,omitempty"`
	ChainHead      string    `json:"chain_head"`
	AnchorKind     Kind      `json:"anchor_kind"`
	AnchoredAt     time.Time `json:"anchored_at"`
	NewestRecordAt time.Time `json:"newest_record_at,omitempty"`
}

// VerifyArtifact verifies any saved format served by /api/v1/audit/export.
// The function performs strict shape checks before chain and authority checks;
// a well-signed trailer cannot make an ambiguous or lossy parser result valid.
func VerifyArtifact(raw []byte, opts VerificationOptions) (VerificationResult, error) {
	if len(raw) == 0 {
		return VerificationResult{}, errors.New("auditanchor: artifact is empty")
	}
	if len(raw) > MaxArtifactBytes {
		return VerificationResult{}, fmt.Errorf("auditanchor: artifact is %d bytes, exceeds the %d-byte limit", len(raw), MaxArtifactBytes)
	}
	format := opts.Format
	if format == "" {
		format = FormatAuto
	}
	if format == FormatAuto {
		var err error
		format, err = detectArtifactFormat(raw)
		if err != nil {
			return VerificationResult{}, err
		}
	}
	if _, err := ParseFormat(string(format)); err != nil {
		return VerificationResult{}, err
	}
	if len(opts.TSARootDER) == 0 {
		return VerificationResult{}, errors.New("auditanchor: a separately pinned TSA root certificate is required")
	}

	switch format {
	case FormatJWS:
		return verifyJWSEvidence(raw, opts)
	case FormatCSV:
		records, err := VerifyCSVArtifact(raw, opts.TSARootDER, opts.MaxAnchorDelay)
		if err != nil {
			return VerificationResult{}, err
		}
		proof, err := csvTrailer(raw)
		if err != nil {
			return VerificationResult{}, err
		}
		if _, err := validateRecordTenancy(records); err != nil {
			return VerificationResult{}, err
		}
		return resultFor(format, records, proof), nil
	case FormatNDJSON, FormatSplunkHEC, FormatSentinel:
		records, proof, err := decodeRecordStream(raw, format)
		if err != nil {
			return VerificationResult{}, err
		}
		if err := verifyRecordStream(records, proof, opts.TSARootDER, opts.MaxAnchorDelay); err != nil {
			return VerificationResult{}, err
		}
		return resultFor(format, records, proof), nil
	default:
		return VerificationResult{}, fmt.Errorf("auditanchor: unsupported verification format %q", format)
	}
}

func verifyJWSEvidence(raw []byte, opts VerificationOptions) (VerificationResult, error) {
	if opts.AuditKeys == nil {
		return VerificationResult{}, errors.New("auditanchor: JWS verification requires a separately pinned audit JWK set")
	}
	bundle, err := VerifyEvidenceEnvelope(raw, opts.AuditKeys, opts.TSARootDER, opts.MaxAnchorDelay)
	if err != nil {
		return VerificationResult{}, err
	}
	if bundle.Count != len(bundle.Records) || bundle.TenantID == "" || bundle.Query.TenantID != bundle.TenantID {
		return VerificationResult{}, errors.New("auditanchor: signed bundle count or tenant scope does not match its records")
	}
	for _, record := range bundle.Records {
		if record.TenantID != bundle.TenantID {
			return VerificationResult{}, errors.New("auditanchor: signed bundle contains a record from a different tenant")
		}
	}
	var envelope EvidenceEnvelope
	if err := decodeExactJSON(raw, &envelope); err != nil {
		return VerificationResult{}, fmt.Errorf("auditanchor: decode evidence envelope: %w", err)
	}
	return VerificationResult{
		Format: FormatJWS, TenantID: bundle.TenantID, RecordCount: len(bundle.Records),
		PrevHash: bundle.PrevHash, ChainHead: bundle.ChainHead, AnchorKind: envelope.Anchor.Kind,
		AnchoredAt: envelope.Anchor.AnchoredAt.UTC(), NewestRecordAt: newestRecordTime(bundle.Records),
	}, nil
}

func detectArtifactFormat(raw []byte) (Format, error) {
	trimmed := bytes.TrimSpace(raw)
	if bytes.HasPrefix(trimmed, []byte(strings.Join(csvColumns, ","))) {
		return FormatCSV, nil
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	var first json.RawMessage
	if err := dec.Decode(&first); err != nil {
		return "", fmt.Errorf("auditanchor: artifact is neither the pinned CSV nor a JSON export: %w", err)
	}
	if err := rejectDuplicateJSONKeys(first); err != nil {
		return "", fmt.Errorf("auditanchor: inspect first JSON value: %w", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(first, &fields); err != nil {
		return "", fmt.Errorf("auditanchor: first JSON value is not an object: %w", err)
	}
	switch {
	case fields["schema_version"] != nil && fields["bundle"] != nil:
		return FormatJWS, nil
	case fields["event"] != nil:
		return FormatSplunkHEC, nil
	case fields["TimeGenerated"] != nil:
		return FormatSentinel, nil
	case fields["sequence"] != nil:
		return FormatNDJSON, nil
	case fields["trstctl_record"] != nil:
		return "", errors.New("auditanchor: an empty JSON stream is format-ambiguous; specify ndjson, splunk-hec, or sentinel")
	default:
		return "", errors.New("auditanchor: could not identify a served audit export format")
	}
}

func decodeRecordStream(raw []byte, format Format) ([]auditchain.Record, trailer, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	records := make([]auditchain.Record, 0)
	for {
		var value json.RawMessage
		err := dec.Decode(&value)
		if errors.Is(err, io.EOF) {
			return nil, trailer{}, errors.New("auditanchor: JSON stream is missing its integrity trailer")
		}
		if err != nil {
			return nil, trailer{}, fmt.Errorf("auditanchor: decode JSON stream value %d: %w", len(records)+1, err)
		}
		if err := rejectDuplicateJSONKeys(value); err != nil {
			return nil, trailer{}, fmt.Errorf("auditanchor: JSON stream value %d: %w", len(records)+1, err)
		}
		var marker struct {
			Kind string `json:"trstctl_record"`
		}
		if err := json.Unmarshal(value, &marker); err != nil {
			return nil, trailer{}, fmt.Errorf("auditanchor: inspect JSON stream value %d: %w", len(records)+1, err)
		}
		if marker.Kind != "" {
			var proof trailer
			if err := decodeExactJSON(value, &proof); err != nil {
				return nil, trailer{}, fmt.Errorf("auditanchor: decode JSON integrity trailer: %w", err)
			}
			if proof.Kind != "chain_trailer" {
				return nil, trailer{}, fmt.Errorf("auditanchor: unrecognized JSON stream metadata %q", proof.Kind)
			}
			var extra json.RawMessage
			if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
				if err == nil {
					return nil, trailer{}, errors.New("auditanchor: JSON stream contains values after its integrity trailer")
				}
				return nil, trailer{}, fmt.Errorf("auditanchor: decode data after JSON integrity trailer: %w", err)
			}
			return records, proof, nil
		}
		if len(records) >= maxArtifactRecords {
			return nil, trailer{}, fmt.Errorf("auditanchor: JSON stream exceeds the %d-record limit", maxArtifactRecords)
		}
		record, err := decodeStreamRecord(value, format)
		if err != nil {
			return nil, trailer{}, fmt.Errorf("auditanchor: decode %s record %d: %w", format, len(records)+1, err)
		}
		records = append(records, record)
	}
}

func decodeStreamRecord(raw []byte, format Format) (auditchain.Record, error) {
	switch format {
	case FormatNDJSON:
		var value ndjsonRecord
		if err := decodeExactJSON(raw, &value); err != nil {
			return auditchain.Record{}, err
		}
		return recordFromNDJSON(value)
	case FormatSplunkHEC:
		var value splunkEvent
		if err := decodeExactJSON(raw, &value); err != nil {
			return auditchain.Record{}, err
		}
		record, err := recordFromNDJSON(value.Event)
		if err != nil {
			return auditchain.Record{}, err
		}
		wantTime := float64(record.Time.UnixNano()) / float64(time.Second)
		if value.Source != "trstctl" || value.SourceType != "trstctl:audit" || value.Host != "" || value.Index != "" || value.Time != wantTime {
			return auditchain.Record{}, errors.New("splunk envelope metadata does not match the canonical trstctl audit mapping")
		}
		return record, nil
	case FormatSentinel:
		var value sentinelRecord
		if err := decodeExactJSON(raw, &value); err != nil {
			return auditchain.Record{}, err
		}
		at, err := time.Parse(time.RFC3339Nano, value.TimeGenerated)
		if err != nil {
			return auditchain.Record{}, fmt.Errorf("invalid TimeGenerated: %w", err)
		}
		record := auditchain.Record{
			Sequence: value.Sequence, ID: value.RecordId, Type: value.EventType,
			TenantID: value.TenantId, Time: at.UTC(), Hash: value.ChainHash, Data: value.Data,
		}
		if value.ActorSubject != "" || value.ActorRoles != "" {
			record.Actor = &eventspec.Actor{Subject: value.ActorSubject, Roles: strings.Fields(value.ActorRoles)}
		}
		return record, nil
	default:
		return auditchain.Record{}, fmt.Errorf("unsupported JSON stream format %q", format)
	}
}

func recordFromNDJSON(value ndjsonRecord) (auditchain.Record, error) {
	at, err := time.Parse(time.RFC3339Nano, value.Time)
	if err != nil {
		return auditchain.Record{}, fmt.Errorf("invalid time: %w", err)
	}
	record := auditchain.Record{
		Sequence: value.Sequence, ID: value.ID, Type: value.Type, TenantID: value.TenantID,
		Time: at.UTC(), Hash: value.ChainHash, Data: value.Data,
	}
	if value.ActorSubject != "" || len(value.ActorRoles) > 0 {
		record.Actor = &eventspec.Actor{Subject: value.ActorSubject, Roles: append([]string(nil), value.ActorRoles...)}
	}
	return record, nil
}

func verifyRecordStream(records []auditchain.Record, proof trailer, tsaRootDER []byte, tolerance time.Duration) error {
	if _, err := validateRecordTenancy(records); err != nil {
		return err
	}
	if proof.Count != len(records) || proof.ChainHead == "" {
		return errors.New("auditanchor: JSON integrity trailer count or chain head does not match the stream")
	}
	recomputed := append([]auditchain.Record(nil), records...)
	head := auditchain.SealFrom(proof.PrevHash, recomputed)
	for i := range records {
		if recomputed[i].Hash != records[i].Hash {
			return fmt.Errorf("auditanchor: JSON record chain is broken at record %d", i+1)
		}
	}
	if head != proof.ChainHead || proof.Anchor.ChainHead != proof.ChainHead {
		return errors.New("auditanchor: JSON records, trailer, and anchor name different chain heads")
	}
	if err := Verify(proof.Anchor, head, tsaRootDER); err != nil {
		return err
	}
	return VerifyNotBackdated(proof.Anchor, newestRecordTime(records), tolerance)
}

func validateRecordTenancy(records []auditchain.Record) (string, error) {
	if len(records) == 0 {
		return "", nil
	}
	tenantID := records[0].TenantID
	if tenantID == "" {
		return "", errors.New("auditanchor: record stream contains an empty tenant scope")
	}
	for i := range records {
		if records[i].TenantID != tenantID {
			return "", fmt.Errorf("auditanchor: record stream crosses tenant scope at record %d", i+1)
		}
	}
	return tenantID, nil
}

func csvTrailer(raw []byte) (trailer, error) {
	rows, err := csv.NewReader(bytes.NewReader(raw)).ReadAll()
	if err != nil || len(rows) < 2 || len(rows[len(rows)-1]) != len(csvColumns) {
		return trailer{}, errors.New("auditanchor: CSV integrity trailer cannot be read")
	}
	var proof trailer
	if err := decodeExactJSON([]byte(rows[len(rows)-1][len(csvColumns)-1]), &proof); err != nil {
		return trailer{}, fmt.Errorf("auditanchor: decode CSV integrity trailer: %w", err)
	}
	return proof, nil
}

func resultFor(format Format, records []auditchain.Record, proof trailer) VerificationResult {
	tenantID := ""
	if len(records) > 0 {
		tenantID = records[0].TenantID
	}
	return VerificationResult{
		Format: format, TenantID: tenantID, RecordCount: len(records), PrevHash: proof.PrevHash,
		ChainHead: proof.ChainHead, AnchorKind: proof.Anchor.Kind,
		AnchoredAt: proof.Anchor.AnchoredAt.UTC(), NewestRecordAt: newestRecordTime(records),
	}
}
