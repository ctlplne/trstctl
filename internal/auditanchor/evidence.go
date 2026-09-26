// SPDX-License-Identifier: BUSL-1.1

package auditanchor

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/crypto/jose"
)

const EvidenceEnvelopeSchemaVersion = 1

// EvidenceEnvelope is the browser/download representation of a signed audit
// export. The JWS, its recomputed chain head, and its external timestamp travel
// as one JSON document. A saved file therefore retains the proof after HTTP
// headers and the live API response are gone.
type EvidenceEnvelope struct {
	SchemaVersion int    `json:"schema_version"`
	Format        Format `json:"format"`
	Bundle        string `json:"bundle"`
	ChainHead     string `json:"chain_head"`
	Anchor        Anchor `json:"anchor"`
}

// VerifyEvidenceEnvelope performs the complete offline check: strict envelope
// shape, JWS signature, record hash chain, head-to-anchor binding, RFC 3161
// signature, and the caller's back-date policy. The TSA root and audit JWK set
// are trust inputs held outside the artifact; accepting roots carried only by
// the file would let an attacker mint their own authority.
func VerifyEvidenceEnvelope(raw []byte, keys *jose.JWKSet, tsaRootDER []byte, tolerance time.Duration) (audit.Bundle, error) {
	bundle, envelope, err := verifySignedEvidenceEnvelope(raw, keys)
	if err != nil {
		return audit.Bundle{}, err
	}
	if err := verifyEvidenceAnchor(bundle, envelope.Anchor, tsaRootDER, tolerance); err != nil {
		return audit.Bundle{}, err
	}
	return bundle, nil
}

// verifySignedEvidenceEnvelope is shared by strict timestamp verification and
// explicitly requested plain-JWS verification. Both paths keep the same shape,
// signature, tenant scope, count, archived-prefix and record-chain checks.
func verifySignedEvidenceEnvelope(raw []byte, keys *jose.JWKSet) (audit.Bundle, EvidenceEnvelope, error) {
	var envelope EvidenceEnvelope
	if err := decodeExactJSON(raw, &envelope); err != nil {
		return audit.Bundle{}, EvidenceEnvelope{}, fmt.Errorf("auditanchor: decode evidence envelope: %w", err)
	}
	if envelope.SchemaVersion != EvidenceEnvelopeSchemaVersion {
		return audit.Bundle{}, EvidenceEnvelope{}, fmt.Errorf("auditanchor: unsupported evidence envelope schema %d", envelope.SchemaVersion)
	}
	if envelope.Format != FormatJWS || strings.TrimSpace(envelope.Bundle) == "" || strings.TrimSpace(envelope.ChainHead) == "" {
		return audit.Bundle{}, EvidenceEnvelope{}, errors.New("auditanchor: evidence envelope requires jws format, bundle, and chain head")
	}
	if keys == nil {
		return audit.Bundle{}, EvidenceEnvelope{}, errors.New("auditanchor: audit verification JWK set is required")
	}
	payload, err := keys.VerifyArtifact(envelope.Bundle, jose.ArtifactAuditExport)
	if err != nil {
		return audit.Bundle{}, EvidenceEnvelope{}, fmt.Errorf("auditanchor: verify signed evidence bundle: %w", err)
	}
	var bundle audit.Bundle
	if err := decodeExactJSON(payload, &bundle); err != nil {
		return audit.Bundle{}, EvidenceEnvelope{}, fmt.Errorf("auditanchor: decode signed evidence bundle: %w", err)
	}
	if len(bundle.Records) > maxArtifactRecords {
		return audit.Bundle{}, EvidenceEnvelope{}, fmt.Errorf("auditanchor: signed bundle exceeds the %d-record limit", maxArtifactRecords)
	}
	if bundle.Count != len(bundle.Records) || bundle.TenantID == "" || bundle.Query.TenantID != bundle.TenantID {
		return audit.Bundle{}, EvidenceEnvelope{}, errors.New("auditanchor: signed bundle count or tenant scope does not match its records")
	}
	for _, record := range bundle.Records {
		if record.TenantID != bundle.TenantID {
			return audit.Bundle{}, EvidenceEnvelope{}, errors.New("auditanchor: signed bundle contains a record from a different tenant")
		}
	}
	head, err := audit.VerifyChainFrom(bundle.PrevHash, bundle.Records)
	if err != nil {
		return audit.Bundle{}, EvidenceEnvelope{}, fmt.Errorf("auditanchor: verify signed evidence chain: %w", err)
	}
	if head != bundle.ChainHead {
		return audit.Bundle{}, EvidenceEnvelope{}, errors.New("auditanchor: signed bundle chain head does not match its records")
	}
	if bundle.ChainHead != envelope.ChainHead {
		return audit.Bundle{}, EvidenceEnvelope{}, errors.New("auditanchor: signed bundle and evidence envelope name different chain heads")
	}
	return bundle, envelope, nil
}

func verifyEvidenceAnchor(bundle audit.Bundle, anchor Anchor, tsaRootDER []byte, tolerance time.Duration) error {
	if err := Verify(anchor, bundle.ChainHead, tsaRootDER); err != nil {
		return err
	}
	return VerifyNotBackdated(anchor, newestRecordTime(bundle.Records), tolerance)
}

func decodeExactJSON(raw []byte, out any) error {
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func rejectDuplicateJSONKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := scanJSONValue(dec); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func scanJSONValue(dec *json.Decoder) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate object key %q", key)
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(dec); err != nil {
				return err
			}
		}
		closeToken, err := dec.Token()
		if err != nil || closeToken != json.Delim('}') {
			return errors.New("unterminated JSON object")
		}
	case '[':
		for dec.More() {
			if err := scanJSONValue(dec); err != nil {
				return err
			}
		}
		closeToken, err := dec.Token()
		if err != nil || closeToken != json.Delim(']') {
			return errors.New("unterminated JSON array")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
	return nil
}

func newestRecordTime(records []audit.Record) time.Time {
	var newest time.Time
	for _, record := range records {
		if record.Time.After(newest) {
			newest = record.Time
		}
	}
	return newest
}
