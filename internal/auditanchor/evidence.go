// SPDX-License-Identifier: MPL-2.0

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
	var envelope EvidenceEnvelope
	if err := decodeExactJSON(raw, &envelope); err != nil {
		return audit.Bundle{}, fmt.Errorf("auditanchor: decode evidence envelope: %w", err)
	}
	if envelope.SchemaVersion != EvidenceEnvelopeSchemaVersion {
		return audit.Bundle{}, fmt.Errorf("auditanchor: unsupported evidence envelope schema %d", envelope.SchemaVersion)
	}
	if envelope.Format != FormatJWS || strings.TrimSpace(envelope.Bundle) == "" || strings.TrimSpace(envelope.ChainHead) == "" {
		return audit.Bundle{}, errors.New("auditanchor: evidence envelope requires jws format, bundle, and chain head")
	}
	bundle, err := audit.VerifyBundle(envelope.Bundle, keys)
	if err != nil {
		return audit.Bundle{}, fmt.Errorf("auditanchor: verify signed evidence bundle: %w", err)
	}
	if bundle.ChainHead != envelope.ChainHead {
		return audit.Bundle{}, errors.New("auditanchor: signed bundle and evidence envelope name different chain heads")
	}
	if err := Verify(envelope.Anchor, envelope.ChainHead, tsaRootDER); err != nil {
		return audit.Bundle{}, err
	}
	if err := VerifyNotBackdated(envelope.Anchor, newestRecordTime(bundle.Records), tolerance); err != nil {
		return audit.Bundle{}, err
	}
	return bundle, nil
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
