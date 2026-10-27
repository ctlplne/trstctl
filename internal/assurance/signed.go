// SPDX-License-Identifier: BUSL-1.1

package assurance

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
)

// Kind is the artifact domain the record is signed under; the isolated signer
// admits it and a verifier requires it.
const Kind = jose.ArtifactAssuranceRecord

// Signed is a record as served and saved: the record, a compact JWS over its
// exact bytes, the public keys to check it with, and a readable rendering.
type Signed struct {
	Record       json.RawMessage `json:"record"`
	SignedRecord string          `json:"signed_record"`
	RecordSHA256 string          `json:"record_sha256"`
	PublicJWKS   json.RawMessage `json:"public_jwks"`
	Rendering    string          `json:"rendering"`
}

// Signer signs evidence under an admitted artifact kind and publishes its
// public keys.
type Signer interface {
	SignArtifact(kind string, payload []byte) (string, error)
	PublicJWKS() ([]byte, error)
}

// Sign signs the record's exact JSON bytes.
func Sign(signer Signer, record Record) (Signed, error) {
	if signer == nil {
		return Signed{}, errors.New("assurance: evidence signer is not configured")
	}
	body, err := json.Marshal(record)
	if err != nil {
		return Signed{}, err
	}
	compact, err := signer.SignArtifact(Kind, body)
	if err != nil {
		return Signed{}, fmt.Errorf("assurance: sign record: %w", err)
	}
	jwks, err := signer.PublicJWKS()
	if err != nil {
		return Signed{}, fmt.Errorf("assurance: publish verifier: %w", err)
	}
	return Signed{
		Record: body, SignedRecord: compact, RecordSHA256: "sha256:" + crypto.SHA256Hex(body),
		PublicJWKS: json.RawMessage(jwks), Rendering: Render(record),
	}, nil
}

// Verified is what an offline check established.
type Verified struct {
	Record       Record
	KeyID        string
	RecordSHA256 string
}

// Verify checks a saved Signed document against a separately pinned JWK set:
// the signature and its artifact domain, and that the record beside the
// signature is exactly the signed record. The document's own public_jwks is
// never trusted; a verifier that took keys from the file would accept a
// forgery that ships its own key.
func Verify(document []byte, keys *jose.JWKSet) (Verified, error) {
	if keys == nil {
		return Verified{}, errors.New("assurance: a pinned JWK set is required")
	}
	var signed Signed
	if err := json.Unmarshal(document, &signed); err != nil {
		return Verified{}, fmt.Errorf("assurance: decode signed record: %w", err)
	}
	if signed.SignedRecord == "" {
		return Verified{}, errors.New("assurance: the document carries no signed_record")
	}
	payload, kid, err := keys.VerifyArtifactWithKeyID(signed.SignedRecord, Kind)
	if err != nil {
		return Verified{}, fmt.Errorf("assurance: signature: %w", err)
	}
	record, err := decodeRecord(payload)
	if err != nil {
		return Verified{}, fmt.Errorf("assurance: decode signed record: %w", err)
	}
	if record.Format != Format {
		return Verified{}, fmt.Errorf("assurance: unsupported record format %q", record.Format)
	}
	if len(signed.Record) > 0 {
		// Compare meaning, not bytes: a tool that re-indents or reorders the
		// saved file changes nothing signed, while any changed value differs.
		saved, err := decodeRecord(signed.Record)
		if err != nil {
			return Verified{}, fmt.Errorf("assurance: decode record: %w", err)
		}
		savedJSON, err := json.Marshal(saved)
		if err != nil {
			return Verified{}, err
		}
		signedJSON, err := json.Marshal(record)
		if err != nil {
			return Verified{}, err
		}
		if !bytes.Equal(savedJSON, signedJSON) {
			return Verified{}, errors.New("assurance: the record differs from the signed record")
		}
	}
	digest := "sha256:" + crypto.SHA256Hex(payload)
	if signed.RecordSHA256 != "" && signed.RecordSHA256 != digest {
		return Verified{}, errors.New("assurance: record_sha256 differs from the signed record")
	}
	return Verified{Record: record, KeyID: kid, RecordSHA256: digest}, nil
}

func decodeRecord(raw []byte) (Record, error) {
	var record Record
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return Record{}, err
	}
	return record, nil
}
