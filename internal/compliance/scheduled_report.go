// SPDX-License-Identifier: BUSL-1.1

package compliance

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// ScheduledReportFormat is the manifest format every scheduled report run is
// signed under.
const ScheduledReportFormat = "trstctl.compliance.scheduled-report.v1"

// ScheduledReport is what an offline check of a saved scheduled report run
// established: the run it binds and the exact payload the key signed.
type ScheduledReport struct {
	TenantID    string          `json:"tenant_id"`
	ScheduleID  string          `json:"schedule_id"`
	RunID       string          `json:"run_id"`
	DueAt       time.Time       `json:"due_at"`
	GeneratedAt time.Time       `json:"generated_at"`
	Framework   string          `json:"framework"`
	ReportType  string          `json:"report_type"`
	Payload     json.RawMessage `json:"payload"`
	// KeySHA256 is the SHA-256 of the pinned key that verified it.
	KeySHA256 string `json:"key_sha256"`
}

// ParsePublicKey reads a pinned public key from a PEM PUBLIC KEY block or raw
// PKIX DER.
func ParsePublicKey(raw []byte) ([]byte, error) {
	if block, _ := pem.Decode(raw); block != nil {
		if block.Type != "PUBLIC KEY" {
			return nil, fmt.Errorf("compliance: pinned key is a PEM %q block, want PUBLIC KEY", block.Type)
		}
		return block.Bytes, nil
	}
	if len(raw) == 0 {
		return nil, errors.New("compliance: pinned key is empty")
	}
	return raw, nil
}

// VerifyScheduledReport checks a saved scheduled report run against a
// separately pinned public key (PKIX DER): the signature over the exact
// manifest bytes, and that the manifest is a complete scheduled-report
// binding. The artifact's own public_key_der is never trusted; a verifier
// that took the key from the file would accept a forgery that ships its own
// key. Nothing is sent anywhere.
func VerifyScheduledReport(artifact, pinnedKeyDER []byte) (ScheduledReport, error) {
	if len(pinnedKeyDER) == 0 {
		return ScheduledReport{}, errors.New("compliance: a pinned public key is required")
	}
	var envelope struct {
		Manifest     json.RawMessage `json:"manifest"`
		Signature    []byte          `json:"signature"`
		PublicKeyDER []byte          `json:"public_key_der"`
	}
	if err := json.Unmarshal(artifact, &envelope); err != nil {
		return ScheduledReport{}, fmt.Errorf("compliance: decode signed report: %w", err)
	}
	if len(envelope.Manifest) == 0 || len(envelope.Signature) == 0 {
		return ScheduledReport{}, errors.New("compliance: the file carries no signed manifest")
	}
	if len(envelope.PublicKeyDER) > 0 && !bytes.Equal(envelope.PublicKeyDER, pinnedKeyDER) {
		return ScheduledReport{}, errors.New("compliance: the report was signed by a different key than the one pinned")
	}
	if err := crypto.VerifyMessage(pinnedKeyDER, envelope.Manifest, envelope.Signature); err != nil {
		return ScheduledReport{}, fmt.Errorf("compliance: signature does not verify under the pinned key: %w", err)
	}
	var manifest struct {
		Format      string          `json:"format"`
		TenantID    string          `json:"tenant_id"`
		ScheduleID  string          `json:"schedule_id"`
		RunID       string          `json:"run_id"`
		DueAt       time.Time       `json:"due_at"`
		GeneratedAt time.Time       `json:"generated_at"`
		Framework   string          `json:"framework"`
		ReportType  string          `json:"report_type"`
		Payload     json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(envelope.Manifest, &manifest); err != nil || manifest.Format != ScheduledReportFormat ||
		manifest.TenantID == "" || manifest.ScheduleID == "" || manifest.RunID == "" || manifest.DueAt.IsZero() ||
		manifest.GeneratedAt.IsZero() || manifest.ReportType == "" || len(manifest.Payload) == 0 || !json.Valid(manifest.Payload) {
		return ScheduledReport{}, errors.New("compliance: the signed manifest is not a complete scheduled report")
	}
	return ScheduledReport{
		TenantID: manifest.TenantID, ScheduleID: manifest.ScheduleID, RunID: manifest.RunID,
		DueAt: manifest.DueAt, GeneratedAt: manifest.GeneratedAt, Framework: manifest.Framework,
		ReportType: manifest.ReportType, Payload: manifest.Payload, KeySHA256: crypto.SHA256Hex(pinnedKeyDER),
	}, nil
}
