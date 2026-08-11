// SPDX-License-Identifier: MPL-2.0

// Package historycontinuity signs and verifies the durable authorization that
// lets the event log switch from one history generation to another.
//
// The receipt is deliberately separate from the events package. The events
// package owns generation mechanics; this package owns the production trust
// decision and routes its signature through internal/crypto/jose (AN-3).
package historycontinuity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/eventledger"
	"trstctl.com/trstctl/internal/events"
)

const (
	// ReceiptEventType is the one event type allowed to authorize destruction of
	// a superseded event-history generation.
	ReceiptEventType = eventledger.EventHistoryTenantDataRewriteContinuity
	// ReceiptEventSchemaVersion is the payload-shape version recorded on the
	// immutable event envelope.
	ReceiptEventSchemaVersion = 1
	// ReceiptClaimsSchema identifies the canonical bytes covered by the JWS.
	ReceiptClaimsSchema = "trstctl.history-rewrite-continuity/v1"

	receiptActorSubject = "trstctl:history-rewrite"
	receiptActorRole    = "system"

	checkpointIdentitySchema = "trstctl.audit-checkpoint-identity/v1"
)

// receiptData has exactly one field. Everything with semantic meaning lives in
// the signed claims; accepting extra JSON next to the JWS would create an
// unsigned interpretation surface.
type receiptData struct {
	JWS string `json:"jws"`
}

// receiptClaims is intentionally a fixed struct, not a map. encoding/json emits
// its fields in declaration order, giving signing and verification one canonical
// byte sequence. Exact-byte verification rejects whitespace, duplicate keys,
// reordered keys, unknown fields, and alternative timestamp spellings.
type receiptClaims struct {
	Schema          string                         `json:"schema"`
	ReceiptID       string                         `json:"receipt_id"`
	ReceiptType     string                         `json:"receipt_type"`
	ReceiptTenantID string                         `json:"receipt_tenant_id"`
	ReceiptTime     string                         `json:"receipt_time"`
	ReceiptSchema   int                            `json:"receipt_schema_version"`
	ReceiptActor    events.Actor                   `json:"receipt_actor"`
	Rewrite         events.TenantDataRewriteReport `json:"rewrite"`
}

// NewReceiptSigner returns the callback used by events.WithTenantDataContinuity.
// It signs the complete canonical report and every interpreted receipt-envelope
// field with the deployment's persistent audit key.
func NewReceiptSigner(key *jose.SigningKey) events.TenantDataContinuity {
	return func(_ context.Context, report events.TenantDataRewriteReport) (events.Event, error) {
		if key == nil {
			return events.Event{}, errors.New("history continuity: audit signing key is required")
		}
		if err := validateReport(report); err != nil {
			return events.Event{}, err
		}
		receipt := events.Event{
			ID:            events.NewID(),
			Type:          ReceiptEventType,
			TenantID:      report.TenantID,
			Time:          time.Now().UTC(),
			SchemaVersion: ReceiptEventSchemaVersion,
			Actor:         receiptActor(),
		}
		claims := claimsFor(receipt, report)
		canonical, err := json.Marshal(claims)
		if err != nil {
			return events.Event{}, fmt.Errorf("history continuity: encode canonical claims: %w", err)
		}
		signed, err := key.SignArtifact(jose.ArtifactHistoryContinuity, canonical)
		if err != nil {
			return events.Event{}, fmt.Errorf("history continuity: sign canonical claims: %w", err)
		}
		receipt.Data, err = json.Marshal(receiptData{JWS: signed})
		if err != nil {
			return events.Event{}, fmt.Errorf("history continuity: encode signed receipt: %w", err)
		}
		return receipt, nil
	}
}

// NewReceiptVerifier returns the signature/evidence wall used both immediately
// before activation and during restart recovery. Recovery may trust neither
// mutable stream metadata nor unsigned receipt fields, so every value it uses is
// compared with the verified canonical claims.
func NewReceiptVerifier(key *jose.SigningKey) events.TenantDataContinuityVerifier {
	return func(_ context.Context, evidence events.TenantDataContinuityEvidence) error {
		if err := validateEvidenceEnvelope(evidence); err != nil {
			return err
		}
		report, err := VerifyReceipt(key, evidence.Receipt)
		if err != nil {
			return err
		}
		signedReport, err := json.Marshal(report)
		if err != nil {
			return fmt.Errorf("history continuity: encode signed report: %w", err)
		}
		evidenceReport, err := json.Marshal(evidence.Report)
		if err != nil {
			return fmt.Errorf("history continuity: encode evidence report: %w", err)
		}
		if !bytes.Equal(signedReport, evidenceReport) {
			return errors.New("history continuity: signed report does not exactly match durable recovery evidence")
		}
		switch {
		case report.OperationID != evidence.OperationID:
			return errors.New("history continuity: signed operation does not match recovery evidence")
		case report.TenantID != evidence.TenantID:
			return errors.New("history continuity: signed tenant does not match recovery evidence")
		case report.SourceStream != evidence.SourceStream:
			return errors.New("history continuity: signed source stream does not match recovery evidence")
		case report.TargetStream != evidence.TargetStream:
			return errors.New("history continuity: signed target stream does not match recovery evidence")
		case report.ReceiptSequence != evidence.ReceiptSequence:
			return errors.New("history continuity: signed receipt sequence does not match recovery evidence")
		default:
			return nil
		}
	}
}

// VerifyReceipt cryptographically opens a self-contained continuity receipt.
// Recovery uses NewReceiptVerifier to additionally compare mutable stream
// metadata; backup descendant verification has no surviving source generation,
// so it uses this narrower signed-envelope proof and independently compares every
// artifact/history position.
func VerifyReceipt(key *jose.SigningKey, receipt events.Event) (events.TenantDataRewriteReport, error) {
	if key == nil {
		return events.TenantDataRewriteReport{}, errors.New("history continuity: audit verification key is required")
	}
	var envelope receiptData
	if err := decodeCanonical(receipt.Data, &envelope); err != nil {
		return events.TenantDataRewriteReport{}, fmt.Errorf("history continuity: receipt data is not canonical: %w", err)
	}
	if strings.TrimSpace(envelope.JWS) == "" {
		return events.TenantDataRewriteReport{}, errors.New("history continuity: receipt JWS is empty")
	}
	payload, err := key.JWKS().Verify(envelope.JWS)
	if err != nil {
		return events.TenantDataRewriteReport{}, fmt.Errorf("history continuity: verify receipt JWS: %w", err)
	}
	var claims receiptClaims
	if err := decodeCanonical(payload, &claims); err != nil {
		return events.TenantDataRewriteReport{}, fmt.Errorf("history continuity: signed claims are not canonical: %w", err)
	}
	report := claims.Rewrite
	evidence := events.TenantDataContinuityEvidence{
		OperationID: report.OperationID, TenantID: report.TenantID,
		SourceStream: report.SourceStream, TargetStream: report.TargetStream,
		ReceiptSequence: report.ReceiptSequence, Receipt: receipt, Report: report,
	}
	if err := validateEvidenceEnvelope(evidence); err != nil {
		return events.TenantDataRewriteReport{}, err
	}
	if err := validateClaims(evidence, claims); err != nil {
		return events.TenantDataRewriteReport{}, err
	}
	return report, nil
}

func receiptActor() *events.Actor {
	return &events.Actor{Subject: receiptActorSubject, Roles: []string{receiptActorRole}}
}

func claimsFor(receipt events.Event, report events.TenantDataRewriteReport) receiptClaims {
	return receiptClaims{
		Schema:          ReceiptClaimsSchema,
		ReceiptID:       receipt.ID,
		ReceiptType:     receipt.Type,
		ReceiptTenantID: receipt.TenantID,
		ReceiptTime:     receipt.Time.UTC().Format(time.RFC3339Nano),
		ReceiptSchema:   receipt.SchemaVersion,
		ReceiptActor:    *receipt.Actor,
		Rewrite:         report,
	}
}

func validateEvidenceEnvelope(evidence events.TenantDataContinuityEvidence) error {
	switch {
	case strings.TrimSpace(evidence.OperationID) == "":
		return errors.New("history continuity: evidence operation_id is required")
	case strings.TrimSpace(evidence.TenantID) == "":
		return errors.New("history continuity: evidence tenant_id is required")
	case strings.TrimSpace(evidence.SourceStream) == "":
		return errors.New("history continuity: evidence source stream is required")
	case strings.TrimSpace(evidence.TargetStream) == "":
		return errors.New("history continuity: evidence target stream is required")
	case evidence.ReceiptSequence == 0:
		return errors.New("history continuity: evidence receipt sequence is required")
	}
	receipt := evidence.Receipt
	if receipt.ID == "" ||
		receipt.Type != ReceiptEventType ||
		receipt.TenantID != evidence.TenantID ||
		receipt.Time.IsZero() ||
		receipt.SchemaVersion != ReceiptEventSchemaVersion ||
		!reflect.DeepEqual(receipt.Actor, receiptActor()) {
		return errors.New("history continuity: receipt type/schema/tenant/time/actor policy mismatch")
	}
	if receipt.Sequence != 0 && receipt.Sequence != evidence.ReceiptSequence {
		return errors.New("history continuity: receipt envelope sequence does not match evidence")
	}
	return nil
}

func validateClaims(evidence events.TenantDataContinuityEvidence, claims receiptClaims) error {
	receipt := evidence.Receipt
	expectedActor := receiptActor()
	switch {
	case claims.Schema != ReceiptClaimsSchema:
		return errors.New("history continuity: signed receipt schema mismatch")
	case claims.ReceiptID != receipt.ID:
		return errors.New("history continuity: signed receipt id does not match event")
	case claims.ReceiptType != receipt.Type:
		return errors.New("history continuity: signed receipt type does not match event")
	case claims.ReceiptTenantID != receipt.TenantID:
		return errors.New("history continuity: signed receipt tenant does not match event")
	case claims.ReceiptTime != receipt.Time.UTC().Format(time.RFC3339Nano):
		return errors.New("history continuity: signed receipt time does not match event")
	case receipt.Time.Before(claims.Rewrite.CompletedAt):
		return errors.New("history continuity: receipt predates rewrite completion")
	case claims.ReceiptSchema != receipt.SchemaVersion:
		return errors.New("history continuity: signed receipt schema version does not match event")
	case !reflect.DeepEqual(&claims.ReceiptActor, expectedActor):
		return errors.New("history continuity: signed receipt actor does not match system actor policy")
	}
	report := claims.Rewrite
	if err := validateReport(report); err != nil {
		return err
	}
	signedReport, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("history continuity: encode signed report: %w", err)
	}
	evidenceReport, err := json.Marshal(evidence.Report)
	if err != nil {
		return fmt.Errorf("history continuity: encode evidence report: %w", err)
	}
	if !bytes.Equal(signedReport, evidenceReport) {
		return errors.New("history continuity: signed report does not exactly match durable recovery evidence")
	}
	switch {
	case report.OperationID != evidence.OperationID:
		return errors.New("history continuity: signed operation does not match recovery evidence")
	case report.TenantID != evidence.TenantID:
		return errors.New("history continuity: signed tenant does not match recovery evidence")
	case report.SourceStream != evidence.SourceStream:
		return errors.New("history continuity: signed source stream does not match recovery evidence")
	case report.TargetStream != evidence.TargetStream:
		return errors.New("history continuity: signed target stream does not match recovery evidence")
	case report.ReceiptSequence != evidence.ReceiptSequence:
		return errors.New("history continuity: signed receipt sequence does not match recovery evidence")
	}
	return nil
}

func validateReport(report events.TenantDataRewriteReport) error {
	switch {
	case strings.TrimSpace(report.OperationID) == "":
		return errors.New("history continuity: rewrite operation_id is required")
	case strings.TrimSpace(report.TenantID) == "":
		return errors.New("history continuity: rewrite tenant_id is required")
	case strings.TrimSpace(report.SourceStream) == "" ||
		strings.TrimSpace(report.SourceGeneration) == "":
		return errors.New("history continuity: source stream and generation are required")
	case strings.TrimSpace(report.TargetStream) == "" ||
		strings.TrimSpace(report.TargetGeneration) == "":
		return errors.New("history continuity: target stream and generation are required")
	case report.SourceStream == report.TargetStream:
		return errors.New("history continuity: source and target streams must differ")
	case report.TargetGeneration != report.OperationID:
		return errors.New("history continuity: target generation must equal the rewrite operation id")
	case report.ChangedEvents <= 0:
		return errors.New("history continuity: rewrite must prove at least one changed event")
	case report.ReceiptSequence == 0 ||
		report.SourceCutSequence == ^uint64(0) ||
		report.ReceiptSequence != report.SourceCutSequence+1:
		return errors.New("history continuity: receipt sequence must immediately follow the frozen source cut")
	case report.FirstSequence == 0:
		return errors.New("history continuity: first sequence is required")
	case report.SourceCutSequence < report.FirstSequence:
		return errors.New("history continuity: source cut precedes the first retained sequence")
	case strings.TrimSpace(report.EnvelopeDigest) == "":
		return errors.New("history continuity: invariant envelope root is required")
	case strings.TrimSpace(report.MappingDigest) == "":
		return errors.New("history continuity: old/new mapping root is required")
	case strings.TrimSpace(report.SourceConfigDigest) == "" ||
		strings.TrimSpace(report.TargetConfigDigest) == "":
		return errors.New("history continuity: source and target config digests are required")
	case strings.TrimSpace(report.TargetContentDigest) == "":
		return errors.New("history continuity: complete target content digest is required")
	case report.ArchiveExposure != events.TenantDataArchiveExposureExternalCopiesMayRetainSourceBytes:
		return errors.New("history continuity: external archive/export/backup exposure disclosure is required")
	case strings.TrimSpace(report.AuditCheckpoint.IdentityDigest) == "":
		return errors.New("history continuity: retention checkpoint/genesis identity is required")
	case report.AuditCheckpoint.BoundarySequence > report.SourceCutSequence:
		return errors.New("history continuity: audit checkpoint boundary is past the frozen source cut")
	case report.AuditCheckpoint.BoundarySequence == 0 &&
		(report.AuditCheckpoint.BoundaryHash != "" || report.AuditCheckpoint.RecordCount != 0):
		return errors.New("history continuity: genesis checkpoint carries non-genesis seed fields")
	case report.AuditCheckpoint.BoundarySequence > 0 &&
		(strings.TrimSpace(report.AuditCheckpoint.BoundaryHash) == "" ||
			report.AuditCheckpoint.RecordCount == 0):
		return errors.New("history continuity: retained checkpoint lacks its boundary seed or record count")
	case strings.TrimSpace(report.SourceAuditHead) == "" && report.ChangedEvents > 0:
		return errors.New("history continuity: source audit head is required for a changed rewrite")
	case strings.TrimSpace(report.TargetAuditHead) == "" && report.ChangedEvents > 0:
		return errors.New("history continuity: target audit head is required for a changed rewrite")
	case report.StartedAt.IsZero() || report.CompletedAt.IsZero() ||
		report.CompletedAt.Before(report.StartedAt):
		return errors.New("history continuity: rewrite timestamps are invalid")
	}
	return nil
}

func decodeCanonical(data []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if err := expectEOF(dec); err != nil {
		return err
	}
	canonical, err := json.Marshal(dst)
	if err != nil {
		return err
	}
	if !bytes.Equal(data, canonical) {
		return errors.New("bytes differ from the one canonical JSON encoding")
	}
	return nil
}

func expectEOF(dec *json.Decoder) error {
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

// AuditCheckpointProvider maps the tenant's durable retention checkpoint to the
// seed contract consumed by the generation-pinned audit-chain derivation. The
// identity digest covers the archive locator too, so two retained prefixes with
// the same numeric boundary cannot be confused.
func AuditCheckpointProvider(source audit.CheckpointSource) events.TenantDataAuditContinuityProvider {
	return func(ctx context.Context, view events.TenantDataAuditView) (events.TenantDataAuditCheckpoint, error) {
		if source == nil {
			return events.TenantDataAuditCheckpoint{}, errors.New("history continuity: audit checkpoint source is required")
		}
		tenantID := view.Report.TenantID
		if strings.TrimSpace(tenantID) == "" {
			return events.TenantDataAuditCheckpoint{}, errors.New("history continuity: checkpoint tenant_id is required")
		}
		cp, ok, err := source.LatestAuditCheckpoint(ctx, tenantID)
		if err != nil {
			return events.TenantDataAuditCheckpoint{}, err
		}
		if !ok {
			identity := checkpointIdentity{
				Schema: checkpointIdentitySchema,
				Kind:   "genesis", TenantID: tenantID,
			}
			return events.TenantDataAuditCheckpoint{
				IdentityDigest: digestIdentity(identity),
			}, nil
		}
		if cp.TenantID != tenantID {
			return events.TenantDataAuditCheckpoint{}, errors.New("history continuity: checkpoint tenant does not match rewrite tenant")
		}
		if cp.BoundarySeq == 0 || strings.TrimSpace(cp.BoundaryHash) == "" || cp.RecordCount < 0 {
			return events.TenantDataAuditCheckpoint{}, errors.New("history continuity: durable audit checkpoint is incomplete")
		}
		identity := checkpointIdentity{
			Schema: checkpointIdentitySchema,
			Kind:   "retention", TenantID: tenantID,
			BoundarySequence: cp.BoundarySeq,
			BoundaryHash:     cp.BoundaryHash,
			RecordCount:      cp.RecordCount,
			ArchiveURI:       cp.ArchiveURI,
		}
		return events.TenantDataAuditCheckpoint{
			BoundarySequence: cp.BoundarySeq,
			BoundaryHash:     cp.BoundaryHash,
			RecordCount:      uint64(cp.RecordCount),
			IdentityDigest:   digestIdentity(identity),
		}, nil
	}
}

type checkpointIdentity struct {
	Schema           string `json:"schema"`
	Kind             string `json:"kind"`
	TenantID         string `json:"tenant_id"`
	BoundarySequence uint64 `json:"boundary_sequence,omitempty"`
	BoundaryHash     string `json:"boundary_hash,omitempty"`
	RecordCount      int    `json:"record_count,omitempty"`
	ArchiveURI       string `json:"archive_uri,omitempty"`
}

func digestIdentity(identity checkpointIdentity) string {
	canonical, _ := json.Marshal(identity)
	return crypto.SHA256Hex(canonical)
}
