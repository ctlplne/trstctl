// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

var ErrCertificateReprotectionConflict = errors.New("store: CA re-protection cutover differs from current tenant state")

// CertificateReprotectionCutover is public, immutable source-event data. It
// carries the verified signed readback itself so a cold event rebuild never
// depends on a mutable receipt read-model row.
type CertificateReprotectionCutover struct {
	IdentityID               string `json:"identity_id"`
	TargetID                 string `json:"target_id"`
	OldCertificateID         string `json:"old_certificate_id"`
	OldFingerprint           string `json:"old_fingerprint"`
	NewCertificateID         string `json:"new_certificate_id"`
	NewFingerprint           string `json:"new_fingerprint"`
	OldAuthorityID           string `json:"old_authority_id"`
	NewAuthorityID           string `json:"new_authority_id"`
	JobID                    string `json:"job_id"`
	ReceiptID                string `json:"receipt_id"`
	ReceiptStatement         string `json:"receipt_statement"`
	ReceiptSignature         string `json:"receipt_signature"`
	ReceiptSignerFingerprint string `json:"receipt_signer_fingerprint"`
}

// ValidateCertificateReprotectionCutover checks that the server-verified
// statement embedded in the source event names this tenant, agent job,
// attempt, verified outcome and served successor leaf. Signature verification
// against the authenticated agent certificate happens before event append.
func ValidateCertificateReprotectionCutover(tenantID string, cut CertificateReprotectionCutover) error {
	if tenantID == "" || cut.IdentityID == "" || cut.TargetID == "" || cut.OldCertificateID == "" ||
		cut.NewCertificateID == "" || cut.OldFingerprint == "" || cut.NewFingerprint == "" ||
		cut.OldAuthorityID == "" || cut.NewAuthorityID == "" || cut.OldAuthorityID == cut.NewAuthorityID ||
		cut.JobID == "" || cut.ReceiptID == "" || cut.OldCertificateID == cut.NewCertificateID ||
		cut.OldFingerprint == cut.NewFingerprint || cut.ReceiptSignerFingerprint == "" {
		return ErrCertificateReprotectionConflict
	}
	var agentJobID int64
	var attempt int
	if _, err := fmt.Sscanf(cut.ReceiptID, "agent-job:%d:%d:verified", &agentJobID, &attempt); err != nil ||
		agentJobID <= 0 || attempt <= 0 || cut.ReceiptID != fmt.Sprintf("agent-job:%d:%d:verified", agentJobID, attempt) {
		return ErrCertificateReprotectionConflict
	}
	sig, err := base64.StdEncoding.DecodeString(cut.ReceiptSignature)
	if err != nil || len(sig) == 0 {
		return ErrCertificateReprotectionConflict
	}
	lines := strings.Split(cut.ReceiptStatement, "\n")
	if len(lines) != 15 || lines[0] != "trstctl-agent-job-receipt/v2" || lines[14] != "" ||
		lines[1] != "tenant="+tenantID || !strings.HasPrefix(lines[2], "agent=") || lines[2] == "agent=" ||
		lines[3] != "job="+strconv.FormatInt(agentJobID, 10) || lines[4] != "attempt="+strconv.Itoa(attempt) ||
		lines[5] != "outcome=verified" || !strings.HasPrefix(lines[6], "evidence=") || lines[6] == "evidence=" ||
		!strings.HasPrefix(lines[7], "detail=") ||
		lines[8] != "credential_fingerprint="+cut.NewFingerprint ||
		!strings.HasPrefix(lines[9], "key_origin=") || lines[9] == "key_origin=" ||
		!strings.HasPrefix(lines[10], "key_storage=") || lines[10] == "key_storage=" ||
		!strings.HasPrefix(lines[11], "key_exportable=") || lines[11] == "key_exportable=" ||
		!strings.HasPrefix(lines[12], "key_generated_by=") || lines[12] == "key_generated_by=" ||
		!strings.HasPrefix(lines[13], "issued_at=") {
		return ErrCertificateReprotectionConflict
	}
	issuedAt, err := strconv.ParseInt(strings.TrimPrefix(lines[13], "issued_at="), 10, 64)
	if err != nil || issuedAt <= 0 {
		return ErrCertificateReprotectionConflict
	}
	return nil
}

// ApplyCertificateReprotectionCutoverTx is called only by the projector. One
// source event changes the old certificate, successor link and identity's CA
// selection in one tenant transaction. A replay of the same event is a no-op;
// a conflicting successor or changed identity fails closed.
func (s *Store) ApplyCertificateReprotectionCutoverTx(ctx context.Context, tx pgx.Tx,
	tenantID string, cut CertificateReprotectionCutover, at time.Time) error {
	if err := ValidateCertificateReprotectionCutover(tenantID, cut); err != nil {
		return err
	}
	var oldStatus, oldFingerprint string
	if err := tx.QueryRow(ctx, `SELECT status, fingerprint FROM certificates
		WHERE tenant_id=$1 AND id=$2::uuid FOR UPDATE`, tenantID, cut.OldCertificateID).
		Scan(&oldStatus, &oldFingerprint); err != nil {
		return err
	}
	var newStatus, newFingerprint, replacesID string
	if err := tx.QueryRow(ctx, `SELECT status, fingerprint, COALESCE(replaces_id::text,'') FROM certificates
		WHERE tenant_id=$1 AND id=$2::uuid FOR UPDATE`, tenantID, cut.NewCertificateID).
		Scan(&newStatus, &newFingerprint, &replacesID); err != nil {
		return err
	}
	var identityStatus, targetID, source, authorityID string
	if err := tx.QueryRow(ctx, `SELECT status, COALESCE(attributes->>'deployment_target_id',''),
		COALESCE(attributes->>'issuing_authority_source',''), COALESCE(attributes->>'issuing_authority_id','')
		FROM identities WHERE tenant_id=$1 AND id=$2::uuid FOR UPDATE`, tenantID, cut.IdentityID).
		Scan(&identityStatus, &targetID, &source, &authorityID); err != nil {
		return err
	}
	if oldFingerprint != cut.OldFingerprint || newFingerprint != cut.NewFingerprint ||
		newStatus != "active" || targetID != cut.TargetID || source != "private" ||
		identityStatus != "deployed" {
		return ErrCertificateReprotectionConflict
	}
	if oldStatus == "superseded" && replacesID == cut.OldCertificateID && authorityID == cut.NewAuthorityID {
		return s.RepairCertificateReprotectionIssuerNameTx(ctx, tx, tenantID, cut)
	}
	if oldStatus != "active" || replacesID != "" || authorityID != cut.OldAuthorityID {
		return ErrCertificateReprotectionConflict
	}
	var successorName string
	if err := tx.QueryRow(ctx, `SELECT common_name FROM ca_authorities
		WHERE tenant_id=$1 AND id=$2::uuid`, tenantID, cut.NewAuthorityID).Scan(&successorName); err != nil {
		return fmt.Errorf("store: resolve successor CA name: %w", err)
	}
	if tag, err := tx.Exec(ctx, `UPDATE certificates SET status='superseded', renewed_at=$4
		WHERE tenant_id=$1 AND id=$2::uuid AND fingerprint=$3 AND status='active'`,
		tenantID, cut.OldCertificateID, cut.OldFingerprint, at.UTC()); err != nil || tag.RowsAffected() != 1 {
		return reprotectionWriteResult("predecessor", tag.RowsAffected(), err)
	}
	if tag, err := tx.Exec(ctx, `UPDATE certificates SET replaces_id=$4::uuid
		WHERE tenant_id=$1 AND id=$2::uuid AND fingerprint=$3 AND replaces_id IS NULL AND status='active'`,
		tenantID, cut.NewCertificateID, cut.NewFingerprint, cut.OldCertificateID); err != nil || tag.RowsAffected() != 1 {
		return reprotectionWriteResult("successor", tag.RowsAffected(), err)
	}
	if tag, err := tx.Exec(ctx, `UPDATE identities SET attributes=attributes ||
		jsonb_build_object('issuing_authority_id',$3::text,'issuing_authority_name',$6::text)
		WHERE tenant_id=$1 AND id=$2::uuid AND status='deployed'
		AND attributes->>'issuing_authority_source'='private' AND attributes->>'issuing_authority_id'=$4
		AND attributes->>'deployment_target_id'=$5`,
		tenantID, cut.IdentityID, cut.NewAuthorityID, cut.OldAuthorityID, cut.TargetID, successorName); err != nil || tag.RowsAffected() != 1 {
		return reprotectionWriteResult("identity authority", tag.RowsAffected(), err)
	}
	return nil
}

// RepairCertificateReprotectionIssuerNameTx repairs only a derived identity
// label from an already retained cutover. A later CA change or tenant offboard
// does not match the event's successor ID, so warm recovery cannot resurrect it.
func (s *Store) RepairCertificateReprotectionIssuerNameTx(ctx context.Context, tx pgx.Tx,
	tenantID string, cut CertificateReprotectionCutover) error {
	if tenantID == "" || cut.IdentityID == "" || cut.NewAuthorityID == "" {
		return ErrCertificateReprotectionConflict
	}
	var successorName string
	if err := tx.QueryRow(ctx, `SELECT common_name FROM ca_authorities
		WHERE tenant_id=$1 AND id=$2::uuid`, tenantID, cut.NewAuthorityID).Scan(&successorName); err != nil {
		return fmt.Errorf("store: resolve re-protection successor name: %w", err)
	}
	_, err := tx.Exec(ctx, `UPDATE identities SET attributes=attributes ||
		jsonb_build_object('issuing_authority_name',$4::text)
		WHERE tenant_id=$1 AND id=$2::uuid
		AND attributes->>'issuing_authority_source'='private'
		AND attributes->>'issuing_authority_id'=$3
		AND attributes->>'issuing_authority_name' IS DISTINCT FROM $4`,
		tenantID, cut.IdentityID, cut.NewAuthorityID, successorName)
	return err
}

func reprotectionWriteResult(name string, rows int64, err error) error {
	if err != nil {
		return fmt.Errorf("store: project CA re-protection %s: %w", name, err)
	}
	return fmt.Errorf("%w: %s matched %d rows", ErrCertificateReprotectionConflict, name, rows)
}
