// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

var ErrCertificateRevocationInvalid = errors.New("orchestrator: invalid certificate revocation request")
var ErrCertificateRevocationUnsupported = errors.New(projections.CertificateRevocationUnsupportedReason)

// ExternalCertificateAuthorityPrefix distinguishes a verified external registry
// binding from the UUID of a locally served CA ledger. It is never tenant input.
const ExternalCertificateAuthorityPrefix = "external:"

// CertificateRevocationChecks are separate: denied policy aborts the entire
// batch, while an unsupported issuer produces an explicit per-certificate error.
// Authority must verify actual certificate bytes/signature and issuer ledger;
// matching an issuer name, owner or serial alone is insufficient.
type CertificateRevocationChecks struct {
	Authorize func(context.Context, store.Certificate) error
	Authority func(context.Context, store.Certificate) (string, error)
}

func (o *Orchestrator) BulkRevokeCertificates(ctx context.Context, tenantID, commandKey, requestBinding string, ids []string, reason string, checks CertificateRevocationChecks) (BulkRevokeResult, error) {
	ctx, releaseTenant, admissionErr := o.beginTenantCommand(ctx, tenantID)
	if admissionErr != nil {
		return BulkRevokeResult{}, admissionErr
	}
	defer releaseTenant()

	if commandKey == "" || len(requestBinding) != 64 || len(ids) == 0 || len(ids) > projections.MaxCertificateRevocationBatch ||
		!crypto.IsValidRevocationReason(reason) || reason == "removeFromCRL" || checks.Authorize == nil || checks.Authority == nil {
		return BulkRevokeResult{}, ErrCertificateRevocationInvalid
	}
	selected := make([]string, 0, len(ids))
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		parsed, err := uuid.Parse(id)
		if err != nil {
			return BulkRevokeResult{}, ErrCertificateRevocationInvalid
		}
		id = parsed.String()
		if !seen[id] {
			selected = append(selected, id)
			seen[id] = true
		}
	}
	sort.Strings(selected)
	var batch projections.CertificateRevocationBatchApplied
	// Preserve privacy -> history -> lifecycle -> certificate metadata -> rows.
	// Holding a tenant row before a history read can deadlock a rewrite/rebuild.
	err := o.store.WithPrivacyRecoveryBarrier(ctx, tenantID, "certificate revocation", func(ctx context.Context) error {
		return o.log.WithHistoryRead(ctx, func(ctx context.Context) error {
			return o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
				tenant, err := o.store.LockLiveTenantRegistrationSnapshotTx(ctx, tx, tenantID)
				if err != nil {
					return err
				}
				registration, err := tenantRegistrationAtSequence(ctx, o.log, tenantID, tenant.EventSeq)
				if err != nil {
					return err
				}
				if err := projections.ValidateSchemaVersion(registration); err != nil {
					return err
				}
				if err := validateTenantRegistrationPayload(registration.Data, tenant.Name); err != nil {
					return err
				}
				coordinates, err := json.Marshal(struct {
					Domain               string
					TenantID             string
					RegistrationEventID  string
					RegistrationSequence uint64
					RegisteredAt         string
					CommandKey           string
				}{"trstctl.certificate-revocation.v1", tenantID, registration.ID, tenant.EventSeq, tenant.CreatedAt.UTC().Format(time.RFC3339Nano), commandKey})
				if err != nil {
					return err
				}
				eventID := "certificate-revocation:" + crypto.SHA256Hex(coordinates)
				// Recording holds metadata before certificate rows. Take it before
				// our command/row locks too, including retained-result projection.
				if err := o.store.LockCertificateMetadataOrderTx(ctx, tx, tenantID); err != nil {
					return err
				}
				if err := o.store.LockCertificateRevocationCommandTx(ctx, tx, tenantID, eventID); err != nil {
					return err
				}
				retained, found, err := o.log.EventByID(ctx, eventID)
				if err != nil {
					return err
				}
				if found {
					if retained.TenantID != tenantID || retained.Type != projections.EventCertificateRevocationBatchApplied ||
						json.Unmarshal(retained.Data, &batch) != nil || batch.RequestBinding != requestBinding || batch.Reason != reason ||
						!sameCertificateRevocationSelection(batch, selected) {
						return fmt.Errorf("%w: certificate revocation command already has a different meaning", store.ErrIdempotencyConflict)
					}
					return o.proj.ApplyTx(ctx, tx, retained)
				}
				batch = projections.CertificateRevocationBatchApplied{RequestBinding: requestBinding, Reason: reason,
					Items: make([]projections.CertificateRevocationItem, 0, len(selected))}
				certificates := make([]store.Certificate, 0, len(selected))
				for _, id := range selected {
					certificate, err := o.store.CertificateForRevocationTx(ctx, tx, tenantID, id)
					if store.IsNotFound(err) {
						batch.Items = append(batch.Items, projections.CertificateRevocationItem{ID: id, Status: "failed", Error: "not found"})
						continue
					}
					if err != nil {
						return err
					}
					if err := checks.Authorize(ctx, certificate); err != nil {
						return err
					}
					certificates = append(certificates, certificate)
				}
				for _, certificate := range certificates {
					item, err := o.exactCertificateRevocationItem(ctx, tx, certificate, checks)
					if err != nil {
						return err
					}
					batch.Items = append(batch.Items, item)
				}
				if err := projections.ValidateCertificateRevocationBatch(batch); err != nil {
					return err
				}
				payload, err := json.Marshal(batch)
				if err != nil {
					return err
				}
				version := 1
				for _, item := range batch.Items {
					if item.Status == "queued" {
						version = projections.CertificateExternalRevocationSchemaVersion
					}
				}
				event, err := o.log.Append(ctx, events.Event{ID: eventID, Type: projections.EventCertificateRevocationBatchApplied, TenantID: tenantID, Data: payload, SchemaVersion: version})
				if err != nil {
					return err
				}
				if event.Type != projections.EventCertificateRevocationBatchApplied || event.TenantID != tenantID || string(event.Data) != string(payload) {
					return fmt.Errorf("%w: certificate revocation append resolved a different command", store.ErrIdempotencyConflict)
				}
				return o.proj.ApplyTx(ctx, tx, event)
			})
		})
	})
	if err != nil {
		return BulkRevokeResult{}, err
	}
	result := BulkRevokeResult{Items: make([]BulkRevokeItem, 0, len(batch.Items))}
	for _, item := range batch.Items {
		if item.Matched {
			result.TotalMatched++
		}
		switch item.Status {
		case "queued":
			result.TotalQueued++
		case "revoked":
			result.TotalRevoked++
		case "skipped":
			result.TotalSkipped++
		case "failed":
			result.TotalFailed++
		}
		result.Items = append(result.Items, BulkRevokeItem{ID: item.ID, Status: item.Status, Error: item.Error})
	}
	return result, nil
}

func (o *Orchestrator) exactCertificateRevocationItem(ctx context.Context, tx pgx.Tx, certificate store.Certificate, checks CertificateRevocationChecks) (projections.CertificateRevocationItem, error) {
	item := projections.CertificateRevocationItem{ID: certificate.ID, Matched: true}
	caID, err := checks.Authority(ctx, certificate)
	if errors.Is(err, ErrCertificateRevocationUnsupported) {
		item.Status, item.Error = "failed", ErrCertificateRevocationUnsupported.Error()
		return item, nil
	}
	if err != nil {
		return item, err
	}
	if caID == "" {
		return item, errors.New("orchestrator: certificate revocation resolved an empty authority")
	}
	if externalID, external := strings.CutPrefix(caID, ExternalCertificateAuthorityPrefix); external {
		item.Status, item.ExternalCAID = "queued", externalID
		item.Fingerprint, item.Serial = certificate.Fingerprint, certificate.Serial
		return item, nil
	}
	issuer, err := o.store.IssuedCertificateForRevocationTx(ctx, tx, certificate.TenantID, caID, certificate.Serial)
	if err != nil {
		return item, err
	}
	if certificate.Status == "revoked" && certificate.RevokedAt != nil && issuer.Revoked() &&
		certificate.RevokedAt.Equal(*issuer.RevokedAt) && crypto.IsValidRevocationReason(certificate.RevocationReason) &&
		crypto.CRLReasonCode(crypto.RevocationReason(certificate.RevocationReason)) == issuer.ReasonCode {
		item.Status, item.Error = "skipped", "already revoked"
		return item, nil
	}
	item.Status, item.CAID, item.Fingerprint, item.Serial = "revoked", caID, certificate.Fingerprint, certificate.Serial
	return item, nil
}

func sameCertificateRevocationSelection(batch projections.CertificateRevocationBatchApplied, selected []string) bool {
	retained := make([]string, 0, len(batch.Items))
	for _, item := range batch.Items {
		retained = append(retained, item.ID)
	}
	sort.Strings(retained)
	if len(retained) != len(selected) {
		return false
	}
	for i := range selected {
		if retained[i] != selected[i] {
			return false
		}
	}
	return true
}
