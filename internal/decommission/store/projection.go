// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/decommission/depstate"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/projections"
	corestore "trstctl.com/trstctl/internal/store"
)

// DependencyProjection maintains the bounded, indexed retirement checklist from
// the same immutable issuance and disposition events that the signer gate folds.
// Its writes join the core rebuild transaction and can be replayed after a crash.
type DependencyProjection struct{ store *corestore.Store }

func NewDependencyProjection(store *corestore.Store) *DependencyProjection {
	return &DependencyProjection{store: store}
}

func (p *DependencyProjection) Name() string { return "vdec.dependencies" }

func (p *DependencyProjection) Reset(ctx context.Context) error {
	if p == nil || p.store == nil {
		return fmt.Errorf("vdec dependencies: store is not configured")
	}
	tx, err := p.store.SystemPool().Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := p.ResetTx(ctx, tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (p *DependencyProjection) ResetTx(ctx context.Context, tx pgx.Tx) error {
	if p == nil || p.store == nil || tx == nil {
		return fmt.Errorf("vdec dependencies: store transaction is not configured")
	}
	//trstctl:system-query — cross-tenant system reset clears only derived VDEC revocations; retained events replay under each tenant's RLS context.
	if _, err := tx.Exec(ctx, `DELETE FROM decommission_revocations`); err != nil {
		return fmt.Errorf("vdec dependencies: reset revocations: %w", err)
	}
	//trstctl:system-query — cross-tenant system reset clears only derived VDEC completions; retained events replay under each tenant's RLS context.
	if _, err := tx.Exec(ctx, `DELETE FROM decommission_completion_events`); err != nil {
		return fmt.Errorf("vdec dependencies: reset completions: %w", err)
	}
	//trstctl:system-query — cross-tenant system reset clears only derived VDEC dependents; retained events replay under each tenant's RLS context.
	if _, err := tx.Exec(ctx, `DELETE FROM decommission_dependents`); err != nil {
		return fmt.Errorf("vdec dependencies: reset dependents: %w", err)
	}
	//trstctl:system-query — cross-tenant system reset clears only derived VDEC key states; retained events replay under each tenant's RLS context.
	if _, err := tx.Exec(ctx, `DELETE FROM decommission_key_states`); err != nil {
		return fmt.Errorf("vdec dependencies: reset keys: %w", err)
	}
	return nil
}

func (p *DependencyProjection) Apply(ctx context.Context, ev eventspec.Event) error {
	if p == nil || p.store == nil {
		return fmt.Errorf("vdec dependencies: store is not configured")
	}
	if !isDependencyEvent(ev.Type) {
		return nil
	}
	return p.store.WithTenant(ctx, ev.TenantID, func(tx pgx.Tx) error {
		return p.ApplyTx(ctx, tx, ev)
	})
}

func isDependencyEvent(eventType string) bool {
	switch eventType {
	case depstate.TypeDependencyRegistered, depstate.TypeDependencyReleased,
		depstate.TypeDependencyErasureDesignated, depstate.TypeReprotectionCompleted,
		depstate.TypeRevocationCompleted,
		projections.EventCAEndEntityIssued, projections.EventCAIssuedCertificate,
		projections.EventCAIntermediateCSRIssued, projections.EventCAIntermediateCreated,
		projections.EventCAAuthorityImported, projections.EventCAAuthorityRekeyed,
		projections.EventCACrossSigned, projections.EventTenantOffboarded:
		return true
	default:
		return false
	}
}

func (p *DependencyProjection) ApplyTx(ctx context.Context, tx pgx.Tx, ev eventspec.Event) error {
	if p == nil || p.store == nil || tx == nil {
		return fmt.Errorf("vdec dependencies: store transaction is not configured")
	}
	if !isDependencyEvent(ev.Type) {
		return nil
	}
	if ev.Type == projections.EventTenantOffboarded {
		if err := p.store.SetTenantGUCTx(ctx, tx, ev.TenantID); err != nil {
			return err
		}
		return clearTenant(ctx, tx)
	}
	registrations, err := depstate.CARegistrations(ev)
	if err != nil {
		return err
	}
	payload, err := depstate.Decode(ev)
	if err != nil {
		return err
	}
	if len(registrations) == 0 {
		if _, unknown := payload.(depstate.Unknown); unknown {
			return nil
		}
	}
	if ev.Sequence > math.MaxInt64 {
		return fmt.Errorf("vdec dependencies: event position exceeds PostgreSQL bigint")
	}
	position := int64(ev.Sequence)
	if position == 0 {
		position = 1 // Synthetic direct-projection tests have no durable sequence.
	}
	if err := p.store.SetTenantGUCTx(ctx, tx, ev.TenantID); err != nil {
		return err
	}
	for _, registration := range registrations {
		if err := upsertDependencyChange(ctx, tx, ev.TenantID, registration.KeyID, registration.Dependent, position, dependencyRegister); err != nil {
			return err
		}
	}
	switch v := payload.(type) {
	case depstate.DependencyRegisteredV1:
		return p.applyBoundChange(ctx, tx, ev.TenantID, v.TenantID, v.KeyID, v.Dependent, position, dependencyRegister)
	case depstate.DependencyReleasedV1:
		return p.applyBoundChange(ctx, tx, ev.TenantID, v.TenantID, v.KeyID, v.Dependent, position, dependencyRelease)
	case depstate.DependencyReleasedV2:
		return p.applySourceBoundRelease(ctx, tx, ev.TenantID, v, position, ev.Time)
	case depstate.DependencyErasureDesignatedV1:
		return p.applyBoundChange(ctx, tx, ev.TenantID, v.TenantID, v.KeyID, v.Dependent, position, dependencyErasure)
	case depstate.ReprotectionCompletedV1:
		if err := p.applyBoundChange(ctx, tx, ev.TenantID, v.TenantID, v.KeyID, v.Dependent, position, dependencyAccount); err != nil {
			return err
		}
	case depstate.RevocationCompletedV1:
		if err := p.applyBoundChange(ctx, tx, ev.TenantID, v.TenantID, v.KeyID, v.Dependent, position, dependencyAccount); err != nil {
			return err
		}
	default:
		return nil
	}
	return insertCompletionFromEvent(ctx, tx, ev.TenantID, ev, uint64(position))
}

// A v2 release cannot create a placeholder dependent. The read model must see
// the original issued leaf, its exact event ordinal, and its public DER before
// it accounts for the release. The isolated signer's fold independently checks
// the immutable mint event, so both views fail closed if source proof drifts.
func (p *DependencyProjection) applySourceBoundRelease(ctx context.Context, tx pgx.Tx, envelopeTenant string, v depstate.DependencyReleasedV2, position int64, completedAt time.Time) error {
	if envelopeTenant == "" || v.TenantID != envelopeTenant || v.KeyID == "" ||
		v.Dependent.Class != depstate.DependentCredential || v.Dependent.ID == "" ||
		v.SourceEventID == "" || v.SourceSequence == 0 || v.SourceSequence > math.MaxInt64 ||
		v.CertificateSHA256 == "" || v.Serial == "" || v.CeremonyID == "" ||
		v.Actor == "" || strings.TrimSpace(v.Reason) == "" || !v.RiskAccepted || len(v.ApprovalEventIDs) < 2 {
		return fmt.Errorf("vdec dependencies: source-bound release lacks exact public source, approval, or risk evidence")
	}
	sourcePosition := int64(v.SourceSequence) // #nosec G115 -- rejected values above MaxInt64 immediately above.
	if sourcePosition >= position {
		return fmt.Errorf("vdec dependencies: source-bound release precedes its managed CA mint")
	}
	var registered int64
	var accounted, released *int64
	if err := tx.QueryRow(ctx, `SELECT registered_ordinal, accounted_ordinal, released_ordinal
		FROM decommission_dependents WHERE tenant_id=$1 AND key_id=$2 AND dependent_class=$3 AND dependent_id=$4 FOR UPDATE`,
		envelopeTenant, v.KeyID, string(v.Dependent.Class), v.Dependent.ID).Scan(&registered, &accounted, &released); err != nil {
		return fmt.Errorf("vdec dependencies: source-bound release has no registered dependent: %w", err)
	}
	if registered <= 0 || uint64(registered) != v.SourceSequence ||
		(accounted != nil && (*accounted != position || released == nil || *released != position)) {
		return fmt.Errorf("vdec dependencies: source-bound release source position or outstanding state changed")
	}
	var issuanceEventID, fingerprint, serial string
	var der []byte
	if err := tx.QueryRow(ctx, `SELECT issuance_event_id,fingerprint,serial,certificate_der
		FROM certificates WHERE tenant_id=$1 AND id=$2`, envelopeTenant, v.Dependent.ID).
		Scan(&issuanceEventID, &fingerprint, &serial, &der); err != nil {
		return fmt.Errorf("vdec dependencies: source-bound release has no exact inventory leaf: %w", err)
	}
	if issuanceEventID != v.SourceEventID || serial != v.Serial ||
		!strings.EqualFold(fingerprint, v.CertificateSHA256) || crypto.SHA256Hex(der) != v.CertificateSHA256 {
		return fmt.Errorf("vdec dependencies: source-bound release differs from issued public certificate")
	}
	if err := validateSourceBoundReleaseApprovals(ctx, tx, envelopeTenant, v); err != nil {
		return err
	}
	if err := upsertDependencyChange(ctx, tx, envelopeTenant, v.KeyID, v.Dependent, position, dependencyRelease); err != nil {
		return err
	}
	return p.store.ApplyKeyCeremonyCompletedTx(ctx, tx, envelopeTenant, v.CeremonyID, completedAt)
}

func validateSourceBoundReleaseApprovals(ctx context.Context, tx pgx.Tx, tenantID string, v depstate.DependencyReleasedV2) error {
	var purpose, status, opener string
	var threshold int
	if err := tx.QueryRow(ctx, `SELECT purpose,status,COALESCE(opener,''),threshold
		FROM ca_key_ceremonies WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenantID, v.CeremonyID).
		Scan(&purpose, &status, &opener, &threshold); err != nil {
		return fmt.Errorf("vdec dependencies: source-bound release ceremony missing: %w", err)
	}
	if purpose != depstate.ReleasePurposeV2(v) || (status != "pending" && status != "completed") || threshold < 2 {
		return fmt.Errorf("vdec dependencies: source-bound release differs from the reviewed ceremony")
	}
	rows, err := tx.Query(ctx, `SELECT custodian,approval_event_id FROM ca_ceremony_approvals
		WHERE tenant_id=$1 AND ceremony_id=$2 AND approval_event_id IS NOT NULL ORDER BY custodian`, tenantID, v.CeremonyID)
	if err != nil {
		return err
	}
	var approved []string
	for rows.Next() {
		var custodian, eventID string
		if err := rows.Scan(&custodian, &eventID); err != nil {
			rows.Close()
			return err
		}
		if custodian == "" || custodian == opener || eventID == "" {
			rows.Close()
			return fmt.Errorf("vdec dependencies: release approval is not a distinct custodian event")
		}
		approved = append(approved, eventID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	claimed := append([]string(nil), v.ApprovalEventIDs...)
	slices.Sort(approved)
	slices.Sort(claimed)
	if len(approved) < threshold || !slices.Equal(approved, claimed) {
		return fmt.Errorf("vdec dependencies: release approval events differ from the ceremony quorum")
	}
	return nil
}

func (p *DependencyProjection) ProjectsTenantLifecycle() {}

func (p *DependencyProjection) ReplayTenantLifecycleTx(ctx context.Context, tx pgx.Tx, ev eventspec.Event) error {
	return p.ApplyTx(ctx, tx, ev)
}

func (p *DependencyProjection) applyBoundChange(ctx context.Context, tx pgx.Tx, envelopeTenant, payloadTenant, keyID string, dep depstate.Dependent, position int64, action dependencyAction) error {
	if envelopeTenant == "" || envelopeTenant != payloadTenant {
		return fmt.Errorf("vdec dependencies: event tenant does not match dependency payload")
	}
	return upsertDependencyChange(ctx, tx, envelopeTenant, keyID, dep, position, action)
}

type dependencyAction uint8

const (
	dependencyRegister dependencyAction = iota
	dependencyRelease
	dependencyErasure
	dependencyAccount
)

func upsertDependencyChange(ctx context.Context, tx pgx.Tx, tenantID, keyID string, dep depstate.Dependent, position int64, action dependencyAction) error {
	if tenantID == "" || keyID == "" || dep.Class == "" || dep.ID == "" || position <= 0 {
		return fmt.Errorf("vdec dependencies: incomplete dependency identity")
	}
	if _, err := tx.Exec(ctx, `INSERT INTO decommission_key_states (tenant_id, key_id, ledger_position)
		VALUES (current_setting('trstctl.tenant_id')::uuid, $1, $2)
		ON CONFLICT (tenant_id, key_id) DO UPDATE
		SET ledger_position = GREATEST(decommission_key_states.ledger_position, EXCLUDED.ledger_position), updated_at = now()`, keyID, position); err != nil {
		return fmt.Errorf("vdec dependencies: project key state: %w", err)
	}
	registered, accounted, released, erased := int64(0), int64(0), int64(0), int64(0)
	switch action {
	case dependencyRegister:
		registered = position
	case dependencyRelease:
		accounted, released = position, position
	case dependencyErasure:
		registered, accounted, erased = position, position, position
	case dependencyAccount:
		accounted = position
	default:
		return fmt.Errorf("vdec dependencies: unknown change")
	}
	_, err := tx.Exec(ctx, `INSERT INTO decommission_dependents
		(tenant_id, key_id, dependent_class, dependent_id, registered_ordinal,
		 accounted_ordinal, released_ordinal, erasure_ordinal, ledger_position)
		VALUES (current_setting('trstctl.tenant_id')::uuid, $1, $2, $3, $4,
		 NULLIF($5::bigint, 0), NULLIF($6::bigint, 0), NULLIF($7::bigint, 0), $8)
		ON CONFLICT (tenant_id, key_id, dependent_class, dependent_id) DO UPDATE SET
		 registered_ordinal = CASE WHEN EXCLUDED.registered_ordinal = 0 THEN decommission_dependents.registered_ordinal
		                           WHEN decommission_dependents.registered_ordinal = 0 THEN EXCLUDED.registered_ordinal
		                           ELSE LEAST(decommission_dependents.registered_ordinal, EXCLUDED.registered_ordinal) END,
		 accounted_ordinal = LEAST(decommission_dependents.accounted_ordinal, EXCLUDED.accounted_ordinal),
		 released_ordinal = LEAST(decommission_dependents.released_ordinal, EXCLUDED.released_ordinal),
		 erasure_ordinal = LEAST(decommission_dependents.erasure_ordinal, EXCLUDED.erasure_ordinal),
		 ledger_position = GREATEST(decommission_dependents.ledger_position, EXCLUDED.ledger_position)`,
		keyID, string(dep.Class), dep.ID, registered, accounted, released, erased, position)
	if err != nil {
		return fmt.Errorf("vdec dependencies: project dependent %s/%s: %w", dep.Class, dep.ID, err)
	}
	return nil
}
