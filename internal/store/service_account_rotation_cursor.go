// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/servicedependents"
)

var ErrServiceDependentCursorAdvanceRequired = errors.New("store: exact manifest cursor transition is pending")

// This resolver is a projection validator. Native dispatch additionally reads
// the matching immutable page sources and refuses any changed SQL authority.
func (s *Store) ServiceDependentManifestResolverTx(ctx context.Context, tx pgx.Tx, tenantID string, intent servicedependents.RotationIntent) (servicedependents.RotationManifestResolver, error) {
	var none servicedependents.RotationManifestResolver
	state, err := s.GetServiceDependentManifestTx(ctx, tx, tenantID, intent.Plan.ID, false)
	if err != nil {
		return none, err
	}
	if state.Seal == nil {
		return none, ErrServiceDependentManifestEvidence
	}
	exact, err := servicedependents.NewRotationIntentFromManifest(state.Header, *state.Seal)
	if err != nil {
		return none, err
	}
	want, err := exact.Digest()
	if err != nil {
		return none, err
	}
	got, err := intent.Digest()
	if err != nil || got != want {
		return none, ErrServiceDependentManifestEvidence
	}
	return servicedependents.RotationManifestResolver{Header: state.Header, Seal: *state.Seal, Page: func(number int64) (servicedependents.RotationManifestPage, error) {
		return s.getServiceDependentManifestPageTx(ctx, tx, tenantID, state.Header, number)
	}}, nil
}
func (s *Store) validateServiceDependentManifestIntentTx(ctx context.Context, tx pgx.Tx, tenantID string, intent servicedependents.RotationIntent, current bool) error {
	r, err := s.ServiceDependentManifestResolverTx(ctx, tx, tenantID, intent)
	if err != nil {
		return err
	}
	seal, err := s.ValidateServiceDependentManifestCompletenessTx(ctx, tx, tenantID, intent.Plan.ID, intent.Plan.CreatedAt, current)
	if err != nil {
		return err
	}
	if seal.Digest != r.Seal.Digest {
		return ErrServiceDependentManifestEvidence
	}
	return nil
}
func (s *Store) ServiceDependentManifestInputTx(ctx context.Context, tx pgx.Tx, tenantID string, host servicedependents.RotationManifestHost) (servicedependents.RotationHostInput, error) {
	var none servicedependents.RotationHostInput
	scan, err := scanServiceDependentScan(tx.QueryRow(ctx, "SELECT "+serviceDependentScanColumns+" FROM service_account_host_scans WHERE tenant_id=$1 AND id=$2", tenantID, host.InventoryRunID))
	if err != nil {
		return none, err
	}
	if scan.Status != "complete" || scan.Report == nil || scan.Intent.Binding != host.Binding || scan.ReportDigest != host.InventoryDigest {
		return none, ErrServiceDependentManifestEvidence
	}
	return servicedependents.RotationHostInput{Binding: scan.Intent.Binding, Inventory: *scan.Report, InventoryDigest: scan.ReportDigest}, nil
}
func (s *Store) nextServiceDependentManifestStepTx(ctx context.Context, tx pgx.Tx, parent ServiceDependentRotation, preflight bool) (*servicedependents.RotationStep, error) {
	if parent.ManifestCursor == nil {
		return nil, ErrServiceDependentManifestEvidence
	}
	cursor := *parent.ManifestCursor
	if cursor.Position.Stage == servicedependents.ManifestComplete || preflight && cursor.Position.Stage != servicedependents.Preflight {
		return nil, nil
	}
	r, err := s.ServiceDependentManifestResolverTx(ctx, tx, parent.TenantID, parent.Intent)
	if err != nil {
		return nil, err
	}
	entry, err := r.Entry(cursor)
	if err != nil {
		return nil, err
	}
	input, err := s.ServiceDependentManifestInputTx(ctx, tx, parent.TenantID, entry.Host)
	if err != nil {
		return nil, err
	}
	step, applicable, err := r.Step(parent.Intent, cursor, input)
	if err != nil {
		return nil, err
	}
	if !applicable {
		return nil, ErrServiceDependentCursorAdvanceRequired
	}
	saved, err := s.EffectiveServiceDependentStepTx(ctx, tx, parent.TenantID, parent.ID, step.ID)
	if errors.Is(err, ErrServiceDependentStepNotFound) {
		return &step, nil
	}
	if err != nil {
		return nil, err
	}
	if saved.Status == "failed" || saved.Status == "uncertain" {
		return &saved.Intent, ErrServiceDependentStepFailed
	}
	if saved.Status == "succeeded" {
		return &saved.Intent, ErrServiceDependentCursorAdvanceRequired
	}
	return &saved.Intent, nil
}
func (s *Store) ApplyServiceDependentCursorAdvanceTx(ctx context.Context, tx pgx.Tx, tenantID, sourceID string, sequence uint64, a servicedependents.ManifestCursorAdvance) error {
	if sourceID != servicedependents.ManifestCursorAdvanceSourceID(tenantID, a.RotationID, a.PreviousSourceID) || sequence == 0 || sequence > uint64(1<<63-1) {
		return ErrIdempotencyConflict
	}
	if _, err := tx.Exec(ctx, `SELECT id FROM service_account_rotations WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenantID, a.RotationID); err != nil {
		return err
	}
	parent, err := s.GetServiceDependentRotationTx(ctx, tx, tenantID, a.RotationID)
	if err != nil {
		return err
	}
	if err := a.Validate(parent.Intent); err != nil {
		return err
	}
	r, err := s.ServiceDependentManifestResolverTx(ctx, tx, tenantID, parent.Intent)
	if err != nil {
		return err
	}
	next, err := r.Advance(a.From)
	if err != nil || next != a.To {
		return ErrServiceDependentManifestEvidence
	}
	// The global source sequence makes repeated historical projection a no-op,
	// including a forward source replayed after inverse selection. It cannot rewind.
	if sequence <= parent.ManifestCursorSequence {
		return nil
	}
	if parent.ManifestCursor == nil || *parent.ManifestCursor != a.From || parent.ManifestCursorSourceID != a.PreviousSourceID || parent.Direction != a.From.Direction {
		return ErrIdempotencyConflict
	}
	entry, err := r.Entry(a.From)
	if err != nil {
		return err
	}
	input, err := s.ServiceDependentManifestInputTx(ctx, tx, tenantID, entry.Host)
	if err != nil {
		return err
	}
	step, applicable, err := r.Step(parent.Intent, a.From, input)
	if err != nil {
		return err
	}
	if applicable {
		saved, err := s.EffectiveServiceDependentStepTx(ctx, tx, tenantID, parent.ID, step.ID)
		if err != nil {
			return err
		}
		raw, err := json.Marshal(saved.Report)
		if err != nil {
			return err
		}
		if a.Cause != servicedependents.ManifestNativeSucceeded || saved.Status != "succeeded" || saved.Report == nil || saved.Intent.ID != a.StepID || saved.Intent.ManifestPosition == nil || *saved.Intent.ManifestPosition != a.From.Position || crypto.SHA256Hex(raw) != a.ReportDigest || saved.ReceivedAt == nil || a.At.Before(*saved.ReceivedAt) {
			return errors.New("store: cursor has no exact successful current native report")
		}
	} else if a.Cause != servicedependents.ManifestNotApplicable {
		return errors.New("store: idle cursor cannot invent native work")
	}
	raw, err := json.Marshal(a.To)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE service_account_rotations SET manifest_cursor=$3::jsonb,manifest_cursor_source_id=$4,manifest_cursor_sequence=$5,updated_at=$6 WHERE tenant_id=$1 AND id=$2`, tenantID, parent.ID, raw, sourceID, sequence, a.At)
	return err
}
