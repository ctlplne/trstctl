// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// applyKMIPClientEventTx projects a tenant's self-service KMIP clients (A197).
func (p *Projector) applyKMIPClientEventTx(ctx context.Context, tx pgx.Tx, e events.Event) error {
	switch e.Type {
	case EventKMIPClientRegistered:
		var pl KMIPClientRegistered
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.ID == "" || pl.Name == "" || pl.EnrollmentHash == "" || pl.EnrollmentExpiresAt.IsZero() {
			return fmt.Errorf("projections: %s requires an id, a name and an enrollment", e.Type)
		}
		expires := pl.EnrollmentExpiresAt
		return p.store.ApplyKMIPClientRegisteredTx(ctx, tx, store.KMIPClient{
			TenantID: e.TenantID, ID: pl.ID, Name: pl.Name, EnrollmentHash: pl.EnrollmentHash,
			EnrollmentExpiresAt: &expires, CreatedAt: e.Time,
		})
	case EventKMIPClientEnrollmentIssued:
		var pl KMIPClientEnrollmentIssued
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.ID == "" || pl.EnrollmentHash == "" || pl.EnrollmentExpiresAt.IsZero() {
			return fmt.Errorf("projections: %s requires an id and an enrollment", e.Type)
		}
		return p.store.ApplyKMIPClientEnrollmentIssuedTx(ctx, tx, e.TenantID, pl.ID, pl.EnrollmentHash, pl.EnrollmentExpiresAt)
	case EventKMIPClientEnrolled:
		var pl KMIPClientEnrolled
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.ID == "" || pl.Fingerprint == "" || pl.NotAfter.IsZero() {
			return fmt.Errorf("projections: %s requires an id, a fingerprint and an expiry", e.Type)
		}
		return p.store.ApplyKMIPClientEnrolledTx(ctx, tx, e.TenantID, pl.ID, pl.Fingerprint, pl.Subject, pl.NotAfter, e.Time)
	default:
		var pl KMIPClientRemoved
		if err := decode(e, &pl); err != nil {
			return err
		}
		if pl.ID == "" {
			return fmt.Errorf("projections: %s requires an id", e.Type)
		}
		return p.store.ApplyKMIPClientRemovedTx(ctx, tx, e.TenantID, pl.ID)
	}
}
