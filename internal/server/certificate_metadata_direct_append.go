// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Direct server producers must own the tenant's certificate metadata order
// before publishing. Otherwise a later certificate recording can project first,
// making the earlier event unprojectable without a full rebuild. The event is
// still the source of truth; the SQL transaction applies its projection while
// holding the publication-order lock.
func appendAndProjectOrderedCertificateMetadata(ctx context.Context, st *store.Store, log *events.Log,
	candidate events.Event,
) (events.Event, error) {
	dependent, err := projections.CertificateMetadataEvent(candidate)
	if err != nil {
		return events.Event{}, err
	}
	if !dependent {
		return events.Event{}, errors.New("server: ordered certificate metadata append requires a metadata event")
	}
	material, recording, err := projections.CertificateRecordingMaterial(candidate)
	if err != nil {
		return events.Event{}, err
	}
	var published events.Event
	err = st.WithTenant(ctx, candidate.TenantID, func(tx pgx.Tx) error {
		if recording {
			// Recording projections also take the fingerprint lock. Preserve
			// their relation -> metadata -> fingerprint order before append.
			if err := st.LockCertificateRecordingTx(ctx, tx, candidate.TenantID, material.Fingerprint); err != nil {
				return err
			}
		} else if err := st.LockCertificateMetadataOrderTx(ctx, tx, candidate.TenantID); err != nil {
			return err
		}
		var err error
		published, err = log.Append(ctx, candidate)
		if err != nil {
			return err
		}
		return projections.New(st).ApplyTx(ctx, tx, published)
	})
	return published, err
}
