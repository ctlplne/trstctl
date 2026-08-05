// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// MDMDeviceCorrelation joins an MDM device record to a SCEP transaction (I5).
//
// A correlation, not a copy of the MDM: it holds the identifiers needed to join
// and the last thing the MDM said. Duplicating device inventory would create a
// second, staler source of truth about devices that somebody would eventually
// trust over the MDM itself.
type MDMDeviceCorrelation struct {
	ID            string
	TenantID      string
	MDM           string
	MDMDeviceID   string
	DeviceName    string
	SerialNumber  string
	TransactionID string
	IdentityID    string
	// InstallState is 'ok' | 'failed' | 'unknown'. Unknown is NOT failed: an MDM
	// we could not reach tells us nothing about the device.
	InstallState  string
	InstallDetail string
	ObservedAt    *time.Time
	UpdatedAt     time.Time
}

const mdmCorrelationCols = `id::text, tenant_id::text, mdm, mdm_device_id, device_name,
	serial_number, transaction_id, coalesce(identity_id::text, ''), install_state,
	install_detail, observed_at, updated_at`

func scanMDMCorrelation(row pgx.Row) (MDMDeviceCorrelation, error) {
	var c MDMDeviceCorrelation
	err := row.Scan(&c.ID, &c.TenantID, &c.MDM, &c.MDMDeviceID, &c.DeviceName, &c.SerialNumber,
		&c.TransactionID, &c.IdentityID, &c.InstallState, &c.InstallDetail, &c.ObservedAt, &c.UpdatedAt)
	return c, err
}

// ListMDMDeviceCorrelations returns the tenant's device correlations.
func (s *Store) ListMDMDeviceCorrelations(ctx context.Context, tenantID, mdm string, limit int) ([]MDMDeviceCorrelation, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	var out []MDMDeviceCorrelation
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+mdmCorrelationCols+` FROM mdm_device_correlations
			  WHERE tenant_id = $1 AND ($2 = '' OR mdm = $2)
			  ORDER BY updated_at DESC LIMIT $3`, tenantID, mdm, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			c, err := scanMDMCorrelation(rows)
			if err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

// GetMDMDeviceCorrelation loads one device's correlation by the MDM's own id —
// the identifier an admin can paste from their MDM console, which is the whole
// point of correlating.
func (s *Store) GetMDMDeviceCorrelation(ctx context.Context, tenantID, mdm, mdmDeviceID string) (MDMDeviceCorrelation, error) {
	var out MDMDeviceCorrelation
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		out, err = scanMDMCorrelation(tx.QueryRow(ctx,
			`SELECT `+mdmCorrelationCols+` FROM mdm_device_correlations
			  WHERE tenant_id = $1 AND mdm = $2 AND mdm_device_id = $3
			  ORDER BY updated_at DESC LIMIT 1`, tenantID, mdm, mdmDeviceID))
		return err
	})
	return out, err
}

// ApplyMDMDeviceCorrelatedTx projects an mdm.device.correlated event.
//
// A device that re-enrolls gets a NEW row (the unique key includes the
// transaction), so a failed enrollment stays visible after a successful retry.
// That history is what shows an operator a device which keeps failing.
func (s *Store) ApplyMDMDeviceCorrelatedTx(ctx context.Context, tx pgx.Tx, c MDMDeviceCorrelation) error {
	var identity any
	if c.IdentityID != "" {
		identity = c.IdentityID
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO mdm_device_correlations
		   (tenant_id, mdm, mdm_device_id, device_name, serial_number, transaction_id,
		    identity_id, install_state, install_detail, observed_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7::uuid, $8, $9, $10)
		 ON CONFLICT (tenant_id, mdm, mdm_device_id, transaction_id) DO UPDATE SET
		   device_name = EXCLUDED.device_name, serial_number = EXCLUDED.serial_number,
		   identity_id = coalesce(EXCLUDED.identity_id, mdm_device_correlations.identity_id),
		   install_state = EXCLUDED.install_state, install_detail = EXCLUDED.install_detail,
		   observed_at = EXCLUDED.observed_at, updated_at = now()`,
		c.TenantID, c.MDM, c.MDMDeviceID, c.DeviceName, c.SerialNumber, c.TransactionID,
		identity, c.InstallState, c.InstallDetail, c.ObservedAt)
	return err
}
