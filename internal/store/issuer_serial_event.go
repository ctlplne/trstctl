// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/eventspec"
)

// RecordIssuedCertEventTx retains which event first created a serial row. The
// caller commits a managed leaf's serial and receipt in the same transaction;
// delegated CA certificates instead retain their explicit non-leaf event type.
// An old writer leaves this binding NULL. Later observations never backfill it
// or overwrite its original authority, so incomplete history stays incomplete.
func (s *Store) RecordIssuedCertEventTx(ctx context.Context, tx pgx.Tx, e eventspec.Event, caID, serial string, issuedAt time.Time) error {
	if e.ID == "" || e.Sequence == 0 {
		return s.RecordIssuedCertTx(ctx, tx, e.TenantID, caID, serial, issuedAt)
	}
	_, err := tx.Exec(ctx, `INSERT INTO ca_issued_certs
		(tenant_id,ca_id,serial,issued_at,issuance_event_id,issuance_event_type)
		VALUES($1,$2,$3,$4,$5,$6)
		ON CONFLICT (tenant_id,ca_id,serial) DO NOTHING`,
		e.TenantID, caID, serial, issuedAt.UTC(), e.ID, e.Type)
	return err
}

// IssuedCertMint is the event a CA ledger serial row records as its mint.
// EventID is empty for a row an older writer recorded without it.
type IssuedCertMint struct {
	EventID   string
	EventType string
}

// IssuedCertEventTx reads the mint a CA ledger row binds a serial to.
func (s *Store) IssuedCertEventTx(ctx context.Context, tx pgx.Tx, tenantID, caID, serial string) (IssuedCertMint, bool, error) {
	var mint IssuedCertMint
	err := tx.QueryRow(ctx, `SELECT COALESCE(issuance_event_id,''),COALESCE(issuance_event_type,'')
		FROM ca_issued_certs WHERE tenant_id=$1 AND ca_id=$2 AND serial=$3`, tenantID, caID, serial).
		Scan(&mint.EventID, &mint.EventType)
	if IsNotFound(err) {
		return IssuedCertMint{}, false, nil
	}
	return mint, err == nil, err
}
