// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"math"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

// ApplySSHCertificateRevokedTx projects ssh.cert.revoked (A245-L1): one row
// per revocation event, the serial in decimal (empty when none was named) and
// whether a key ID was named, never the ID. A replayed event changes nothing.
func (s *Store) ApplySSHCertificateRevokedTx(ctx context.Context, tx pgx.Tx, tenantID, eventID string, serial uint64, byKeyID bool,
	reason, revokedBy string, revokedAt time.Time, eventSequence uint64) error {
	serialText := ""
	if serial != 0 {
		serialText = strconv.FormatUint(serial, 10)
	}
	if eventSequence > math.MaxInt64 {
		eventSequence = 0
	}
	_, err := tx.Exec(ctx, `INSERT INTO ssh_certificate_revocations (tenant_id, event_id, serial, by_key_id, reason, revoked_by, revoked_at, event_sequence)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (tenant_id, event_id) DO NOTHING`,
		tenantID, eventID, serialText, byKeyID, reason, revokedBy, revokedAt, int64(eventSequence)) // #nosec G115 -- bounded by MaxInt64 above.
	return err
}
