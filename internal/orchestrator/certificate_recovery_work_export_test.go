// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// RecoverCertificateHistoryForTest lets real-PG integration tests measure the
// recovery boundary without adding a production hook. The caller holds the same
// privacy and certificate-order fences as the normal recording command.
func RecoverCertificateHistoryForTest(o *Orchestrator, ctx context.Context, tx pgx.Tx, tenantID, fingerprint string) error {
	return o.catchUpCertificateRecordingTx(ctx, tx, tenantID, fingerprint)
}
