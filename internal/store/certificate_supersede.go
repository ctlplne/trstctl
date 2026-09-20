// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// SupersedeObservedCertificatesAtTx retires every discovery-observed certificate at
// one listener once a managed certificate with a different fingerprint has been
// verified there: the observed baseline is no longer what the listener serves, so
// the inventory must stop reporting its owner gap and its imminent expiry
// (DP2-030). It is a function of the verification event and the rows that exist,
// and an update to a fixed value, so a replay converges. Only rows a discovery
// collector recorded are touched; issued and imported records keep their own
// lifecycle.
func (s *Store) SupersedeObservedCertificatesAtTx(ctx context.Context, tx pgx.Tx, tenantID, deploymentLocation, verifiedFingerprint string) (int64, error) {
	if tenantID == "" || deploymentLocation == "" || verifiedFingerprint == "" {
		return 0, fmt.Errorf("store: supersede observed certificates requires tenant, location and fingerprint")
	}
	tag, err := tx.Exec(ctx,
		`UPDATE certificates
		    SET status = 'superseded'
		  WHERE tenant_id = $1
		    AND deployment_location = $2
		    AND fingerprint <> $3
		    AND COALESCE(source, '') LIKE 'discovery:%'
		    AND status = 'active'`,
		tenantID, deploymentLocation, verifiedFingerprint)
	if err != nil {
		return 0, fmt.Errorf("store: supersede observed certificates: %w", err)
	}
	return tag.RowsAffected(), nil
}
