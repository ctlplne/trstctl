// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// BrokerAgentKeyLimit bounds an agent's published key set: an agent holds a few
// overlapping short-lived identities, never hundreds.
const BrokerAgentKeyLimit = 20

// BrokerAgentKey is one valid broker-issued certificate of an agent: the public
// material an authorization server checks the agent's signed assertions with.
type BrokerAgentKey struct {
	CertificateID  string
	CertificateDER []byte
	NotAfter       time.Time
}

// ListValidBrokerAgentKeys returns the agent's broker-issued certificates that are
// valid at now: inside their validity window and neither revoked nor superseded,
// newest first. A revoked certificate leaves the list as soon as its revocation
// is projected.
func (s *Store) ListValidBrokerAgentKeys(ctx context.Context, tenantID, agentID string, now time.Time) ([]BrokerAgentKey, error) {
	keys := []BrokerAgentKey{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id::text, certificate_der, not_after FROM certificates
			WHERE tenant_id = $1 AND issuance_idempotency_key LIKE 'broker-issue:%'
			  AND broker_issuance->>'agent_id' = $2 AND certificate_der IS NOT NULL
			  AND (`+brokerCertificateStateSQL("$3")+`) = 'valid'
			ORDER BY not_after DESC, id DESC LIMIT $4`, tenantID, agentID, now, BrokerAgentKeyLimit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var key BrokerAgentKey
			if err := rows.Scan(&key.CertificateID, &key.CertificateDER, &key.NotAfter); err != nil {
				return err
			}
			keys = append(keys, key)
		}
		return rows.Err()
	})
	return keys, err
}
