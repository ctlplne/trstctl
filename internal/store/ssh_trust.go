// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// SSHTrustFindingKind is the discovery finding kind an agent reports for one
// sshd configuration's trust posture (A115).
const SSHTrustFindingKind = "ssh_trust"

// MaxSSHTrustPostures bounds one host-trust read.
const MaxSSHTrustPostures = 5000

// SSHTrustPosture is the newest trust posture one agent reported for one sshd
// configuration. Metadata is the agent's report as recorded, with the host and
// agent ID the control plane stamped from the agent's certificate.
type SSHTrustPosture struct {
	SourceID    string
	RunID       string
	AgentID     string
	AgentName   string
	ConfigPath  string
	Fingerprint string
	Metadata    []byte
	FirstSeenAt time.Time
	LastSeenAt  time.Time
}

// ListSSHTrustPostures returns, per agent and sshd configuration, the posture
// that agent reported most recently; a changed configuration is a new finding,
// so the newest one is the host's current answer.
func (s *Store) ListSSHTrustPostures(ctx context.Context, tenantID string, limit int) ([]SSHTrustPosture, error) {
	if limit <= 0 || limit > MaxSSHTrustPostures {
		limit = MaxSSHTrustPostures
	}
	var out []SSHTrustPosture
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT source_id, run_id, agent_id, host, ref, fingerprint, metadata, first_seen_at, last_seen_at
			   FROM (SELECT DISTINCT ON (f.metadata->>'agent_id', f.ref)
			                f.source_id::text AS source_id, f.run_id::text AS run_id,
			                COALESCE(f.metadata->>'agent_id', '') AS agent_id,
			                COALESCE(f.metadata->>'host', '') AS host,
			                f.ref, f.fingerprint, f.metadata, f.first_seen_at, f.last_seen_at
			           FROM discovery_findings f
			          WHERE f.tenant_id = $1 AND f.kind = $2
			          ORDER BY f.metadata->>'agent_id', f.ref, f.last_seen_at DESC, f.id DESC) newest
			  ORDER BY host, ref
			  LIMIT $3`, tenantID, SSHTrustFindingKind, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var p SSHTrustPosture
			if err := rows.Scan(&p.SourceID, &p.RunID, &p.AgentID, &p.AgentName, &p.ConfigPath, &p.Fingerprint, &p.Metadata, &p.FirstSeenAt, &p.LastSeenAt); err != nil {
				return err
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	return out, err
}
