// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// Decoy files (Q6-O1): an SSH private key a host agent planted where no file
// was. The agent watches the file and reports each open over its channel; the
// control plane finds the decoy by host and path and records the opening
// program as its reader (ApplyDecoySecretReadTx), one critical alert per
// program.

// maxLiveDecoyFilesAtPath bounds one path's lookup; a path holds one live decoy
// unless the agent planted a new key there before the old decoy was retired.
const maxLiveDecoyFilesAtPath = 16

// LiveDecoyFileIDs returns the decoys planted at path on host that are active or
// already triggered, newest first. A retired decoy no longer alerts.
func (s *Store) LiveDecoyFileIDs(ctx context.Context, tenantID, host, path string) ([]string, error) {
	var out []string
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text FROM honey_tokens
			  WHERE tenant_id = $1 AND kind = 'file' AND file_host = $2 AND file_path = $3 AND state <> 'revoked'
			  ORDER BY created_at DESC, id LIMIT $4`, tenantID, host, path, maxLiveDecoyFilesAtPath)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			out = append(out, id)
		}
		return rows.Err()
	})
	return out, err
}

// ListDecoyFilesPage pages the tenant's decoy files in id order.
func (s *Store) ListDecoyFilesPage(ctx context.Context, tenantID, afterID string, limit int) ([]HoneyToken, error) {
	return s.listHoneyTokensWhere(ctx, tenantID, `kind = 'file'`, afterID, limit)
}

// maxKubernetesDecoysPerCluster bounds the decoys one cluster's audit batch is
// matched against.
const maxKubernetesDecoysPerCluster = 1000

// LiveKubernetesDecoys returns the decoys registered for cluster that are
// active or already triggered (Q6-O2): the ones its audit events are matched
// against. A retired decoy no longer alerts.
func (s *Store) LiveKubernetesDecoys(ctx context.Context, tenantID, cluster string) ([]HoneyToken, error) {
	out := make([]HoneyToken, 0)
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+honeyTokenColumns+` FROM honey_tokens
			  WHERE tenant_id = $1 AND kind = 'kubernetes' AND k8s_cluster = $2 AND state <> 'revoked'
			  ORDER BY id LIMIT $3`, tenantID, cluster, maxKubernetesDecoysPerCluster)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			h, err := scanHoneyToken(rows)
			if err != nil {
				return err
			}
			out = append(out, h)
		}
		return rows.Err()
	})
	return out, err
}

// ListKubernetesDecoysPage pages the tenant's Kubernetes decoys in id order.
func (s *Store) ListKubernetesDecoysPage(ctx context.Context, tenantID, afterID string, limit int) ([]HoneyToken, error) {
	return s.listHoneyTokensWhere(ctx, tenantID, `kind = 'kubernetes'`, afterID, limit)
}
