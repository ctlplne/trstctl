// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	KubernetesPostureCertificateSigningRequests = "certificate-signing-requests"
	KubernetesPostureTrustBundles               = "trust-bundles"
)

// KubernetesPostureResource is one metadata-only Kubernetes object observation.
// PublicHash is a SHA-256 digest of public CSR or trust-bundle material; payload
// bytes and credentials never enter this read model.
type KubernetesPostureResource struct {
	Namespace       string `json:"namespace,omitempty"`
	Name            string `json:"name"`
	UID             string `json:"uid"`
	ResourceVersion string `json:"resource_version"`
	State           string `json:"state"`
	Reason          string `json:"reason"`
	PublicHash      string `json:"public_hash,omitempty"`
}

// KubernetesControllerPosture is the latest event-projected observation for one
// cluster and capability, including the authenticated controller that reported it.
type KubernetesControllerPosture struct {
	TenantID                 string
	ControllerID             string
	ClusterID                string
	Capability               string
	ReportID                 string
	ReconcileComplete        bool
	FailureCode              string
	ReconcileIntervalSeconds int
	Resources                []KubernetesPostureResource
	ReportedAt               time.Time
	EventSequence            uint64
}

// ApplyKubernetesControllerPostureTx projects one capability section. A DaemonSet
// can run many controller pods in one cluster, so cluster+capability is the durable
// identity and the latest authenticated controller replaces the prior reporter.
// Event sequence wins over arrival order, so a delayed live projection cannot
// replace newer replayed state.
func (s *Store) ApplyKubernetesControllerPostureTx(ctx context.Context, tx pgx.Tx, p KubernetesControllerPosture) error {
	resources, err := json.Marshal(p.Resources)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO kubernetes_controller_posture
		        (tenant_id, controller_id, cluster_id, capability, report_id,
		         reconcile_complete, failure_code, reconcile_interval_seconds,
		         resources, reported_at, event_sequence)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11)
		 ON CONFLICT (tenant_id, cluster_id, capability) DO UPDATE
		    SET controller_id = EXCLUDED.controller_id,
		        report_id = EXCLUDED.report_id,
		        reconcile_complete = EXCLUDED.reconcile_complete,
		        failure_code = EXCLUDED.failure_code,
		        reconcile_interval_seconds = EXCLUDED.reconcile_interval_seconds,
		        resources = EXCLUDED.resources,
		        reported_at = EXCLUDED.reported_at,
		        event_sequence = EXCLUDED.event_sequence
		  WHERE EXCLUDED.event_sequence >= kubernetes_controller_posture.event_sequence`,
		p.TenantID, p.ControllerID, p.ClusterID, p.Capability, p.ReportID,
		p.ReconcileComplete, p.FailureCode, p.ReconcileIntervalSeconds,
		resources, p.ReportedAt, p.EventSequence)
	return err
}

// ListKubernetesControllerPosture returns only the authenticated tenant's latest
// controller reports for one closed-set capability. Both the SQL predicate and
// PostgreSQL RLS enforce tenant isolation (AN-1).
func (s *Store) ListKubernetesControllerPosture(ctx context.Context, tenantID, capability string) ([]KubernetesControllerPosture, error) {
	var out []KubernetesControllerPosture
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT tenant_id::text, controller_id::text, cluster_id, capability,
			        report_id::text, reconcile_complete, failure_code,
			        reconcile_interval_seconds, resources, reported_at, event_sequence
			   FROM kubernetes_controller_posture
			  WHERE tenant_id = $1 AND capability = $2
			  ORDER BY reported_at DESC, controller_id, cluster_id`, tenantID, capability)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var row KubernetesControllerPosture
			var resources []byte
			if err := rows.Scan(&row.TenantID, &row.ControllerID, &row.ClusterID, &row.Capability,
				&row.ReportID, &row.ReconcileComplete, &row.FailureCode,
				&row.ReconcileIntervalSeconds, &resources, &row.ReportedAt, &row.EventSequence); err != nil {
				return err
			}
			if err := json.Unmarshal(resources, &row.Resources); err != nil {
				return err
			}
			out = append(out, row)
		}
		return rows.Err()
	})
	return out, err
}
