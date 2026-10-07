// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// KubernetesCertificateProvenance is a retained, metadata-only observation from
// an enrolled controller. It binds a public issued leaf digest to exact
// Kubernetes resource UIDs; it is not evidence that a workload serves the leaf.
type KubernetesCertificateProvenance struct {
	TenantID        string    `json:"-"`
	ClusterID       string    `json:"cluster_id"`
	Namespace       string    `json:"namespace"`
	RequestName     string    `json:"request_name"`
	RequestUID      string    `json:"request_uid"`
	CertificateName string    `json:"certificate_name"`
	CertificateUID  string    `json:"certificate_uid"`
	Fingerprint     string    `json:"fingerprint"`
	ControllerID    string    `json:"controller_id"`
	ReportID        string    `json:"report_id"`
	ObservedAt      time.Time `json:"observed_at"`
	EventSequence   uint64    `json:"-"`
}

// ApplyKubernetesCertificateProvenanceTx only runs while projecting the
// authenticated immutable controller event, never from an API read/write path.
func (s *Store) ApplyKubernetesCertificateProvenanceTx(ctx context.Context, tx pgx.Tx, p KubernetesCertificateProvenance) error {
	_, err := tx.Exec(ctx, `INSERT INTO kubernetes_certificate_provenance
	    (tenant_id, cluster_id, namespace, request_name, request_uid,
	     certificate_name, certificate_uid, fingerprint, controller_id, report_id,
	     observed_at, event_sequence)
	 VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9::uuid, $10::uuid, $11, $12)
	 ON CONFLICT (tenant_id, cluster_id, request_uid, fingerprint) DO UPDATE
	    SET namespace = EXCLUDED.namespace, request_name = EXCLUDED.request_name,
	        certificate_name = EXCLUDED.certificate_name, certificate_uid = EXCLUDED.certificate_uid,
	        controller_id = EXCLUDED.controller_id, report_id = EXCLUDED.report_id,
	        observed_at = EXCLUDED.observed_at, event_sequence = EXCLUDED.event_sequence
	  WHERE EXCLUDED.event_sequence >= kubernetes_certificate_provenance.event_sequence`,
		p.TenantID, p.ClusterID, p.Namespace, p.RequestName, p.RequestUID,
		p.CertificateName, p.CertificateUID, p.Fingerprint, p.ControllerID, p.ReportID,
		p.ObservedAt, p.EventSequence)
	return err
}

// ListKubernetesCertificateProvenance returns only the tenant's exact leaf
// matches. The tenant predicate and RLS both enforce isolation.
func (s *Store) ListKubernetesCertificateProvenance(ctx context.Context, tenantID string, fingerprints []string) (map[string][]KubernetesCertificateProvenance, error) {
	out := make(map[string][]KubernetesCertificateProvenance)
	if len(fingerprints) == 0 {
		return out, nil
	}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT tenant_id::text, cluster_id, namespace, request_name, request_uid,
	              certificate_name, certificate_uid, fingerprint, controller_id::text,
	              report_id::text, observed_at, event_sequence
	           FROM kubernetes_certificate_provenance
	          WHERE tenant_id = $1::uuid AND fingerprint = ANY($2::text[])
	          ORDER BY observed_at DESC, cluster_id, request_uid`, tenantID, fingerprints)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var row KubernetesCertificateProvenance
			if err := rows.Scan(&row.TenantID, &row.ClusterID, &row.Namespace, &row.RequestName,
				&row.RequestUID, &row.CertificateName, &row.CertificateUID, &row.Fingerprint,
				&row.ControllerID, &row.ReportID, &row.ObservedAt, &row.EventSequence); err != nil {
				return err
			}
			out[row.Fingerprint] = append(out[row.Fingerprint], row)
		}
		return rows.Err()
	})
	return out, err
}
