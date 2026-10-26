// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// Kubernetes trust-bundle rollout states (A138).
const (
	KubernetesTrustRolloutRunning    = "running"
	KubernetesTrustRolloutPaused     = "paused"
	KubernetesTrustRolloutCompleted  = "completed"
	KubernetesTrustRolloutSuperseded = "superseded"

	KubernetesTrustClusterWaiting    = "waiting"
	KubernetesTrustClusterDispatched = "dispatched"
	KubernetesTrustClusterVerified   = "verified"
	KubernetesTrustClusterFailed     = "failed"
)

// ErrKubernetesTrustRolloutNotFound reports a rollout id the tenant does not have.
var ErrKubernetesTrustRolloutNotFound = errors.New("store: Kubernetes trust rollout not found")

// KubernetesTrustRollout is one TrustBundle rolled out to an ordered list of
// clusters, the first of which is the canary. The bundle is public CA
// certificates only.
type KubernetesTrustRollout struct {
	TenantID      string                          `json:"tenant_id"`
	ID            string                          `json:"id"`
	Name          string                          `json:"name"`
	CABundlePEM   string                          `json:"ca_bundle_pem"`
	BundleSHA256  string                          `json:"bundle_sha256"`
	ConfigMapName string                          `json:"config_map_name"`
	BundleKey     string                          `json:"key"`
	Namespaces    []string                        `json:"namespaces"`
	State         string                          `json:"state"`
	CreatedAt     time.Time                       `json:"created_at"`
	UpdatedAt     time.Time                       `json:"updated_at"`
	EventSequence uint64                          `json:"event_sequence"`
	Clusters      []KubernetesTrustRolloutCluster `json:"clusters"`
}

// KubernetesTrustRolloutCluster is one cluster's progress. Verified carries the
// posture report in which the cluster's own controller reported the bundle
// distributed with the rollout's hash.
type KubernetesTrustRolloutCluster struct {
	ClusterID    string     `json:"cluster_id"`
	Position     int        `json:"position"`
	State        string     `json:"state"`
	Reason       string     `json:"reason,omitempty"`
	ReportID     string     `json:"report_id,omitempty"`
	ObservedHash string     `json:"observed_hash,omitempty"`
	DispatchedAt *time.Time `json:"dispatched_at,omitempty"`
	VerifiedAt   *time.Time `json:"verified_at,omitempty"`
}

// KubernetesDesiredTrustBundle is one bundle a cluster's controller should hold.
type KubernetesDesiredTrustBundle struct {
	RolloutID     string
	Name          string
	CABundlePEM   string
	BundleSHA256  string
	ConfigMapName string
	BundleKey     string
	Namespaces    []string
}

// ApplyKubernetesTrustRolloutStartedTx records a new rollout: its canary is
// dispatched at once and the other clusters wait for it. An earlier running or
// paused rollout of the same TrustBundle name is superseded; clusters it already
// reached keep its bundle until this rollout reaches them.
func (s *Store) ApplyKubernetesTrustRolloutStartedTx(ctx context.Context, tx pgx.Tx, r KubernetesTrustRollout, at time.Time, seq uint64) error {
	namespaces, err := json.Marshal(r.Namespaces)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE kubernetes_trust_rollouts
		    SET state = 'superseded', updated_at = $3, event_sequence = $4
		  WHERE tenant_id = $1 AND name = $2 AND state IN ('running', 'paused') AND event_sequence < $4`,
		r.TenantID, r.Name, at, seq); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx,
		`INSERT INTO kubernetes_trust_rollouts
		        (tenant_id, id, name, ca_bundle_pem, bundle_sha256, config_map_name, bundle_key,
		         namespaces, state, created_at, updated_at, event_sequence)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, 'running', $9, $9, $10)
		 ON CONFLICT (tenant_id, id) DO NOTHING`,
		r.TenantID, r.ID, r.Name, r.CABundlePEM, r.BundleSHA256, r.ConfigMapName, r.BundleKey,
		namespaces, at, seq)
	if err != nil || tag.RowsAffected() == 0 {
		return err // a replayed start changes nothing
	}
	for position, cluster := range r.Clusters {
		state, dispatched := KubernetesTrustClusterWaiting, (*time.Time)(nil)
		if position == 0 {
			state, dispatched = KubernetesTrustClusterDispatched, &at
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO kubernetes_trust_rollout_clusters
			        (tenant_id, rollout_id, cluster_id, position, state, dispatched_at, event_sequence)
			 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			r.TenantID, r.ID, cluster.ClusterID, position, state, dispatched, seq); err != nil {
			return err
		}
	}
	return nil
}

// ApplyKubernetesTrustRolloutStateTx pauses or resumes a rollout. Pausing
// stops the canary gate from dispatching the other clusters; resuming
// re-evaluates it. The API refuses any other transition before it emits; one
// that a race made stale here (a rollout that completed meanwhile) changes
// nothing.
func (s *Store) ApplyKubernetesTrustRolloutStateTx(ctx context.Context, tx pgx.Tx, tenantID, id, state string, at time.Time, seq uint64) error {
	from := KubernetesTrustRolloutRunning
	if state == KubernetesTrustRolloutRunning {
		from = KubernetesTrustRolloutPaused
	}
	tag, err := tx.Exec(ctx,
		`UPDATE kubernetes_trust_rollouts SET state = $3, updated_at = $5, event_sequence = $6
		  WHERE tenant_id = $1 AND id = $2 AND state = $4 AND event_sequence < $6`,
		tenantID, id, state, from, at, seq)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		var exists bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM kubernetes_trust_rollouts WHERE tenant_id = $1 AND id = $2)`,
			tenantID, id).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrKubernetesTrustRolloutNotFound
		}
		return nil // a replay, or a transition a race made stale
	}
	return s.advanceKubernetesTrustRolloutTx(ctx, tx, tenantID, id, at, seq)
}

// ObserveKubernetesTrustRolloutsTx applies one cluster's authenticated posture
// report to the rollouts that reached it: a TrustBundle the report shows ready
// with the rollout's hash verifies the cluster, one it shows failed fails it.
// A verified canary then dispatches the other clusters.
func (s *Store) ObserveKubernetesTrustRolloutsTx(ctx context.Context, tx pgx.Tx, tenantID, clusterID, reportID string, bundles []KubernetesPostureResource, at time.Time, seq uint64) error {
	rows, err := tx.Query(ctx,
		`SELECT c.rollout_id::text, r.name, r.bundle_sha256
		   FROM kubernetes_trust_rollout_clusters c
		   JOIN kubernetes_trust_rollouts r ON r.tenant_id = c.tenant_id AND r.id = c.rollout_id
		  WHERE c.tenant_id = $1 AND c.cluster_id = $2 AND c.state IN ('dispatched', 'failed')`,
		tenantID, clusterID)
	if err != nil {
		return err
	}
	type pending struct{ id, name, hash string }
	var waiting []pending
	for rows.Next() {
		var p pending
		if err := rows.Scan(&p.id, &p.name, &p.hash); err != nil {
			rows.Close()
			return err
		}
		waiting = append(waiting, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	byName := make(map[string]KubernetesPostureResource, len(bundles))
	for _, bundle := range bundles {
		byName[bundle.Name] = bundle
	}
	for _, p := range waiting {
		observed, ok := byName[p.name]
		var state, reason string
		switch {
		case !ok:
			continue
		case observed.State == "ready" && observed.PublicHash == p.hash:
			state = KubernetesTrustClusterVerified
		case observed.State == "failed":
			state, reason = KubernetesTrustClusterFailed, observed.Reason
		default:
			continue // not yet distributed, or still holding an earlier bundle
		}
		if _, err := tx.Exec(ctx,
			`UPDATE kubernetes_trust_rollout_clusters
			    SET state = $4, reason = $5, report_id = $6, observed_hash = $7,
			        verified_at = CASE WHEN $4 = 'verified' THEN $8::timestamptz ELSE NULL END,
			        event_sequence = $9
			  WHERE tenant_id = $1 AND rollout_id = $2 AND cluster_id = $3 AND event_sequence < $9`,
			tenantID, p.id, clusterID, state, reason, reportID, observed.PublicHash, at, seq); err != nil {
			return err
		}
		if err := s.advanceKubernetesTrustRolloutTx(ctx, tx, tenantID, p.id, at, seq); err != nil {
			return err
		}
	}
	return nil
}

// advanceKubernetesTrustRolloutTx applies the canary gate and completion: a
// running rollout whose canary is verified dispatches its waiting clusters,
// and a rollout whose clusters are all verified is completed.
func (s *Store) advanceKubernetesTrustRolloutTx(ctx context.Context, tx pgx.Tx, tenantID, id string, at time.Time, seq uint64) error {
	if _, err := tx.Exec(ctx,
		`UPDATE kubernetes_trust_rollout_clusters c
		    SET state = 'dispatched', dispatched_at = $3, event_sequence = $4
		  WHERE c.tenant_id = $1 AND c.rollout_id = $2 AND c.state = 'waiting'
		    AND EXISTS (SELECT 1 FROM kubernetes_trust_rollouts r
		                 WHERE r.tenant_id = $1 AND r.id = $2 AND r.state = 'running')
		    AND EXISTS (SELECT 1 FROM kubernetes_trust_rollout_clusters canary
		                 WHERE canary.tenant_id = $1 AND canary.rollout_id = $2
		                   AND canary.position = 0 AND canary.state = 'verified')`,
		tenantID, id, at, seq); err != nil {
		return err
	}
	_, err := tx.Exec(ctx,
		`UPDATE kubernetes_trust_rollouts r
		    SET state = 'completed', updated_at = $3, event_sequence = GREATEST(r.event_sequence, $4)
		  WHERE r.tenant_id = $1 AND r.id = $2 AND r.state IN ('running', 'paused')
		    AND NOT EXISTS (SELECT 1 FROM kubernetes_trust_rollout_clusters c
		                     WHERE c.tenant_id = $1 AND c.rollout_id = $2 AND c.state <> 'verified')`,
		tenantID, id, at, seq)
	return err
}

// ListKubernetesTrustRollouts returns the tenant's rollouts, newest first.
func (s *Store) ListKubernetesTrustRollouts(ctx context.Context, tenantID string) ([]KubernetesTrustRollout, error) {
	var out []KubernetesTrustRollout
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		out, err = s.queryKubernetesTrustRollouts(ctx, tx, tenantID, "")
		return err
	})
	return out, err
}

// GetKubernetesTrustRollout returns one rollout with its clusters.
func (s *Store) GetKubernetesTrustRollout(ctx context.Context, tenantID, id string) (KubernetesTrustRollout, error) {
	var out []KubernetesTrustRollout
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		out, err = s.queryKubernetesTrustRollouts(ctx, tx, tenantID, id)
		return err
	})
	if err != nil {
		return KubernetesTrustRollout{}, err
	}
	if len(out) == 0 {
		return KubernetesTrustRollout{}, ErrKubernetesTrustRolloutNotFound
	}
	return out[0], nil
}

func (s *Store) queryKubernetesTrustRollouts(ctx context.Context, tx pgx.Tx, tenantID, id string) ([]KubernetesTrustRollout, error) {
	rows, err := tx.Query(ctx,
		`SELECT tenant_id::text, id::text, name, ca_bundle_pem, bundle_sha256, config_map_name, bundle_key,
		        namespaces, state, created_at, updated_at, event_sequence
		   FROM kubernetes_trust_rollouts
		  WHERE tenant_id = $1 AND ($2 = '' OR id::text = $2)
		  ORDER BY created_at DESC, id`, tenantID, id)
	if err != nil {
		return nil, err
	}
	var out []KubernetesTrustRollout
	index := map[string]int{}
	for rows.Next() {
		var r KubernetesTrustRollout
		var namespaces []byte
		if err := rows.Scan(&r.TenantID, &r.ID, &r.Name, &r.CABundlePEM, &r.BundleSHA256, &r.ConfigMapName, &r.BundleKey,
			&namespaces, &r.State, &r.CreatedAt, &r.UpdatedAt, &r.EventSequence); err != nil {
			rows.Close()
			return nil, err
		}
		if err := json.Unmarshal(namespaces, &r.Namespaces); err != nil {
			rows.Close()
			return nil, err
		}
		r.Clusters = []KubernetesTrustRolloutCluster{}
		index[r.ID] = len(out)
		out = append(out, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil || len(out) == 0 {
		return out, err
	}
	clusters, err := tx.Query(ctx,
		`SELECT rollout_id::text, cluster_id, position, state, reason, report_id, observed_hash, dispatched_at, verified_at
		   FROM kubernetes_trust_rollout_clusters
		  WHERE tenant_id = $1 AND ($2 = '' OR rollout_id::text = $2)
		  ORDER BY rollout_id, position`, tenantID, id)
	if err != nil {
		return nil, err
	}
	defer clusters.Close()
	for clusters.Next() {
		var rolloutID string
		var c KubernetesTrustRolloutCluster
		if err := clusters.Scan(&rolloutID, &c.ClusterID, &c.Position, &c.State, &c.Reason, &c.ReportID, &c.ObservedHash,
			&c.DispatchedAt, &c.VerifiedAt); err != nil {
			return nil, err
		}
		if i, ok := index[rolloutID]; ok {
			out[i].Clusters = append(out[i].Clusters, c)
		}
	}
	return out, clusters.Err()
}

// DesiredKubernetesTrustBundles returns the bundles a cluster's controller
// should hold: for each TrustBundle name, the latest rollout that has reached
// the cluster.
func (s *Store) DesiredKubernetesTrustBundles(ctx context.Context, tenantID, clusterID string) ([]KubernetesDesiredTrustBundle, error) {
	var out []KubernetesDesiredTrustBundle
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT DISTINCT ON (r.name) r.id::text, r.name, r.ca_bundle_pem, r.bundle_sha256, r.config_map_name,
			        r.bundle_key, r.namespaces
			   FROM kubernetes_trust_rollout_clusters c
			   JOIN kubernetes_trust_rollouts r ON r.tenant_id = c.tenant_id AND r.id = c.rollout_id
			  WHERE c.tenant_id = $1 AND c.cluster_id = $2 AND c.state <> 'waiting'
			  ORDER BY r.name, r.created_at DESC, r.event_sequence DESC`, tenantID, clusterID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var d KubernetesDesiredTrustBundle
			var namespaces []byte
			if err := rows.Scan(&d.RolloutID, &d.Name, &d.CABundlePEM, &d.BundleSHA256, &d.ConfigMapName, &d.BundleKey, &namespaces); err != nil {
				return err
			}
			if err := json.Unmarshal(namespaces, &d.Namespaces); err != nil {
				return err
			}
			out = append(out, d)
		}
		return rows.Err()
	})
	return out, err
}

// KnownKubernetesClusters lists the clusters whose controllers have reported
// posture for the tenant: the clusters a rollout may name.
func (s *Store) KnownKubernetesClusters(ctx context.Context, tenantID string) (map[string]bool, error) {
	out := map[string]bool{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT DISTINCT cluster_id FROM kubernetes_controller_posture WHERE tenant_id = $1`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var cluster string
			if err := rows.Scan(&cluster); err != nil {
				return err
			}
			out[cluster] = true
		}
		return rows.Err()
	})
	return out, err
}
