// SPDX-License-Identifier: BUSL-1.1

// Package store is the tenant-scoped (RLS) persistence for PCAS: the durable
// succession-record chain and the serving copy of each identity's algorithm-epoch
// high-water. It layers on the MPL core store through the feature-neutral
// WithExtraMigrations seam and the RLS-scoped Store.WithTenant transaction; it
// forks neither the core store nor its migration runner (AN-1, AN-9).
package store

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"time"

	"github.com/jackc/pgx/v5"

	corestore "trstctl.com/trstctl/internal/store"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// MigrationsFS returns the PCAS succession DDL as a migration source for the core
// store's feature-neutral WithExtraMigrations seam. It is wired only through the
// tagged ee_attach seam (PCAS-08); the core-only build never references it, so the
// core-only build applies zero PCAS migrations (G6).
func MigrationsFS() fs.FS { return migrationsFS }

// ErrHighWaterRegression is returned by UpsertHighWater when the requested epoch
// is not strictly greater than the stored high-water (defense in depth; the
// signer floor is the authority, INV-3).
var ErrHighWaterRegression = errors.New("succession store: high-water cannot regress")

// Record is a durable succession-chain row (one per succession record). It holds
// public key material and the opaque encoded record only; no private keys (AN-8).
type Record struct {
	IdentityID       string
	Epoch            uint64
	PredecessorEpoch uint64
	PredecessorAlg   string
	SuccessorAlg     string
	SuccessorPub     []byte
	Encoded          []byte // opaque encoded dual-signed record (PCAS-04)
}

type DelegationScope struct {
	ScopeID       string
	ParentScopeID string
	EpochFloor    uint64
	UpdatedAt     time.Time
}

type RecoveryPolicy struct {
	IdentityID   string
	Threshold    int
	RosterJSON   json.RawMessage
	TrustRootDER []byte
	UpdatedAt    time.Time
}

type FederationBridge struct {
	ForeignDeploymentID string
	IdentityID          string
	ForeignTrustRootDER []byte
	LocalBaseEpoch      uint64
	BridgeJSON          json.RawMessage
	UpdatedAt           time.Time
}

type FederationQuarantine struct {
	ForeignDeploymentID string
	IdentityID          string
	Reason              string
	ProofJSON           json.RawMessage
	DetectedAt          time.Time
}

type RewrapJob struct {
	JobID            string
	IdentityID       string
	PredecessorEpoch uint64
	Stage            string
	TotalStages      int
	CompletedStages  int
	Status           string
	UpdatedAt        time.Time
}

type EpochCheckpoint struct {
	IdentityID     string
	Epoch          uint64
	LogTreeSize    uint64
	LogRoot        []byte
	Signature      []byte
	CheckpointJSON json.RawMessage
	IssuedAt       time.Time
}

type Misissuance struct {
	IdentityID    string
	Epoch         uint64
	RecordADigest []byte
	RecordBDigest []byte
	SignerA       string
	SignerB       string
	ProofJSON     json.RawMessage
	DetectedAt    time.Time
}

type IssuerAuthority struct {
	IssuerID     string
	IdentityID   string
	CurrentEpoch uint64
	CAKeyHandle  string
	CACertDER    []byte
	UpdatedAt    time.Time
}

type RetirementPolicy struct {
	IdentityID            string
	PredecessorEpoch      uint64
	Threshold             int
	RosterJSON            json.RawMessage
	ValidityWindowSeconds uint64
	PredecessorHandle     string
	Status                string
	UpdatedAt             time.Time
}

// Repo is the tenant-scoped repository. Every method runs inside the core store's
// RLS-scoped transaction (Store.WithTenant), so row-level security confines all
// access to the caller's tenant (AN-1, PCAS-claim-7 / INV-5 RLS half).
type Repo struct {
	core *corestore.Store
}

// New returns a Repo over the core store.
func New(core *corestore.Store) *Repo { return &Repo{core: core} }

// AppendRecord inserts a succession record for tenantID. The tenant_id column is
// bound from the RLS session setting, so the row is always the caller's tenant
// (the RLS WITH CHECK enforces it).
func (r *Repo) AppendRecord(ctx context.Context, tenantID string, rec Record) error {
	return r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO succession_records
			   (tenant_id, identity_id, epoch, predecessor_epoch, predecessor_alg, successor_alg, successor_pub, record)
			 VALUES (current_setting('trstctl.tenant_id')::uuid, $1, $2, $3, $4, $5, $6, $7)`,
			rec.IdentityID, rec.Epoch, rec.PredecessorEpoch, rec.PredecessorAlg, rec.SuccessorAlg, rec.SuccessorPub, rec.Encoded)
		if err != nil {
			return fmt.Errorf("succession store: append record: %w", err)
		}
		return nil
	})
}

// FetchChain returns identityID's succession records ordered and complete by
// epoch ascending, scoped to tenantID by RLS.
func (r *Repo) FetchChain(ctx context.Context, tenantID, identityID string) ([]Record, error) {
	var out []Record
	err := r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT identity_id, epoch, predecessor_epoch, predecessor_alg, successor_alg, successor_pub, record
			   FROM succession_records
			  WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND identity_id = $1
			  ORDER BY epoch ASC`, identityID)
		if err != nil {
			return fmt.Errorf("succession store: fetch chain: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var rec Record
			if err := rows.Scan(&rec.IdentityID, &rec.Epoch, &rec.PredecessorEpoch, &rec.PredecessorAlg, &rec.SuccessorAlg, &rec.SuccessorPub, &rec.Encoded); err != nil {
				return fmt.Errorf("succession store: scan record: %w", err)
			}
			out = append(out, rec)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (r *Repo) ListRecords(ctx context.Context, tenantID string) ([]Record, error) {
	var out []Record
	err := r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT identity_id, epoch, predecessor_epoch, predecessor_alg, successor_alg, successor_pub, record
			   FROM succession_records
			  WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid
			  ORDER BY identity_id ASC, epoch ASC`)
		if err != nil {
			return fmt.Errorf("succession store: list records: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var rec Record
			if err := rows.Scan(&rec.IdentityID, &rec.Epoch, &rec.PredecessorEpoch, &rec.PredecessorAlg, &rec.SuccessorAlg, &rec.SuccessorPub, &rec.Encoded); err != nil {
				return fmt.Errorf("succession store: scan listed record: %w", err)
			}
			out = append(out, rec)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (r *Repo) LatestRecord(ctx context.Context, tenantID, identityID string) (Record, bool, error) {
	var rec Record
	err := r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		e := tx.QueryRow(ctx,
			`SELECT identity_id, epoch, predecessor_epoch, predecessor_alg, successor_alg, successor_pub, record
			   FROM succession_records
			  WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND identity_id = $1
			  ORDER BY epoch DESC
			  LIMIT 1`, identityID).
			Scan(&rec.IdentityID, &rec.Epoch, &rec.PredecessorEpoch, &rec.PredecessorAlg, &rec.SuccessorAlg, &rec.SuccessorPub, &rec.Encoded)
		if errors.Is(e, pgx.ErrNoRows) {
			return nil
		}
		if e != nil {
			return fmt.Errorf("succession store: latest record: %w", e)
		}
		return nil
	})
	if err != nil {
		return Record{}, false, err
	}
	return rec, rec.IdentityID != "", nil
}

// UpsertHighWater advances the serving high-water for identityID to epoch. It is
// monotonic: an equal or lower epoch is rejected (ErrHighWaterRegression) and
// leaves the stored value unchanged.
func (r *Repo) UpsertHighWater(ctx context.Context, tenantID, identityID string, epoch uint64) error {
	return r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx,
			`INSERT INTO identity_algorithm_epoch (tenant_id, identity_id, epoch)
			 VALUES (current_setting('trstctl.tenant_id')::uuid, $1, $2)
			 ON CONFLICT (tenant_id, identity_id)
			 DO UPDATE SET epoch = EXCLUDED.epoch, updated_at = now()
			 WHERE identity_algorithm_epoch.epoch < EXCLUDED.epoch`,
			identityID, epoch)
		if err != nil {
			return fmt.Errorf("succession store: upsert high-water: %w", err)
		}
		if ct.RowsAffected() == 0 {
			return fmt.Errorf("%w: identity %q epoch %d", ErrHighWaterRegression, identityID, epoch)
		}
		return nil
	})
}

// GetHighWater returns the serving high-water epoch for identityID and whether a
// row exists, scoped to tenantID by RLS.
func (r *Repo) GetHighWater(ctx context.Context, tenantID, identityID string) (epoch uint64, found bool, err error) {
	err = r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		e := tx.QueryRow(ctx,
			`SELECT epoch FROM identity_algorithm_epoch
			  WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND identity_id = $1`, identityID).Scan(&epoch)
		if errors.Is(e, pgx.ErrNoRows) {
			return nil
		}
		if e != nil {
			return fmt.Errorf("succession store: get high-water: %w", e)
		}
		found = true
		return nil
	})
	return epoch, found, err
}

func (r *Repo) UpsertDelegationScope(ctx context.Context, tenantID string, scope DelegationScope) error {
	return r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO pcas_delegation_scope (tenant_id, scope_id, parent_scope_id, epoch_floor)
			 VALUES (current_setting('trstctl.tenant_id')::uuid, $1, $2, $3)
			 ON CONFLICT (tenant_id, scope_id)
			 DO UPDATE SET parent_scope_id = EXCLUDED.parent_scope_id,
			               epoch_floor = EXCLUDED.epoch_floor,
			               updated_at = now()`,
			scope.ScopeID, scope.ParentScopeID, scope.EpochFloor)
		if err != nil {
			return fmt.Errorf("succession store: upsert delegation scope: %w", err)
		}
		return nil
	})
}

func (r *Repo) ListDelegationScopes(ctx context.Context, tenantID string) ([]DelegationScope, error) {
	var out []DelegationScope
	err := r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT scope_id, parent_scope_id, epoch_floor, updated_at
			   FROM pcas_delegation_scope
			  WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid
			  ORDER BY scope_id ASC`)
		if err != nil {
			return fmt.Errorf("succession store: list delegation scopes: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var scope DelegationScope
			if err := rows.Scan(&scope.ScopeID, &scope.ParentScopeID, &scope.EpochFloor, &scope.UpdatedAt); err != nil {
				return fmt.Errorf("succession store: scan delegation scope: %w", err)
			}
			out = append(out, scope)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (r *Repo) RaiseDelegationFloor(ctx context.Context, tenantID, scopeID string, epochFloor uint64) error {
	return r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx,
			`UPDATE pcas_delegation_scope
			    SET epoch_floor = GREATEST(epoch_floor, $2), updated_at = now()
			  WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND scope_id = $1`,
			scopeID, epochFloor)
		if err != nil {
			return fmt.Errorf("succession store: raise delegation floor: %w", err)
		}
		if ct.RowsAffected() == 0 {
			return pgx.ErrNoRows
		}
		return nil
	})
}

func (r *Repo) UpsertRecoveryPolicy(ctx context.Context, tenantID string, policy RecoveryPolicy) error {
	roster := jsonPayload(policy.RosterJSON, "[]")
	return r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO pcas_recovery_policy (tenant_id, identity_id, threshold, roster_json, trust_root_der)
			 VALUES (current_setting('trstctl.tenant_id')::uuid, $1, $2, $3::jsonb, $4)
			 ON CONFLICT (tenant_id, identity_id)
			 DO UPDATE SET threshold = EXCLUDED.threshold,
			               roster_json = EXCLUDED.roster_json,
			               trust_root_der = EXCLUDED.trust_root_der,
			               updated_at = now()`,
			policy.IdentityID, policy.Threshold, roster, policy.TrustRootDER)
		if err != nil {
			return fmt.Errorf("succession store: upsert recovery policy: %w", err)
		}
		return nil
	})
}

func (r *Repo) GetRecoveryPolicy(ctx context.Context, tenantID, identityID string) (RecoveryPolicy, bool, error) {
	var policy RecoveryPolicy
	err := r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		e := tx.QueryRow(ctx,
			`SELECT identity_id, threshold, roster_json, trust_root_der, updated_at
			   FROM pcas_recovery_policy
			  WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND identity_id = $1`, identityID).
			Scan(&policy.IdentityID, &policy.Threshold, &policy.RosterJSON, &policy.TrustRootDER, &policy.UpdatedAt)
		if errors.Is(e, pgx.ErrNoRows) {
			return nil
		}
		if e != nil {
			return fmt.Errorf("succession store: get recovery policy: %w", e)
		}
		return nil
	})
	if err != nil {
		return RecoveryPolicy{}, false, err
	}
	return policy, policy.IdentityID != "", nil
}

func (r *Repo) UpsertFederationBridge(ctx context.Context, tenantID string, bridge FederationBridge) error {
	bridgeJSON := jsonPayload(bridge.BridgeJSON, "{}")
	return r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO pcas_federation_bridge
			    (tenant_id, foreign_deployment_id, identity_id, foreign_trust_root_der, local_base_epoch, bridge_json)
			 VALUES (current_setting('trstctl.tenant_id')::uuid, $1, $2, $3, $4, $5::jsonb)
			 ON CONFLICT (tenant_id, foreign_deployment_id, identity_id)
			 DO UPDATE SET foreign_trust_root_der = EXCLUDED.foreign_trust_root_der,
			               local_base_epoch = EXCLUDED.local_base_epoch,
			               bridge_json = EXCLUDED.bridge_json,
			               updated_at = now()`,
			bridge.ForeignDeploymentID, bridge.IdentityID, bridge.ForeignTrustRootDER, bridge.LocalBaseEpoch, bridgeJSON)
		if err != nil {
			return fmt.Errorf("succession store: upsert federation bridge: %w", err)
		}
		return nil
	})
}

// ListFederationBridges returns every imported federation bridge for the
// tenant. It is the read path AUD-9 found missing: bridges were persisted under
// RLS and then consulted by nothing — an operator could import a foreign trust
// root and never see which bridges exist or what they trust.
func (r *Repo) ListFederationBridges(ctx context.Context, tenantID string) ([]FederationBridge, error) {
	var out []FederationBridge
	err := r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT foreign_deployment_id, identity_id, foreign_trust_root_der, local_base_epoch, bridge_json, updated_at
			   FROM pcas_federation_bridge
			  WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid
			  ORDER BY foreign_deployment_id ASC, identity_id ASC`)
		if err != nil {
			return fmt.Errorf("succession store: list federation bridges: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var b FederationBridge
			if err := rows.Scan(&b.ForeignDeploymentID, &b.IdentityID, &b.ForeignTrustRootDER, &b.LocalBaseEpoch, &b.BridgeJSON, &b.UpdatedAt); err != nil {
				return fmt.Errorf("succession store: scan federation bridge: %w", err)
			}
			out = append(out, b)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (r *Repo) SaveFederationQuarantine(ctx context.Context, tenantID string, q FederationQuarantine) error {
	proof := jsonPayload(q.ProofJSON, "{}")
	return r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO pcas_federation_quarantine
			    (tenant_id, foreign_deployment_id, identity_id, reason, proof_json)
			 VALUES (current_setting('trstctl.tenant_id')::uuid, $1, $2, $3, $4::jsonb)`,
			q.ForeignDeploymentID, q.IdentityID, q.Reason, proof)
		if err != nil {
			return fmt.Errorf("succession store: save federation quarantine: %w", err)
		}
		return nil
	})
}

func (r *Repo) ListFederationQuarantine(ctx context.Context, tenantID string) ([]FederationQuarantine, error) {
	var out []FederationQuarantine
	err := r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT foreign_deployment_id, identity_id, reason, proof_json, detected_at
			   FROM pcas_federation_quarantine
			  WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid
			  ORDER BY detected_at DESC`)
		if err != nil {
			return fmt.Errorf("succession store: list federation quarantine: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var q FederationQuarantine
			if err := rows.Scan(&q.ForeignDeploymentID, &q.IdentityID, &q.Reason, &q.ProofJSON, &q.DetectedAt); err != nil {
				return fmt.Errorf("succession store: scan federation quarantine: %w", err)
			}
			out = append(out, q)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (r *Repo) UpsertRewrapJob(ctx context.Context, tenantID string, job RewrapJob) error {
	return r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO pcas_rewrap_job
			    (tenant_id, job_id, identity_id, predecessor_epoch, stage, total_stages, completed_stages, status)
			 VALUES (current_setting('trstctl.tenant_id')::uuid, $1, $2, $3, $4, $5, $6, $7)
			 ON CONFLICT (tenant_id, job_id, stage)
			 DO UPDATE SET completed_stages = EXCLUDED.completed_stages,
			               status = EXCLUDED.status,
			               updated_at = now()`,
			job.JobID, job.IdentityID, job.PredecessorEpoch, job.Stage, job.TotalStages, job.CompletedStages, job.Status)
		if err != nil {
			return fmt.Errorf("succession store: upsert rewrap job: %w", err)
		}
		return nil
	})
}

func (r *Repo) RewrapComplete(ctx context.Context, tenantID, identityID string, predecessorEpoch uint64) (bool, error) {
	var complete bool
	err := r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		e := tx.QueryRow(ctx,
			`SELECT COALESCE(bool_and(status = 'complete'), false)
			   FROM pcas_rewrap_job
			  WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid
			    AND identity_id = $1
			    AND predecessor_epoch = $2`,
			identityID, predecessorEpoch).Scan(&complete)
		if e != nil {
			return fmt.Errorf("succession store: rewrap complete: %w", e)
		}
		return nil
	})
	return complete, err
}

func (r *Repo) ListRewrapJobs(ctx context.Context, tenantID, identityID string, predecessorEpoch uint64) ([]RewrapJob, error) {
	var out []RewrapJob
	err := r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT job_id, identity_id, predecessor_epoch, stage, total_stages, completed_stages, status, updated_at
			   FROM pcas_rewrap_job
			  WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid
			    AND identity_id = $1
			    AND ($2::bigint = 0 OR predecessor_epoch = $2)
			  ORDER BY updated_at DESC, stage ASC`,
			identityID, predecessorEpoch)
		if err != nil {
			return fmt.Errorf("succession store: list rewrap jobs: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var job RewrapJob
			if err := rows.Scan(&job.JobID, &job.IdentityID, &job.PredecessorEpoch, &job.Stage, &job.TotalStages, &job.CompletedStages, &job.Status, &job.UpdatedAt); err != nil {
				return fmt.Errorf("succession store: scan rewrap job: %w", err)
			}
			out = append(out, job)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (r *Repo) SaveCheckpoint(ctx context.Context, tenantID string, cp EpochCheckpoint) error {
	checkpointJSON := jsonPayload(cp.CheckpointJSON, "{}")
	return r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO pcas_epoch_checkpoint
			    (tenant_id, identity_id, epoch, log_tree_size, log_root, signature, checkpoint_json)
			 VALUES (current_setting('trstctl.tenant_id')::uuid, $1, $2, $3, $4, $5, $6::jsonb)
			 ON CONFLICT (tenant_id, identity_id, epoch)
			 DO UPDATE SET log_tree_size = EXCLUDED.log_tree_size,
			               log_root = EXCLUDED.log_root,
			               signature = EXCLUDED.signature,
			               checkpoint_json = EXCLUDED.checkpoint_json,
			               issued_at = now()`,
			cp.IdentityID, cp.Epoch, cp.LogTreeSize, cp.LogRoot, cp.Signature, checkpointJSON)
		if err != nil {
			return fmt.Errorf("succession store: save checkpoint: %w", err)
		}
		return nil
	})
}

func (r *Repo) LatestCheckpoint(ctx context.Context, tenantID, identityID string) (EpochCheckpoint, bool, error) {
	var cp EpochCheckpoint
	err := r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		e := tx.QueryRow(ctx,
			`SELECT identity_id, epoch, log_tree_size, log_root, signature, checkpoint_json, issued_at
			   FROM pcas_epoch_checkpoint
			  WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND identity_id = $1
			  ORDER BY epoch DESC
			  LIMIT 1`, identityID).
			Scan(&cp.IdentityID, &cp.Epoch, &cp.LogTreeSize, &cp.LogRoot, &cp.Signature, &cp.CheckpointJSON, &cp.IssuedAt)
		if errors.Is(e, pgx.ErrNoRows) {
			return nil
		}
		if e != nil {
			return fmt.Errorf("succession store: latest checkpoint: %w", e)
		}
		return nil
	})
	if err != nil {
		return EpochCheckpoint{}, false, err
	}
	return cp, cp.IdentityID != "", nil
}

func (r *Repo) SaveMisissuance(ctx context.Context, tenantID string, m Misissuance) error {
	proof := jsonPayload(m.ProofJSON, "{}")
	return r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO pcas_misissuance
			    (tenant_id, identity_id, epoch, record_a_digest, record_b_digest, signer_a, signer_b, proof_json)
			 VALUES (current_setting('trstctl.tenant_id')::uuid, $1, $2, $3, $4, $5, $6, $7::jsonb)
			 ON CONFLICT (tenant_id, identity_id, epoch, record_a_digest, record_b_digest)
			 DO UPDATE SET signer_a = EXCLUDED.signer_a,
			               signer_b = EXCLUDED.signer_b,
			               proof_json = EXCLUDED.proof_json`,
			m.IdentityID, m.Epoch, m.RecordADigest, m.RecordBDigest, m.SignerA, m.SignerB, proof)
		if err != nil {
			return fmt.Errorf("succession store: save misissuance: %w", err)
		}
		return nil
	})
}

func (r *Repo) ListMisissuance(ctx context.Context, tenantID string) ([]Misissuance, error) {
	var out []Misissuance
	err := r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT identity_id, epoch, record_a_digest, record_b_digest, signer_a, signer_b, proof_json, detected_at
			   FROM pcas_misissuance
			  WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid
			  ORDER BY detected_at DESC`)
		if err != nil {
			return fmt.Errorf("succession store: list misissuance: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var m Misissuance
			if err := rows.Scan(&m.IdentityID, &m.Epoch, &m.RecordADigest, &m.RecordBDigest, &m.SignerA, &m.SignerB, &m.ProofJSON, &m.DetectedAt); err != nil {
				return fmt.Errorf("succession store: scan misissuance: %w", err)
			}
			out = append(out, m)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (r *Repo) UpsertIssuerAuthority(ctx context.Context, tenantID string, authority IssuerAuthority) error {
	return r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO pcas_issuer_authority
			    (tenant_id, issuer_id, identity_id, current_epoch, ca_key_handle, ca_cert_der)
			 VALUES (current_setting('trstctl.tenant_id')::uuid, $1, $2, $3, $4, $5)
			 ON CONFLICT (tenant_id, issuer_id)
			 DO UPDATE SET identity_id = EXCLUDED.identity_id,
			               current_epoch = EXCLUDED.current_epoch,
			               ca_key_handle = EXCLUDED.ca_key_handle,
			               ca_cert_der = EXCLUDED.ca_cert_der,
			               updated_at = now()`,
			authority.IssuerID, authority.IdentityID, authority.CurrentEpoch, authority.CAKeyHandle, authority.CACertDER)
		if err != nil {
			return fmt.Errorf("succession store: upsert issuer authority: %w", err)
		}
		return nil
	})
}

func (r *Repo) GetIssuerAuthority(ctx context.Context, tenantID, issuerID string) (IssuerAuthority, bool, error) {
	var authority IssuerAuthority
	err := r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		e := tx.QueryRow(ctx,
			`SELECT issuer_id, identity_id, current_epoch, ca_key_handle, ca_cert_der, updated_at
			   FROM pcas_issuer_authority
			  WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND issuer_id = $1`, issuerID).
			Scan(&authority.IssuerID, &authority.IdentityID, &authority.CurrentEpoch, &authority.CAKeyHandle, &authority.CACertDER, &authority.UpdatedAt)
		if errors.Is(e, pgx.ErrNoRows) {
			return nil
		}
		if e != nil {
			return fmt.Errorf("succession store: get issuer authority: %w", e)
		}
		return nil
	})
	if err != nil {
		return IssuerAuthority{}, false, err
	}
	return authority, authority.IssuerID != "", nil
}

func (r *Repo) UpsertRetirementPolicy(ctx context.Context, tenantID string, policy RetirementPolicy) error {
	roster := jsonPayload(policy.RosterJSON, "[]")
	status := policy.Status
	if status == "" {
		status = "active"
	}
	return r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO pcas_retirement_policy
			    (tenant_id, identity_id, predecessor_epoch, threshold, roster_json, validity_window_seconds, predecessor_handle, status)
			 VALUES (current_setting('trstctl.tenant_id')::uuid, $1, $2, $3, $4::jsonb, $5, $6, $7)
			 ON CONFLICT (tenant_id, identity_id, predecessor_epoch)
			 DO UPDATE SET threshold = EXCLUDED.threshold,
			               roster_json = EXCLUDED.roster_json,
			               validity_window_seconds = EXCLUDED.validity_window_seconds,
			               predecessor_handle = EXCLUDED.predecessor_handle,
			               status = EXCLUDED.status,
			               updated_at = now()`,
			policy.IdentityID, policy.PredecessorEpoch, policy.Threshold, roster, policy.ValidityWindowSeconds,
			policy.PredecessorHandle, status)
		if err != nil {
			return fmt.Errorf("succession store: upsert retirement policy: %w", err)
		}
		return nil
	})
}

func (r *Repo) ListRetirementPolicies(ctx context.Context, tenantID string, onlyActive bool) ([]RetirementPolicy, error) {
	var out []RetirementPolicy
	err := r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT identity_id, predecessor_epoch, threshold, roster_json, validity_window_seconds, predecessor_handle, status, updated_at
			   FROM pcas_retirement_policy
			  WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid
			    AND ($1::boolean = false OR status = 'active')
			  ORDER BY updated_at DESC`,
			onlyActive)
		if err != nil {
			return fmt.Errorf("succession store: list retirement policies: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var policy RetirementPolicy
			if err := rows.Scan(&policy.IdentityID, &policy.PredecessorEpoch, &policy.Threshold, &policy.RosterJSON,
				&policy.ValidityWindowSeconds, &policy.PredecessorHandle, &policy.Status, &policy.UpdatedAt); err != nil {
				return fmt.Errorf("succession store: scan retirement policy: %w", err)
			}
			out = append(out, policy)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (r *Repo) GetRetirementPolicy(ctx context.Context, tenantID, identityID string, predecessorEpoch uint64) (RetirementPolicy, bool, error) {
	var policy RetirementPolicy
	err := r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		e := tx.QueryRow(ctx,
			`SELECT identity_id, predecessor_epoch, threshold, roster_json, validity_window_seconds, predecessor_handle, status, updated_at
			   FROM pcas_retirement_policy
			  WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid
			    AND identity_id = $1
			    AND predecessor_epoch = $2`,
			identityID, predecessorEpoch).
			Scan(&policy.IdentityID, &policy.PredecessorEpoch, &policy.Threshold, &policy.RosterJSON,
				&policy.ValidityWindowSeconds, &policy.PredecessorHandle, &policy.Status, &policy.UpdatedAt)
		if errors.Is(e, pgx.ErrNoRows) {
			return nil
		}
		if e != nil {
			return fmt.Errorf("succession store: get retirement policy: %w", e)
		}
		return nil
	})
	if err != nil {
		return RetirementPolicy{}, false, err
	}
	return policy, policy.IdentityID != "", nil
}

func (r *Repo) MarkRetirementRetired(ctx context.Context, tenantID, identityID string, predecessorEpoch uint64) error {
	return r.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`UPDATE pcas_retirement_policy
			    SET status = 'retired', updated_at = now()
			  WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid
			    AND identity_id = $1
			    AND predecessor_epoch = $2`,
			identityID, predecessorEpoch)
		if err != nil {
			return fmt.Errorf("succession store: mark retirement retired: %w", err)
		}
		return nil
	})
}

func jsonPayload(raw json.RawMessage, fallback string) string {
	if len(raw) == 0 || !json.Valid(raw) {
		return fallback
	}
	return string(raw)
}
