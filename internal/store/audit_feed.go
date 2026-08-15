// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

var ErrAuditFeedBatchConflict = errors.New("store: audit feed batch conflicts with durable authority")

// AuditFeed is one tenant-owned standing collector instruction plus its latest
// durable delivery posture. TokenRef is a pointer only; credential bytes never
// enter this read model.
type AuditFeed struct {
	ID                     string
	TenantID               string
	Name                   string
	Provider               string
	EndpointURL            string
	TokenRef               string
	IntervalSeconds        int
	BatchSize              int
	Enabled                bool
	AllowPrivateEndpoint   bool
	PrivateEgressCIDRs     []string
	ConfigEventSequence    uint64
	NextRunAt              time.Time
	LastQueuedSequence     uint64
	LastDeliveredSequence  uint64
	LagRecords             int
	LastBatchID            string
	LastOutboxKey          string
	LastStatus             string
	LastAttemptAt          *time.Time
	LastDeliveredAt        *time.Time
	LastErrorCode          string
	LastBatchStartSequence uint64
	LastBatchRecordCount   int
	LastCollectorRequestID string
	OutboxStatus           string
	OutboxAttempts         int
	OutboxLastError        string
	OutboxNextAttemptAt    *time.Time
	CreatedAt              time.Time
	UpdatedAt              time.Time
}

// EffectiveStatus distinguishes queued intent, a failed attempt waiting for its
// outbox backoff, terminal failure, and a receipt-backed delivery.
func (f AuditFeed) EffectiveStatus() string {
	if f.LastStatus != "queued" {
		return f.LastStatus
	}
	switch f.OutboxStatus {
	case "processing":
		return "delivering"
	case "failed":
		return "failed"
	case "pending":
		if f.OutboxAttempts > 0 {
			return "retrying"
		}
	}
	return "queued"
}

type AuditFeedBatch struct {
	BatchID              string
	TenantID             string
	DestinationID        string
	Provider             string
	StartSequence        uint64
	EndSequence          uint64
	RecordCount          int
	ChainHead            string
	OutboxIdempotencyKey string
	Status               string
	QueuedAt             time.Time
	AcceptedAt           *time.Time
	CollectorRequestID   string
	ErrorCode            string
}

func (s *Store) ApplyAuditFeedConfiguredTx(ctx context.Context, tx pgx.Tx, feed AuditFeed) error {
	cidrs, err := json.Marshal(feed.PrivateEgressCIDRs)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO audit_feed_destinations
		        (id, tenant_id, name, provider, endpoint_url, token_ref, interval_seconds,
		         batch_size, enabled, allow_private_endpoint, private_egress_cidrs,
		         config_event_sequence, next_run_at, created_at, updated_at)
		      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12,$13,$14,$14)
		 ON CONFLICT (tenant_id, id) DO UPDATE
		      SET name = EXCLUDED.name,
		          provider = EXCLUDED.provider,
		          endpoint_url = EXCLUDED.endpoint_url,
		          token_ref = EXCLUDED.token_ref,
		          interval_seconds = EXCLUDED.interval_seconds,
		          batch_size = EXCLUDED.batch_size,
		          enabled = EXCLUDED.enabled,
		          allow_private_endpoint = EXCLUDED.allow_private_endpoint,
		          private_egress_cidrs = EXCLUDED.private_egress_cidrs,
		          config_event_sequence = EXCLUDED.config_event_sequence,
		          next_run_at = EXCLUDED.next_run_at,
		          updated_at = EXCLUDED.updated_at
		    WHERE audit_feed_destinations.config_event_sequence < EXCLUDED.config_event_sequence`,
		feed.ID, feed.TenantID, feed.Name, feed.Provider, feed.EndpointURL, feed.TokenRef,
		feed.IntervalSeconds, feed.BatchSize, feed.Enabled, feed.AllowPrivateEndpoint,
		cidrs, feed.ConfigEventSequence, feed.NextRunAt, feed.UpdatedAt)
	return err
}

func (s *Store) ApplyAuditFeedScheduleCheckedTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, destinationID string,
	configEventSequence, cursor uint64,
	intervalSeconds int,
	checkedAt time.Time,
) error {
	command, err := tx.Exec(ctx,
		`UPDATE audit_feed_destinations
		    SET next_run_at = $6::timestamptz + ($5::integer * interval '1 second'),
		        lag_records = 0,
		        updated_at = $6::timestamptz
		  WHERE tenant_id = $1 AND id = $2 AND config_event_sequence = $3
		    AND last_delivered_sequence = $4 AND last_status <> 'queued'`,
		tenantID, destinationID, configEventSequence, cursor, intervalSeconds, checkedAt)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrAuditFeedBatchConflict
	}
	return nil
}

func (s *Store) ApplyAuditFeedBatchQueuedTx(ctx context.Context, tx pgx.Tx, batch AuditFeedBatch, intervalSeconds int) error {
	command, err := tx.Exec(ctx,
		`INSERT INTO audit_feed_deliveries
		        (batch_id, tenant_id, destination_id, provider, start_sequence, end_sequence,
		         record_count, chain_head, outbox_idempotency_key, status, queued_at)
		      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'queued',$10)
		 ON CONFLICT (tenant_id, batch_id) DO NOTHING`,
		batch.BatchID, batch.TenantID, batch.DestinationID, batch.Provider,
		batch.StartSequence, batch.EndSequence, batch.RecordCount, batch.ChainHead,
		batch.OutboxIdempotencyKey, batch.QueuedAt)
	if err != nil {
		return err
	}
	if command.RowsAffected() == 0 {
		var existing AuditFeedBatch
		if err := scanAuditFeedBatch(tx.QueryRow(ctx,
			`SELECT batch_id::text, tenant_id::text, destination_id::text, provider,
			        start_sequence, end_sequence, record_count, chain_head,
			        outbox_idempotency_key, status, queued_at, accepted_at,
			        collector_request_id, error_code
			   FROM audit_feed_deliveries
			  WHERE tenant_id = $1 AND batch_id = $2`, batch.TenantID, batch.BatchID), &existing); err != nil {
			return err
		}
		if existing.DestinationID != batch.DestinationID || existing.Provider != batch.Provider ||
			existing.StartSequence != batch.StartSequence || existing.EndSequence != batch.EndSequence ||
			existing.RecordCount != batch.RecordCount || existing.ChainHead != batch.ChainHead ||
			existing.OutboxIdempotencyKey != batch.OutboxIdempotencyKey {
			return ErrAuditFeedBatchConflict
		}
	}
	command, err = tx.Exec(ctx,
		`UPDATE audit_feed_destinations
		    SET last_queued_sequence = $3,
		        last_batch_id = $4,
		        last_outbox_key = $5,
		        last_status = 'queued',
		        lag_records = $8,
		        last_attempt_at = $6::timestamptz,
		        last_error_code = '',
		        next_run_at = $6::timestamptz + ($7::integer * interval '1 second'),
		        updated_at = $6::timestamptz
		  WHERE tenant_id = $1 AND id = $2
		    AND last_delivered_sequence < $3`,
		batch.TenantID, batch.DestinationID, batch.EndSequence, batch.BatchID,
		batch.OutboxIdempotencyKey, batch.QueuedAt, intervalSeconds, batch.RecordCount)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		var lastBatchID string
		if err := tx.QueryRow(ctx,
			`SELECT COALESCE(last_batch_id::text, '') FROM audit_feed_destinations
			  WHERE tenant_id = $1 AND id = $2`, batch.TenantID, batch.DestinationID).Scan(&lastBatchID); err != nil {
			return err
		}
		if lastBatchID != batch.BatchID {
			return ErrAuditFeedBatchConflict
		}
	}
	return nil
}

func (s *Store) ApplyAuditFeedBatchDeliveredTx(ctx context.Context, tx pgx.Tx, batch AuditFeedBatch) error {
	command, err := tx.Exec(ctx,
		`UPDATE audit_feed_deliveries
		    SET status = 'delivered', accepted_at = $4, collector_request_id = $5, error_code = ''
		  WHERE tenant_id = $1 AND batch_id = $2 AND destination_id = $3
		    AND start_sequence = $6 AND end_sequence = $7 AND record_count = $8
		    AND chain_head = $9 AND outbox_idempotency_key = $10
		    AND status IN ('queued','delivered')`,
		batch.TenantID, batch.BatchID, batch.DestinationID, batch.AcceptedAt,
		batch.CollectorRequestID, batch.StartSequence, batch.EndSequence,
		batch.RecordCount, batch.ChainHead, batch.OutboxIdempotencyKey)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrAuditFeedBatchConflict
	}
	command, err = tx.Exec(ctx,
		`UPDATE audit_feed_destinations
		    SET last_delivered_sequence = $4,
		        last_status = 'delivered',
		        lag_records = 0,
		        last_delivered_at = $5,
		        last_attempt_at = $5,
		        last_error_code = '',
		        updated_at = $5
		  WHERE tenant_id = $1 AND id = $2 AND last_batch_id = $3
		    AND last_outbox_key = $6 AND last_queued_sequence = $4`,
		batch.TenantID, batch.DestinationID, batch.BatchID, batch.EndSequence,
		batch.AcceptedAt, batch.OutboxIdempotencyKey)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrAuditFeedBatchConflict
	}
	return nil
}

func (s *Store) ApplyAuditFeedBatchFailedTx(ctx context.Context, tx pgx.Tx, batch AuditFeedBatch) error {
	command, err := tx.Exec(ctx,
		`UPDATE audit_feed_deliveries
		    SET status = 'failed', error_code = $4
		  WHERE tenant_id = $1 AND batch_id = $2 AND destination_id = $3
		    AND outbox_idempotency_key = $5 AND status IN ('queued','failed')`,
		batch.TenantID, batch.BatchID, batch.DestinationID, batch.ErrorCode,
		batch.OutboxIdempotencyKey)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrAuditFeedBatchConflict
	}
	command, err = tx.Exec(ctx,
		`UPDATE audit_feed_destinations
		    SET last_status = 'failed', last_error_code = $4,
		        last_attempt_at = $5, updated_at = $5
		  WHERE tenant_id = $1 AND id = $2 AND last_batch_id = $3
		    AND last_outbox_key = $6`,
		batch.TenantID, batch.DestinationID, batch.BatchID, batch.ErrorCode,
		batch.AcceptedAt, batch.OutboxIdempotencyKey)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrAuditFeedBatchConflict
	}
	return nil
}

func (s *Store) GetAuditFeed(ctx context.Context, tenantID, id string) (AuditFeed, bool, error) {
	var out AuditFeed
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanAuditFeed(tx.QueryRow(ctx, auditFeedSelectSQL+` WHERE f.tenant_id = $1 AND f.id = $2`, tenantID, id), &out)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return AuditFeed{}, false, nil
	}
	return out, err == nil, err
}

func (s *Store) ListAuditFeeds(ctx context.Context, tenantID string) ([]AuditFeed, error) {
	var out []AuditFeed
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, auditFeedSelectSQL+` WHERE f.tenant_id = $1 ORDER BY f.name, f.id`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var feed AuditFeed
			if err := scanAuditFeed(rows, &feed); err != nil {
				return err
			}
			out = append(out, feed)
		}
		return rows.Err()
	})
	return out, err
}

func (s *Store) TenantsWithEnabledAuditFeeds(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		//trstctl:system-query — cross-tenant by design: enumerates tenants with enabled audit feeds so the leader scheduler can enter each tenant's RLS context (AN-1 exemption).
		`SELECT DISTINCT tenant_id::text FROM audit_feed_destinations WHERE enabled ORDER BY tenant_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var tenantID string
		if err := rows.Scan(&tenantID); err != nil {
			return nil, err
		}
		out = append(out, tenantID)
	}
	return out, rows.Err()
}

func (s *Store) AuditFeedsDue(ctx context.Context, tenantID string, now time.Time, limit int) ([]AuditFeed, error) {
	if tenantID == "" || limit < 1 {
		return nil, fmt.Errorf("store: tenant id and positive audit feed limit are required")
	}
	var out []AuditFeed
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, auditFeedSelectSQL+
			// 'queued' is excluded because a batch is in flight and re-queueing
			// would duplicate it. 'failed' used to be excluded alongside it, which
			// is a different thing entirely: a failed batch is not in flight, and
			// nothing anywhere clears the status or offers an operator a resume.
			// One transient delivery error therefore stopped a SIEM feed
			// permanently and silently — the worst way for compliance evidence to
			// stop. Retrying is safe: the failure path deliberately leaves
			// last_delivered_sequence where it was, so the retry replays the same
			// records rather than skipping them, and next_run_at was already
			// advanced by one interval when the batch was queued, so this resumes
			// at the feed's configured cadence instead of spinning.
			` WHERE f.tenant_id = $1 AND f.enabled AND f.next_run_at <= $2
			    AND f.last_status <> 'queued'
			  ORDER BY f.next_run_at, f.id LIMIT $3`, tenantID, now, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var feed AuditFeed
			if err := scanAuditFeed(rows, &feed); err != nil {
				return err
			}
			out = append(out, feed)
		}
		return rows.Err()
	})
	return out, err
}

const auditFeedSelectSQL = `SELECT f.id::text, f.tenant_id::text, f.name, f.provider,
	       f.endpoint_url, f.token_ref, f.interval_seconds, f.batch_size, f.enabled,
	       f.allow_private_endpoint, f.private_egress_cidrs, f.config_event_sequence,
	       f.next_run_at, f.last_queued_sequence, f.last_delivered_sequence,
	       f.lag_records,
	       COALESCE(f.last_batch_id::text, ''), f.last_outbox_key, f.last_status,
	       f.last_attempt_at, f.last_delivered_at, f.last_error_code,
	       COALESCE(o.status, ''), COALESCE(o.attempts, 0), COALESCE(o.last_error, ''),
	       o.next_attempt_at, COALESCE(b.start_sequence, 0), COALESCE(b.record_count, 0),
	       COALESCE(b.collector_request_id, ''), f.created_at, f.updated_at
	  FROM audit_feed_destinations f
	  LEFT JOIN outbox o ON o.tenant_id = f.tenant_id AND o.idempotency_key = f.last_outbox_key
	  LEFT JOIN audit_feed_deliveries b ON b.tenant_id = f.tenant_id AND b.batch_id = f.last_batch_id`

func scanAuditFeed(row rowScanner, out *AuditFeed) error {
	var cidrs []byte
	var configSeq, queuedSeq, deliveredSeq, batchStartSeq int64
	if err := row.Scan(
		&out.ID, &out.TenantID, &out.Name, &out.Provider, &out.EndpointURL, &out.TokenRef,
		&out.IntervalSeconds, &out.BatchSize, &out.Enabled, &out.AllowPrivateEndpoint,
		&cidrs, &configSeq, &out.NextRunAt, &queuedSeq, &deliveredSeq, &out.LagRecords, &out.LastBatchID,
		&out.LastOutboxKey, &out.LastStatus, &out.LastAttemptAt, &out.LastDeliveredAt,
		&out.LastErrorCode, &out.OutboxStatus, &out.OutboxAttempts, &out.OutboxLastError,
		&out.OutboxNextAttemptAt, &batchStartSeq, &out.LastBatchRecordCount,
		&out.LastCollectorRequestID, &out.CreatedAt, &out.UpdatedAt,
	); err != nil {
		return err
	}
	if err := json.Unmarshal(cidrs, &out.PrivateEgressCIDRs); err != nil {
		return err
	}
	out.ConfigEventSequence = uint64(configSeq)        // #nosec G115 -- PostgreSQL bigint event sequence is non-negative by schema (CWE-190)
	out.LastQueuedSequence = uint64(queuedSeq)         // #nosec G115 -- PostgreSQL bigint tenant sequence is non-negative by schema (CWE-190)
	out.LastDeliveredSequence = uint64(deliveredSeq)   // #nosec G115 -- PostgreSQL bigint tenant sequence is non-negative by schema (CWE-190)
	out.LastBatchStartSequence = uint64(batchStartSeq) // #nosec G115 -- PostgreSQL bigint tenant sequence is non-negative by schema (CWE-190)
	return nil
}

func scanAuditFeedBatch(row rowScanner, out *AuditFeedBatch) error {
	var start, end int64
	if err := row.Scan(
		&out.BatchID, &out.TenantID, &out.DestinationID, &out.Provider, &start, &end,
		&out.RecordCount, &out.ChainHead, &out.OutboxIdempotencyKey, &out.Status,
		&out.QueuedAt, &out.AcceptedAt, &out.CollectorRequestID, &out.ErrorCode,
	); err != nil {
		return err
	}
	out.StartSequence = uint64(start) // #nosec G115 -- positive PostgreSQL bigint by schema (CWE-190)
	out.EndSequence = uint64(end)     // #nosec G115 -- positive PostgreSQL bigint by schema (CWE-190)
	return nil
}
