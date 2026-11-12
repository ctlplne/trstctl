// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/servicedependents"
)

var ErrServiceDependentHostNotFound = errors.New("store: service-account host binding not found")
var ErrServiceDependentScanNotFound = errors.New("store: service-account host scan not found")

type ServiceDependentScanHead struct {
	DeliveryStatus string     `json:"delivery_status"`
	ID             string     `json:"id"`
	AgentID        string     `json:"agent_id"`
	BindingDigest  string     `json:"binding_digest"`
	Status         string     `json:"status"`
	Failure        string     `json:"failure,omitempty"`
	QueuedAt       time.Time  `json:"queued_at"`
	ReceivedAt     *time.Time `json:"received_at,omitempty"`
	ServiceCount   int        `json:"service_count"`
	TaskCount      int        `json:"task_count"`
	PoolCount      int        `json:"pool_count"`
	Current        bool       `json:"current"`
}
type ServiceDependentHost struct {
	BindingDigest string                        `json:"binding_digest"`
	LatestScan    *ServiceDependentScanHead     `json:"latest_scan,omitempty"`
	Binding       servicedependents.HostBinding `json:"binding"`
	SavedBy       string                        `json:"saved_by"`
	UpdatedAt     time.Time                     `json:"updated_at"`
}
type ServiceDependentScan struct {
	ObservedEventID   string                             `json:"observed_event_id,omitempty"`
	DeliveryStatus    string                             `json:"delivery_status"`
	ID                string                             `json:"id"`
	Intent            servicedependents.InventoryIntent  `json:"intent"`
	Status            string                             `json:"status"`
	QueuedBy          string                             `json:"queued_by"`
	QueuedAt          time.Time                          `json:"queued_at"`
	QueuedEventID     string                             `json:"queued_event_id"`
	OutboxID          *int64                             `json:"outbox_id,omitempty"`
	Report            *servicedependents.InventoryReport `json:"report,omitempty"`
	ReportDigest      string                             `json:"report_digest,omitempty"`
	Failure           string                             `json:"failure,omitempty"`
	ServiceCount      int                                `json:"service_count"`
	TaskCount         int                                `json:"task_count"`
	PoolCount         int                                `json:"pool_count"`
	ReceivedAt        *time.Time                         `json:"received_at,omitempty"`
	ObservedAt        *time.Time                         `json:"observed_at,omitempty"`
	ReceiptJobID      *int64                             `json:"receipt_job_id,omitempty"`
	Attempt           *int                               `json:"attempt,omitempty"`
	ReceiptStatement  string                             `json:"receipt_statement,omitempty"`
	ReceiptSignature  string                             `json:"receipt_signature_base64,omitempty"`
	SignerFingerprint string                             `json:"signer_fingerprint,omitempty"`
}

// ApplyServiceDependentHostSavedTx projects the source sequence as its revision.
func (s *Store) ApplyServiceDependentHostSavedTx(ctx context.Context, tx pgx.Tx, tenantID string, account servicedependents.AccountBinding, agentID string, enabled bool, actor string, at time.Time, sequence uint64) error {
	if sequence == 0 || sequence > math.MaxInt64 {
		return errors.New("store: invalid host binding source sequence")
	}
	binding := servicedependents.HostBinding{Account: account, AgentID: agentID, Revision: int64(sequence), Enabled: enabled}
	if err := binding.Validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(binding)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO service_account_hosts(tenant_id,account_id,agent_id,binding,revision,enabled,saved_by,updated_at)
 VALUES($1,$2,$3,$4::jsonb,$5,$6,$7,$8)
 ON CONFLICT(tenant_id,account_id,agent_id) DO UPDATE SET binding=EXCLUDED.binding,revision=EXCLUDED.revision,enabled=EXCLUDED.enabled,saved_by=EXCLUDED.saved_by,updated_at=EXCLUDED.updated_at
 WHERE service_account_hosts.tenant_id=$1 AND service_account_hosts.revision<EXCLUDED.revision`, tenantID, account.AccountID, agentID, raw, binding.Revision, enabled, actor, at)
	if err != nil {
		return err
	}
	current, err := getServiceDependentHostTx(ctx, tx, tenantID, account.AccountID, agentID)
	if err != nil {
		return err
	}
	digest, err := current.Binding.Digest()
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE service_account_host_scans SET status='superseded' WHERE tenant_id=$1 AND account_id=$2 AND agent_id=$3 AND binding_digest<>$4 AND status IN ('queued','retrying')`, tenantID, account.AccountID, agentID, digest)
	return err
}
func getServiceDependentHostTx(ctx context.Context, tx pgx.Tx, tenantID, accountID, agentID string) (ServiceDependentHost, error) {
	var value ServiceDependentHost
	var raw []byte
	err := tx.QueryRow(ctx, `SELECT binding,saved_by,updated_at FROM service_account_hosts WHERE tenant_id=$1 AND account_id=$2 AND agent_id=$3`, tenantID, accountID, agentID).Scan(&raw, &value.SavedBy, &value.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return value, ErrServiceDependentHostNotFound
	}
	if err != nil {
		return value, err
	}
	if err = json.Unmarshal(raw, &value.Binding); err != nil {
		return value, err
	}
	if err := value.Binding.Validate(); err != nil {
		return value, err
	}
	value.BindingDigest, err = value.Binding.Digest()
	return value, err
}
func (s *Store) GetServiceDependentHost(ctx context.Context, tenantID, accountID, agentID string) (ServiceDependentHost, error) {
	var value ServiceDependentHost
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		value, err = getServiceDependentHostTx(ctx, tx, tenantID, accountID, agentID)
		return err
	})
	return value, err
}

// MaxDiscoveryDependentHosts bounds the enabled host bindings one AD
// discovery run refreshes (A267-O1).
const MaxDiscoveryDependentHosts = 4096

// ListEnabledServiceDependentHostsForProvider returns the enabled host
// bindings of a discovery source's current accounts, by account and host, at
// most limit (A267-O1).
func (s *Store) ListEnabledServiceDependentHostsForProvider(ctx context.Context, tenantID, providerID string, limit int) ([]ServiceDependentHost, error) {
	var values []ServiceDependentHost
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT h.binding,h.saved_by,h.updated_at FROM service_account_hosts h
 JOIN pam_discovered_accounts a ON a.tenant_id=h.tenant_id AND a.id=h.account_id
 WHERE h.tenant_id=$1 AND a.tenant_id=$1 AND a.provider_id=$2 AND a.removed_at IS NULL AND h.enabled
 ORDER BY h.account_id, h.agent_id LIMIT $3`, tenantID, providerID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var value ServiceDependentHost
			var raw []byte
			if err := rows.Scan(&raw, &value.SavedBy, &value.UpdatedAt); err != nil {
				return err
			}
			if err := json.Unmarshal(raw, &value.Binding); err != nil {
				return err
			}
			if err := value.Binding.Validate(); err != nil {
				return err
			}
			if value.BindingDigest, err = value.Binding.Digest(); err != nil {
				return err
			}
			values = append(values, value)
		}
		return rows.Err()
	})
	return values, err
}

func (s *Store) ListServiceDependentHosts(ctx context.Context, tenantID, accountID, after string, limit int) ([]ServiceDependentHost, error) {
	var values []ServiceDependentHost
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT binding,saved_by,updated_at FROM service_account_hosts WHERE tenant_id=$1 AND account_id=$2 AND agent_id>$3::uuid ORDER BY agent_id LIMIT $4`, tenantID, accountID, after, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var value ServiceDependentHost
			var raw []byte
			if err := rows.Scan(&raw, &value.SavedBy, &value.UpdatedAt); err != nil {
				return err
			}
			if err := json.Unmarshal(raw, &value.Binding); err != nil {
				return err
			}
			if err := value.Binding.Validate(); err != nil {
				return err
			}
			value.BindingDigest, err = value.Binding.Digest()
			if err != nil {
				return err
			}
			values = append(values, value)
		}
		return rows.Err()
	})
	return values, err
}

// ApplyServiceDependentScanQueuedTx commits queued state and the exact host
// outbox intent in the same projection transaction (AN-6).
func (s *Store) ApplyServiceDependentScanQueuedTx(ctx context.Context, tx pgx.Tx, tenantID, eventID string, intent servicedependents.InventoryIntent, actor string, at time.Time) error {
	if err := intent.Validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(intent)
	if err != nil {
		return err
	}
	host, err := getServiceDependentHostTx(ctx, tx, tenantID, intent.Binding.Account.AccountID, intent.Binding.AgentID)
	if err != nil {
		return err
	}
	current, err := host.Binding.Digest()
	if err != nil {
		return err
	}
	state := "queued"
	if current != intent.BindingDigest || !host.Binding.Enabled {
		state = "superseded"
	}
	_, err = tx.Exec(ctx, `INSERT INTO service_account_host_scans(tenant_id,id,account_id,agent_id,intent,binding_digest,status,queued_by,queued_at,queued_event_id)
 VALUES($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9,$10) ON CONFLICT(tenant_id,id) DO NOTHING`, tenantID, intent.RunID, intent.Binding.Account.AccountID, intent.Binding.AgentID, raw, intent.BindingDigest, state, actor, at, eventID)
	if err != nil {
		return err
	}
	var existingDigest, status string
	if err := tx.QueryRow(ctx, `SELECT binding_digest,status FROM service_account_host_scans WHERE tenant_id=$1 AND id=$2`, tenantID, intent.RunID).Scan(&existingDigest, &status); err != nil {
		return err
	}
	if existingDigest != intent.BindingDigest {
		return ErrIdempotencyConflict
	}
	if status != "queued" {
		return nil
	}
	key := "service-dependent-inventory:" + intent.RunID
	id, err := ensureSecretIntegrationOutboxTx(ctx, tx, tenantID, servicedependents.InventoryDestination, "service-dependent-host:"+intent.Binding.AgentID, key, raw)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE outbox SET required_agent_role='host',required_agent_id=$3 WHERE tenant_id=$1 AND id=$2
 AND (required_agent_role IS NULL OR required_agent_role='' OR required_agent_role='host')
 AND (required_agent_id IS NULL OR required_agent_id=$3)`, tenantID, id, intent.Binding.AgentID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("%w: host inventory outbox authority differs", ErrIdempotencyConflict)
	}
	_, err = tx.Exec(ctx, `UPDATE service_account_host_scans SET outbox_id=$3 WHERE tenant_id=$1 AND id=$2`, tenantID, intent.RunID, id)
	return err
}

const serviceDependentScanColumns = `id::text,intent,status,queued_by,queued_at,queued_event_id::text,outbox_id,report,report_digest,failure,service_count,task_count,pool_count,received_at,observed_at,receipt_job_id,job_attempt,receipt_statement,receipt_signature,signer_fingerprint,coalesce(observed_event_id::text,'')`

func scanServiceDependentScan(row pgx.Row) (ServiceDependentScan, error) {
	var value ServiceDependentScan
	var intent, report []byte
	err := row.Scan(&value.ID, &intent, &value.Status, &value.QueuedBy, &value.QueuedAt, &value.QueuedEventID, &value.OutboxID, &report, &value.ReportDigest, &value.Failure, &value.ServiceCount, &value.TaskCount, &value.PoolCount, &value.ReceivedAt, &value.ObservedAt, &value.ReceiptJobID, &value.Attempt, &value.ReceiptStatement, &value.ReceiptSignature, &value.SignerFingerprint, &value.ObservedEventID)
	if errors.Is(err, pgx.ErrNoRows) {
		return value, ErrServiceDependentScanNotFound
	}
	if err != nil {
		return value, err
	}
	if err = json.Unmarshal(intent, &value.Intent); err != nil {
		return value, err
	}
	if err = value.Intent.Validate(); err != nil {
		return value, err
	}
	if len(report) > 0 {
		var decoded servicedependents.InventoryReport
		if len(report) > 2<<20 {
			return value, errors.New("store: native inventory read exceeds bound")
		}
		if err := json.Unmarshal(report, &decoded); err != nil {
			return value, err
		}
		if err = decoded.Validate(value.Intent); err != nil {
			return value, err
		}
		value.Report = &decoded
	}
	return value, nil
}
func (s *Store) GetServiceDependentScan(ctx context.Context, tenantID, id string) (ServiceDependentScan, error) {
	var value ServiceDependentScan
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		value, err = scanServiceDependentScan(tx.QueryRow(ctx, "SELECT "+serviceDependentScanColumns+" FROM service_account_host_scans WHERE tenant_id=$1 AND id=$2", tenantID, id))
		if err != nil {
			return err
		}
		value.DeliveryStatus = "missing"
		if value.OutboxID == nil {
			return nil
		}
		err = tx.QueryRow(ctx, `SELECT status FROM outbox WHERE tenant_id=$1 AND id=$2 AND destination=$3 AND idempotency_key=$4`, tenantID, *value.OutboxID, servicedependents.InventoryDestination, "service-dependent-inventory:"+value.ID).Scan(&value.DeliveryStatus)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	})
	return value, err
}

// ApplyServiceDependentScanObservedTx retains one canonical signed observation.
// A later replay cannot replace the original fact with a different native read.
func (s *Store) ApplyServiceDependentScanObservedTx(ctx context.Context, tx pgx.Tx, tenantID string, jobID int64, attempt int, report servicedependents.InventoryReport, digest, statement, signature, fingerprint string, at time.Time, sourceEventIDs ...string) error {
	existing, err := scanServiceDependentScan(tx.QueryRow(ctx, "SELECT "+serviceDependentScanColumns+" FROM service_account_host_scans WHERE tenant_id=$1 AND id=$2 FOR UPDATE", tenantID, report.RunID))
	if err != nil {
		return err
	}
	if jobID <= 0 || attempt <= 0 {
		return errors.New("store: native inventory receipt names another job")
	}
	if err := report.Validate(existing.Intent); err != nil {
		return err
	}
	var sourceID any
	if len(sourceEventIDs) > 0 {
		if !dependentSourceEventID(sourceEventIDs[0]) {
			return errors.New("store: native observation source identity invalid")
		}
		sourceID = sourceEventIDs[0]
	}
	if existing.ReportDigest != "" {
		if existing.ReportDigest != digest || existing.Attempt == nil || *existing.Attempt != attempt || existing.ReceiptJobID == nil || *existing.ReceiptJobID != jobID {
			return ErrIdempotencyConflict
		}
		if sourceID != nil && existing.ObservedEventID == "" {
			_, err = tx.Exec(ctx, `UPDATE service_account_host_scans SET observed_event_id=$3 WHERE tenant_id=$1 AND id=$2 AND observed_event_id IS NULL`, tenantID, report.RunID, sourceID)
			return err
		}
		return nil
	}
	raw, err := json.Marshal(report)
	if err != nil {
		return err
	}
	state := "partial"
	if report.Complete() {
		state = "complete"
	}
	host, err := getServiceDependentHostTx(ctx, tx, tenantID, existing.Intent.Binding.Account.AccountID, existing.Intent.Binding.AgentID)
	if err != nil {
		return err
	}
	current, err := host.Binding.Digest()
	if err != nil {
		return err
	}
	if current != existing.Intent.BindingDigest || !host.Binding.Enabled {
		state = "superseded"
	}
	_, err = tx.Exec(ctx, `UPDATE service_account_host_scans SET status=$3,report=$4::jsonb,report_digest=$5,failure='',
 service_count=$6,task_count=$7,pool_count=$8,received_at=$9,observed_at=$10,job_attempt=$11,
 receipt_statement=$12,receipt_signature=$13,signer_fingerprint=$14,receipt_job_id=$15,observed_event_id=$16
 WHERE tenant_id=$1 AND id=$2`, tenantID, report.RunID, state, raw, digest, len(report.Services), len(report.Tasks), len(report.Pools), at, report.ObservedAt, attempt, statement, signature, fingerprint, jobID, sourceID)
	if err != nil {
		return err
	}
	// A restored source observation retires only a recreated, unclaimed intent.
	// Live reports still close their exact leased claim through CompleteAgentJobClaim.
	if existing.OutboxID != nil {
		_, err = tx.Exec(ctx, `UPDATE outbox SET status='delivered',delivered_at=COALESCE(delivered_at,$3),worker_id=NULL,lease_until=NULL
   WHERE tenant_id=$1 AND id=$2 AND status='pending' AND delivered_at IS NULL AND claimed_by_agent_id IS NULL`, tenantID, *existing.OutboxID, at)
	}
	return err
}
func (s *Store) ApplyServiceDependentScanFailedTx(ctx context.Context, tx pgx.Tx, tenantID, runID string, jobID int64, attempt int, reason, statement, signature, fingerprint string, at time.Time) error {
	_, err := tx.Exec(ctx, `UPDATE service_account_host_scans SET status=CASE WHEN $5='invalid_native_report' THEN 'failed' ELSE 'retrying' END,failure=$5,job_attempt=$4,received_at=$6,
 receipt_statement=$7,receipt_signature=$8,signer_fingerprint=$9,receipt_job_id=$3
 WHERE tenant_id=$1 AND id=$2 AND report_digest='' AND status<>'superseded'
 AND (job_attempt IS NULL OR job_attempt<=$4)`, tenantID, runID, jobID, attempt, reason, at, statement, signature, fingerprint)
	if err != nil || reason != "invalid_native_report" {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE outbox SET status='failed',last_error='invalid_native_report',worker_id=NULL,lease_until=NULL
 WHERE tenant_id=$1 AND destination=$2 AND idempotency_key=$3 AND status='pending' AND delivered_at IS NULL AND claimed_by_agent_id IS NULL`, tenantID, servicedependents.InventoryDestination, "service-dependent-inventory:"+runID)
	return err
}

// LatestServiceDependentScans reads bounded summaries for one page of selected
// hosts. Full signed metadata is fetched only for the exact chosen scan.
func (s *Store) LatestServiceDependentScans(ctx context.Context, tenantID, accountID string, agents []string) (map[string]ServiceDependentScanHead, error) {
	result := map[string]ServiceDependentScanHead{}
	if len(agents) == 0 {
		return result, nil
	}
	if len(agents) > 256 {
		return nil, errors.New("store: host scan summary page exceeds bound")
	}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT DISTINCT ON(s.agent_id) s.id::text,s.agent_id::text,s.binding_digest,s.status,s.failure,s.queued_at,s.received_at,s.service_count,s.task_count,s.pool_count,COALESCE(o.status,'missing')
   FROM service_account_host_scans s LEFT JOIN outbox o ON o.tenant_id=$1 AND o.tenant_id=s.tenant_id AND o.id=s.outbox_id AND o.destination='host.windows_dependents.inventory' AND o.idempotency_key='service-dependent-inventory:'||s.id::text
   WHERE s.tenant_id=$1 AND s.account_id=$2 AND s.agent_id=ANY($3::uuid[])
   ORDER BY s.agent_id,s.queued_at DESC,s.id DESC`, tenantID, accountID, agents)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var value ServiceDependentScanHead
			if err := rows.Scan(&value.ID, &value.AgentID, &value.BindingDigest, &value.Status, &value.Failure, &value.QueuedAt, &value.ReceivedAt, &value.ServiceCount, &value.TaskCount, &value.PoolCount, &value.DeliveryStatus); err != nil {
				return err
			}
			result[value.AgentID] = value
		}
		return rows.Err()
	})
	return result, err
}

func dependentSourceEventID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '.' && r != '_' && r != ':' && r != '-' {
			return false
		}
	}
	return true
}
