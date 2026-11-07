// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"strconv"
	"strings"
	"time"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/hostaccounts"
	"trstctl.com/trstctl/internal/pamdiscovery"
)

var ErrWindowsLocalAccountScanNotFound = errors.New("store: Windows local-account scan not found")

type WindowsLocalAccountScan struct {
	ID                string                        `json:"id"`
	Intent            hostaccounts.InventoryIntent  `json:"intent"`
	Status            string                        `json:"status"`
	DeliveryStatus    string                        `json:"delivery_status"`
	QueuedBy          string                        `json:"queued_by"`
	QueuedAt          time.Time                     `json:"queued_at"`
	QueuedEventID     string                        `json:"queued_event_id"`
	OutboxID          *int64                        `json:"outbox_id,omitempty"`
	Report            *hostaccounts.InventoryReport `json:"report,omitempty"`
	ReportDigest      string                        `json:"report_digest,omitempty"`
	Failure           string                        `json:"failure,omitempty"`
	ReceivedAt        *time.Time                    `json:"received_at,omitempty"`
	ReceiptJobID      *int64                        `json:"receipt_job_id,omitempty"`
	Attempt           *int                          `json:"attempt,omitempty"`
	ReceiptStatement  string                        `json:"receipt_statement,omitempty"`
	ReceiptSignature  string                        `json:"receipt_signature_base64,omitempty"`
	SignerFingerprint string                        `json:"signer_fingerprint,omitempty"`
	ObservedEventID   string                        `json:"observed_event_id,omitempty"`
}

func WindowsHostAccountProviderID(agentID string) string { return "windows-host:" + agentID }

const windowsLocalScanColumns = `id::text,intent,status,queued_by,queued_at,queued_event_id::text,outbox_id,report,report_digest,failure,received_at,receipt_job_id,job_attempt,receipt_statement,receipt_signature,signer_fingerprint,coalesce(observed_event_id::text,''),COALESCE((SELECT o.status FROM outbox o WHERE o.tenant_id=$1 AND o.tenant_id=windows_local_account_scans.tenant_id AND o.id=windows_local_account_scans.outbox_id AND o.destination='host.windows_local_accounts.inventory' AND o.idempotency_key='windows-local-inventory:'||windows_local_account_scans.id::text),'missing')`

func scanWindowsLocalAccountScan(row pgx.Row) (WindowsLocalAccountScan, error) {
	var v WindowsLocalAccountScan
	var intent, report []byte
	err := row.Scan(&v.ID, &intent, &v.Status, &v.QueuedBy, &v.QueuedAt, &v.QueuedEventID, &v.OutboxID, &report, &v.ReportDigest, &v.Failure, &v.ReceivedAt, &v.ReceiptJobID, &v.Attempt, &v.ReceiptStatement, &v.ReceiptSignature, &v.SignerFingerprint, &v.ObservedEventID, &v.DeliveryStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		return v, ErrWindowsLocalAccountScanNotFound
	}
	if err != nil {
		return v, err
	}
	v.Intent, err = hostaccounts.DecodeInventoryIntent(intent)
	if err != nil {
		return v, err
	}
	if len(report) > 0 {
		var compact bytes.Buffer
		if e := json.Compact(&compact, report); e != nil {
			return v, e
		}
		observed, e := hostaccounts.DecodeInventoryReport(compact.Bytes())
		if e != nil {
			return v, e
		}
		if e = observed.Validate(v.Intent); e != nil {
			return v, e
		}
		canonical, e := json.Marshal(observed)
		if e != nil || crypto.SHA256Hex(canonical) != v.ReportDigest {
			return v, errors.New("store: native inventory report digest differs")
		}
		v.Report = &observed
	}
	return v, nil
}

// ApplyWindowsLocalAccountScanQueuedTx creates the read model and exact-host
// outbox intent together. No external read occurs in this transaction.
func (s *Store) ApplyWindowsLocalAccountScanQueuedTx(ctx context.Context, tx pgx.Tx, tenantID, eventID string, intent hostaccounts.InventoryIntent, actor string, at time.Time) error {
	if err := intent.Validate(); err != nil {
		return err
	}
	if intent.TenantID != tenantID || eventID != intent.RunID || actor == "" || at.IsZero() {
		return ErrIdempotencyConflict
	}
	raw, err := json.Marshal(intent)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO windows_local_account_scans(tenant_id,id,agent_id,intent,status,queued_by,queued_at,queued_event_id)
 VALUES($1,$2,$3,$4::jsonb,'queued',$5,$6,$2) ON CONFLICT(tenant_id,id) DO NOTHING`, tenantID, intent.RunID, intent.AgentID, raw, actor, at)
	if err != nil {
		return err
	}
	existing, err := scanWindowsLocalAccountScan(tx.QueryRow(ctx, "SELECT "+windowsLocalScanColumns+" FROM windows_local_account_scans WHERE tenant_id=$1 AND id=$2", tenantID, intent.RunID))
	if err != nil {
		return err
	}
	if existing.Intent != intent || !existing.QueuedAt.Equal(at) {
		return ErrIdempotencyConflict
	}
	if existing.Status != "queued" {
		return nil
	}
	provider := WindowsHostAccountProviderID(intent.AgentID)
	if err = s.ApplyPAMDiscoverySourceSavedTx(ctx, tx, tenantID, PAMDiscoverySource{ProviderID: provider, ProviderType: "windows_local", SavedBy: actor, SavedAt: at}); err != nil {
		return err
	}
	// Pending host reads live in the exact-host scan model. The generic
	// discovery timeline receives only observed completions/failures, so a
	// terminal delivery failure cannot strand its provider's queued uniqueness.
	id, err := ensureSecretIntegrationOutboxTx(ctx, tx, tenantID, hostaccounts.InventoryDestination, "windows-local-host:"+intent.AgentID, "windows-local-inventory:"+intent.RunID, raw)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE outbox SET required_agent_role='host',required_agent_id=$3 WHERE tenant_id=$1 AND id=$2
 AND (required_agent_role IS NULL OR required_agent_role='' OR required_agent_role='host') AND (required_agent_id IS NULL OR required_agent_id=$3)`, tenantID, id, intent.AgentID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrIdempotencyConflict
	}
	_, err = tx.Exec(ctx, `UPDATE windows_local_account_scans SET outbox_id=$3 WHERE tenant_id=$1 AND id=$2`, tenantID, intent.RunID, id)
	return err
}
func (s *Store) GetWindowsLocalAccountScan(ctx context.Context, tenantID, id string) (WindowsLocalAccountScan, error) {
	var value WindowsLocalAccountScan
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		value, err = scanWindowsLocalAccountScan(tx.QueryRow(ctx, "SELECT "+windowsLocalScanColumns+" FROM windows_local_account_scans WHERE tenant_id=$1 AND id=$2", tenantID, id))
		return err
	})
	return value, err
}

func (s *Store) PendingWindowsLocalAccountScan(ctx context.Context, tenantID, agentID string) (bool, error) {
	var pending bool
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM windows_local_account_scans s JOIN outbox o ON o.tenant_id=s.tenant_id AND o.id=s.outbox_id WHERE s.tenant_id=$1 AND s.agent_id=$2 AND s.status IN ('queued','retrying') AND o.status IN ('pending','claimed'))`, tenantID, agentID).Scan(&pending)
	})
	return pending, err
}
func (s *Store) ListWindowsLocalAccountScans(ctx context.Context, tenantID, agentID, after string, limit int) ([]WindowsLocalAccountScan, error) {
	var values []WindowsLocalAccountScan
	// The summary query never loads full native reports into memory.
	heads := strings.Replace(windowsLocalScanColumns, ",report,", ",NULL::jsonb,", 1)
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, "SELECT "+heads+" FROM windows_local_account_scans WHERE tenant_id=$1 AND agent_id=$2 AND id>$3::uuid ORDER BY id LIMIT $4", tenantID, agentID, after, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			v, err := scanWindowsLocalAccountScan(rows)
			if err != nil {
				return err
			}
			values = append(values, v)
		}
		return rows.Err()
	})
	return values, err
}

// ApplyWindowsLocalAccountScanObservedTx retains the exact signed fact and feeds
// the existing staged privileged-account model. Failed reads never remove rows.
func (s *Store) ApplyWindowsLocalAccountScanObservedTx(ctx context.Context, tx pgx.Tx, tenantID, eventID string, jobID int64, attempt int, report hostaccounts.InventoryReport, digest, statement, signature, fingerprint string, at time.Time) error {
	v, err := scanWindowsLocalAccountScan(tx.QueryRow(ctx, "SELECT "+windowsLocalScanColumns+" FROM windows_local_account_scans WHERE tenant_id=$1 AND id=$2 FOR UPDATE", tenantID, report.RunID))
	if err != nil {
		return err
	}
	if err = report.Validate(v.Intent); err != nil {
		return err
	}
	if v.ReportDigest != "" {
		if v.ReportDigest != digest || v.ReceiptJobID == nil || *v.ReceiptJobID != jobID || v.Attempt == nil || *v.Attempt != attempt {
			return ErrIdempotencyConflict
		}
		return nil
	}
	state := "failed"
	var accounts []pamdiscovery.Account
	if report.Status == "complete" {
		state = "complete"
		for _, account := range report.Inventory.Accounts {
			accounts = append(accounts, pamdiscovery.Account{Key: "sid:" + account.SID, Name: account.Name, Kind: pamdiscovery.KindLocalUser, Privileges: []string{"local_administrator"}, Disabled: !account.Enabled, Details: map[string]string{"agent_id": v.Intent.AgentID, "native_sid": account.SID, "machine_sid": report.Inventory.Machine.SID, "machine_name": report.Inventory.Machine.Name, "locked": strconv.FormatBool(account.Locked), "password_required": strconv.FormatBool(account.PasswordRequired)}})
		}
	}
	raw, err := json.Marshal(report)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE windows_local_account_scans SET status=$3,report=$4::jsonb,report_digest=$5,failure=$6,received_at=$7,receipt_job_id=$8,job_attempt=$9,receipt_statement=$10,receipt_signature=$11,signer_fingerprint=$12,observed_event_id=$13 WHERE tenant_id=$1 AND id=$2`, tenantID, report.RunID, state, raw, digest, report.Failure, at, jobID, attempt, statement, signature, fingerprint, eventID)
	if err != nil {
		return err
	}
	runState := "failed"
	if state == "complete" {
		runState = "completed"
	}
	if err = s.ApplyPAMDiscoveryRunTx(ctx, tx, tenantID, PAMDiscoveryRun{ID: v.ID, ProviderID: WindowsHostAccountProviderID(v.Intent.AgentID), Status: runState, Failure: report.Failure, StartedAt: v.QueuedAt, FinishedAt: at, RequestedBy: v.QueuedBy}, pamdiscovery.Normalize(accounts)); err != nil {
		return err
	}
	if err = s.bindWindowsDiscoveryOutboxTx(ctx, tx, tenantID, v); err != nil {
		return err
	}
	if v.OutboxID != nil {
		_, err = tx.Exec(ctx, `UPDATE outbox SET status='delivered',delivered_at=COALESCE(delivered_at,$3),worker_id=NULL,lease_until=NULL WHERE tenant_id=$1 AND id=$2 AND status='pending' AND delivered_at IS NULL AND claimed_by_agent_id IS NULL`, tenantID, *v.OutboxID, at)
	}
	return err
}
func (s *Store) ApplyWindowsLocalAccountScanFailedTx(ctx context.Context, tx pgx.Tx, tenantID, runID, eventID string, jobID int64, attempt int, reason, statement, signature, fingerprint string, at time.Time) error {
	state := "retrying"
	if reason == "invalid_native_report" {
		state = "failed"
	}
	tag, err := tx.Exec(ctx, `UPDATE windows_local_account_scans SET status=$3,failure=$4,received_at=$5,receipt_job_id=$6,job_attempt=$7,receipt_statement=$8,receipt_signature=$9,signer_fingerprint=$10,observed_event_id=$11 WHERE tenant_id=$1 AND id=$2 AND report_digest='' AND (job_attempt IS NULL OR job_attempt<=$7)`, tenantID, runID, state, reason, at, jobID, attempt, statement, signature, fingerprint, eventID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return nil
	}
	if state == "failed" {
		v, readErr := scanWindowsLocalAccountScan(tx.QueryRow(ctx, "SELECT "+windowsLocalScanColumns+" FROM windows_local_account_scans WHERE tenant_id=$1 AND id=$2", tenantID, runID))
		if readErr != nil {
			return readErr
		}
		if err = s.ApplyPAMDiscoveryRunTx(ctx, tx, tenantID, PAMDiscoveryRun{ID: runID, ProviderID: WindowsHostAccountProviderID(v.Intent.AgentID), Status: "failed", Failure: reason, StartedAt: v.QueuedAt, FinishedAt: at, RequestedBy: v.QueuedBy}, nil); err != nil {
			return err
		}
		if err = s.bindWindowsDiscoveryOutboxTx(ctx, tx, tenantID, v); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE outbox SET status='failed',last_error=$4,worker_id=NULL,lease_until=NULL WHERE tenant_id=$1 AND destination=$2 AND idempotency_key=$3 AND status='pending' AND delivered_at IS NULL AND claimed_by_agent_id IS NULL`, tenantID, hostaccounts.InventoryDestination, "windows-local-inventory:"+runID, reason)
	}
	return err
}

func (s *Store) LatestWindowsLocalAccountScan(ctx context.Context, tenantID, agentID string) (WindowsLocalAccountScan, error) {
	var value WindowsLocalAccountScan
	heads := strings.Replace(windowsLocalScanColumns, ",report,", ",NULL::jsonb,", 1)
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		value, err = scanWindowsLocalAccountScan(tx.QueryRow(ctx, "SELECT "+heads+" FROM windows_local_account_scans WHERE tenant_id=$1 AND agent_id=$2 ORDER BY queued_at DESC,id DESC LIMIT 1", tenantID, agentID))
		return err
	})
	return value, err
}

func (s *Store) bindWindowsDiscoveryOutboxTx(ctx context.Context, tx pgx.Tx, tenantID string, v WindowsLocalAccountScan) error {
	if v.OutboxID == nil {
		return nil
	}
	_, err := tx.Exec(ctx, `UPDATE pam_discovery_runs SET outbox_id=$3 WHERE tenant_id=$1 AND id=$2`, tenantID, v.ID, *v.OutboxID)
	return err
}

// WindowsLocalAccountHost is the public picker projection. It intentionally
// excludes transport configuration, plug-in grants and general agent posture.
type WindowsLocalAccountHost struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Status     string     `json:"status"`
	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`
}

func (s *Store) ListWindowsLocalAccountHosts(ctx context.Context, tenantID, after string, limit int) ([]WindowsLocalAccountHost, error) {
	values := []WindowsLocalAccountHost{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id::text,name,status,last_seen_at FROM agents WHERE tenant_id=$1 AND id>$2::uuid AND offboarded_at IS NULL AND roles @> ARRAY['host']::text[] ORDER BY id LIMIT $3`, tenantID, after, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var v WindowsLocalAccountHost
			if err := rows.Scan(&v.ID, &v.Name, &v.Status, &v.LastSeenAt); err != nil {
				return err
			}
			values = append(values, v)
		}
		return rows.Err()
	})
	return values, err
}
