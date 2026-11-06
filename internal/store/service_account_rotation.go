// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"strings"
	"time"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/servicedependents"
)

var ErrServiceDependentRotationNotFound = errors.New("store: service-account rotation not found")
var ErrServiceDependentStepFailed = errors.New("store: dependent native step failed or remains uncertain")
var ErrServiceDependentStepNotFound = errors.New("store: service-account rotation step not found")

type ServiceDependentRotation struct {
	DirectoryApplyStarted bool                             `json:"directory_apply_started"`
	DirectoryRestored     bool                             `json:"directory_restored"`
	TenantID              string                           `json:"-"`
	ID                    string                           `json:"id"`
	Intent                servicedependents.RotationIntent `json:"intent"`
	IntentDigest          string                           `json:"intent_digest"`
	CommandID             string                           `json:"command_id"`
	TenantEpoch           string                           `json:"tenant_epoch"`
	Direction             string                           `json:"direction"`
	Actor                 string                           `json:"actor"`
	Failure               string                           `json:"failure,omitempty"`
	CreatedAt             time.Time                        `json:"created_at"`
	UpdatedAt             time.Time                        `json:"updated_at"`
}
type ServiceDependentStep struct {
	DeliveryStatus    string                         `json:"delivery_status,omitempty"`
	Intent            servicedependents.RotationStep `json:"intent"`
	Status            string                         `json:"status"`
	OutboxID          *int64                         `json:"outbox_id,omitempty"`
	Report            *servicedependents.StepReport  `json:"report,omitempty"`
	ReceiptJobID      *int64                         `json:"receipt_job_id,omitempty"`
	Attempt           *int                           `json:"attempt,omitempty"`
	ReceiptStatement  string                         `json:"receipt_statement,omitempty"`
	ReceiptSignature  string                         `json:"receipt_signature_base64,omitempty"`
	SignerFingerprint string                         `json:"signer_fingerprint,omitempty"`
	QueuedAt          time.Time                      `json:"queued_at"`
	ReceivedAt        *time.Time                     `json:"received_at,omitempty"`
}

// ServiceDependentRotationInputsTx returns exact retained scans. Complete host
// enumeration has no fixed fleet count; the reviewed wire intent bounds memory.
func (s *Store) ServiceDependentRotationInputsTx(ctx context.Context, tx pgx.Tx, tenantID string, intent servicedependents.RotationIntent) ([]servicedependents.RotationHostInput, error) {
	var inputs []servicedependents.RotationHostInput
	for _, host := range intent.Plan.Hosts {
		scan, e := scanServiceDependentScan(tx.QueryRow(ctx, "SELECT "+serviceDependentScanColumns+" FROM service_account_host_scans WHERE tenant_id=$1 AND id=$2", tenantID, host.InventoryRunID))
		if e != nil {
			return nil, e
		}
		if scan.Status != "complete" || scan.Report == nil || scan.Intent.Binding != host.Binding || scan.ReportDigest != host.InventoryDigest {
			return nil, errors.New("store: rotation inventory source differs")
		}
		inputs = append(inputs, servicedependents.RotationHostInput{Binding: host.Binding, Inventory: *scan.Report, InventoryDigest: scan.ReportDigest})
	}
	if e := intent.Validate(inputs); e != nil {
		return nil, e
	}
	return inputs, nil
}
func (s *Store) ValidateServiceDependentRotationSourcesTx(ctx context.Context, tx pgx.Tx, tenantID string, intent servicedependents.RotationIntent, current bool) error {
	if _, e := s.ServiceDependentRotationInputsTx(ctx, tx, tenantID, intent); e != nil {
		return e
	}
	if !current {
		return nil
	}
	rows, e := tx.Query(ctx, `SELECT binding FROM service_account_hosts WHERE tenant_id=$1 AND account_id=$2 AND enabled ORDER BY agent_id`, tenantID, intent.Plan.Account.AccountID)
	if e != nil {
		return e
	}
	defer rows.Close()
	i := 0
	for rows.Next() {
		var raw []byte
		var binding servicedependents.HostBinding
		if e := rows.Scan(&raw); e != nil {
			return e
		}
		if e := json.Unmarshal(raw, &binding); e != nil {
			return e
		}
		if i >= len(intent.Plan.Hosts) || binding != intent.Plan.Hosts[i].Binding {
			return errors.New("store: enabled native host set changed before rotation")
		}
		i++
	}
	if e := rows.Err(); e != nil {
		return e
	}
	if i != len(intent.Plan.Hosts) {
		return errors.New("store: selected native host removed before rotation")
	}
	return nil
}
func (s *Store) ApplyServiceDependentRotationQueuedTx(ctx context.Context, tx pgx.Tx, parent ServiceDependentRotation) error {
	digest, e := parent.Intent.Digest()
	if e != nil {
		return e
	}
	if parent.ID != parent.Intent.Plan.ID || parent.CommandID != parent.ID || parent.IntentDigest != digest || !dependentCanonicalUUID(parent.CommandID) || parent.TenantEpoch == "" || parent.Actor == "" || parent.CreatedAt.IsZero() || parent.Direction != servicedependents.Forward {
		return errors.New("store: incomplete dependent rotation authority")
	}
	// The child-command index is also unique. Lock that exact authority before
	// an identical replay can contend on either index.
	if _, e := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "service-dependent-parent:"+parent.TenantID+":"+parent.CommandID); e != nil {
		return e
	}
	var existingID string
	e = tx.QueryRow(ctx, `SELECT id::text FROM service_account_rotations WHERE tenant_id=$1 AND command_id=$2`, parent.TenantID, parent.CommandID).Scan(&existingID)
	if e == nil && existingID != parent.ID {
		return ErrIdempotencyConflict
	}
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return e
	}
	// An event replay after the host catalogue changes reconstructs history. New
	// admission additionally checks the current catalogue before appending source.
	if e := s.ValidateServiceDependentRotationSourcesTx(ctx, tx, parent.TenantID, parent.Intent, false); e != nil {
		return e
	}
	raw, e := json.Marshal(parent.Intent)
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `INSERT INTO service_account_rotations(tenant_id,id,intent,intent_digest,command_id,tenant_epoch,direction,actor,created_at,updated_at)
 VALUES($1,$2,$3::jsonb,$4,$5,$6,'forward',$7,$8,$8) ON CONFLICT(tenant_id,id) DO NOTHING`, parent.TenantID, parent.ID, raw, digest, parent.CommandID, parent.TenantEpoch, parent.Actor, parent.CreatedAt)
	if e != nil {
		return e
	}
	existing, e := s.GetServiceDependentRotationTx(ctx, tx, parent.TenantID, parent.ID)
	if e != nil {
		return e
	}
	if existing.IntentDigest != digest || existing.CommandID != parent.CommandID || existing.TenantEpoch != parent.TenantEpoch {
		return ErrIdempotencyConflict
	}
	return nil
}
func (s *Store) GetServiceDependentRotationTx(ctx context.Context, tx pgx.Tx, tenantID, id string) (ServiceDependentRotation, error) {
	var v ServiceDependentRotation
	var raw []byte
	e := tx.QueryRow(ctx, `SELECT id::text,intent,intent_digest,command_id::text,tenant_epoch,direction,actor,failure,created_at,updated_at,directory_restored,directory_apply_started FROM service_account_rotations WHERE tenant_id=$1 AND id=$2`, tenantID, id).Scan(&v.ID, &raw, &v.IntentDigest, &v.CommandID, &v.TenantEpoch, &v.Direction, &v.Actor, &v.Failure, &v.CreatedAt, &v.UpdatedAt, &v.DirectoryRestored, &v.DirectoryApplyStarted)
	if errors.Is(e, pgx.ErrNoRows) {
		return v, ErrServiceDependentRotationNotFound
	}
	if e != nil {
		return v, e
	}
	if e = json.Unmarshal(raw, &v.Intent); e != nil {
		return v, e
	}
	v.TenantID = tenantID
	digest, e := v.Intent.Digest()
	if e != nil {
		return v, e
	}
	if digest != v.IntentDigest || v.ID != v.Intent.Plan.ID {
		return v, errors.New("store: retained dependent rotation binding differs")
	}
	return v, nil
}
func (s *Store) GetServiceDependentRotation(ctx context.Context, tenantID, id string) (ServiceDependentRotation, error) {
	var v ServiceDependentRotation
	e := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var e error
		v, e = s.GetServiceDependentRotationTx(ctx, tx, tenantID, id)
		return e
	})
	return v, e
}
func (s *Store) ApplyServiceDependentRotationInverseTx(ctx context.Context, tx pgx.Tx, tenantID, id, digest, failure string, at time.Time) error {
	switch failure {
	case "dependent_failed", "dependent_uncertain", "native_apply_failed", "source_changed", "deadline_expired", "vault_version_changed":
	default:
		return errors.New("store: unknown dependent inverse reason")
	}
	tag, e := tx.Exec(ctx, `UPDATE service_account_rotations SET direction='inverse',failure=CASE WHEN direction='forward' THEN $4 ELSE failure END,updated_at=$5 WHERE tenant_id=$1 AND id=$2 AND intent_digest=$3`, tenantID, id, digest, failure, at)
	if e != nil {
		return e
	}
	if tag.RowsAffected() != 1 {
		return ErrIdempotencyConflict
	}
	// Forward retry authority ends with the source-selected inverse. Otherwise a
	// failed forward row can repeatedly claim the host quota ahead of its repair.
	_, e = tx.Exec(ctx, `UPDATE outbox o SET status='cancelled',worker_id=NULL,lease_until=NULL,
 claimed_by_agent_id=NULL,claim_expires_at=NULL,claim_completed_at=COALESCE(claim_completed_at,$4)
 FROM service_account_rotation_steps s
 WHERE o.tenant_id=$1 AND s.tenant_id=$1 AND s.rotation_id=$2 AND s.direction='forward'
 AND o.id=s.outbox_id AND o.destination=$3
 AND o.idempotency_key='service-dependent-step:'||$2::text||':'||s.step_id
 AND o.status='pending'`, tenantID, id, servicedependents.RotationDestination, at)
	return e
}

const dependentStepColumns = `intent,status,outbox_id,report,receipt_job_id,job_attempt,receipt_statement,receipt_signature,signer_fingerprint,queued_at,received_at`

func scanDependentStep(row pgx.Row, delivery ...bool) (ServiceDependentStep, error) {
	var v ServiceDependentStep
	var raw, report []byte
	fields := []any{&raw, &v.Status, &v.OutboxID, &report, &v.ReceiptJobID, &v.Attempt, &v.ReceiptStatement, &v.ReceiptSignature, &v.SignerFingerprint, &v.QueuedAt, &v.ReceivedAt}
	if len(delivery) > 0 && delivery[0] {
		fields = append(fields, &v.DeliveryStatus)
	}
	e := row.Scan(fields...)
	if errors.Is(e, pgx.ErrNoRows) {
		return v, ErrServiceDependentStepNotFound
	}
	if e != nil {
		return v, e
	}
	if e = json.Unmarshal(raw, &v.Intent); e != nil {
		return v, e
	}
	if e = v.Intent.Validate(); e != nil {
		return v, e
	}
	if len(report) > 0 {
		v.Report = &servicedependents.StepReport{}
		if e = json.Unmarshal(report, v.Report); e != nil {
			return v, e
		}
		if e = v.Report.Validate(v.Intent); e != nil {
			return v, e
		}
	}
	return v, nil
}
func (s *Store) GetServiceDependentStepTx(ctx context.Context, tx pgx.Tx, tenantID, rotationID, stepID string) (ServiceDependentStep, error) {
	return scanDependentStep(tx.QueryRow(ctx, "SELECT "+dependentStepColumns+" FROM service_account_rotation_steps WHERE tenant_id=$1 AND rotation_id=$2 AND step_id=$3", tenantID, rotationID, stepID))
}
func (s *Store) GetServiceDependentStep(ctx context.Context, tenantID, rotationID, stepID string) (ServiceDependentStep, error) {
	var v ServiceDependentStep
	e := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var e error
		v, e = s.GetServiceDependentStepTx(ctx, tx, tenantID, rotationID, stepID)
		return e
	})
	return v, e
}

// NextServiceDependentStepTx is also the cutover/inverse barrier: only a complete
// sequence of validated signed receipts can return no remaining step.
func (s *Store) NextServiceDependentStepTx(ctx context.Context, tx pgx.Tx, parent ServiceDependentRotation, preflightOnly bool) (*servicedependents.RotationStep, error) {
	inputs, e := s.ServiceDependentRotationInputsTx(ctx, tx, parent.TenantID, parent.Intent)
	if e != nil {
		return nil, e
	}
	steps, e := parent.Intent.Steps(inputs, parent.Direction)
	if e != nil {
		return nil, e
	}
	for _, step := range steps {
		if preflightOnly && step.Action != servicedependents.Preflight {
			return nil, nil
		}
		saved, e := s.GetServiceDependentStepTx(ctx, tx, parent.TenantID, parent.ID, step.ID)
		if errors.Is(e, ErrServiceDependentStepNotFound) {
			return &step, nil
		}
		if e != nil {
			return nil, e
		}
		if saved.Status == "failed" || saved.Status == "uncertain" {
			return &saved.Intent, ErrServiceDependentStepFailed
		}
		if saved.Status != "succeeded" {
			return &saved.Intent, nil
		}
	}
	return nil, nil
}
func (s *Store) ApplyServiceDependentStepQueuedTx(ctx context.Context, tx pgx.Tx, tenantID string, step servicedependents.RotationStep, at time.Time) error {
	if e := step.Validate(); e != nil {
		return e
	}
	if step.Challenge == "" || at.IsZero() {
		return errors.New("store: native step has no fresh bounded execution authority")
	}
	parent, e := s.GetServiceDependentRotationTx(ctx, tx, tenantID, step.RotationID)
	if e != nil {
		return e
	}
	existing, readErr := s.GetServiceDependentStepTx(ctx, tx, tenantID, parent.ID, step.ID)
	if readErr == nil {
		a, _ := json.Marshal(existing.Intent)
		b, _ := json.Marshal(step)
		if crypto.SHA256Hex(a) != crypto.SHA256Hex(b) {
			return ErrIdempotencyConflict
		}
		return nil
	}
	if !errors.Is(readErr, ErrServiceDependentStepNotFound) {
		return readErr
	}
	next, e := s.NextServiceDependentStepTx(ctx, tx, parent, false)
	if e != nil {
		return e
	}
	if next == nil || next.ID != step.ID || step.Direction != parent.Direction {
		return errors.New("store: native step is outside the recorded sequence")
	}
	// The static child supplies sealed custody. A host effect cannot precede it.
	child, e := scanSecretStaticRotationCommand(tx.QueryRow(ctx, "SELECT "+secretStaticRotationColumns+" FROM secret_static_rotation_commands WHERE tenant_id=$1 AND id=$2 FOR UPDATE", tenantID, parent.CommandID))
	if e != nil {
		return e
	}
	if child.DependentChangeID != parent.ID || child.RequestBinding != parent.IntentDigest {
		return errors.New("store: native step has no exact sealed child")
	}
	// Static commands are retained operational fences during a read-model
	// rebuild. Their later phase may already exist while historical step source
	// replays. Live claim admission independently requires the current child phase.
	historical := !at.After(child.UpdatedAt) && secretStaticRotationPhaseRank(child.Phase) >= secretStaticRotationPhaseRank(SecretStaticRotationPrepared)
	if parent.Direction == servicedependents.Forward && !historical {
		if step.Action == servicedependents.Preflight && child.Phase != SecretStaticRotationPrepared || step.Action != servicedependents.Preflight && child.Phase != SecretStaticRotationStaged {
			return errors.New("store: native effect precedes its directory phase")
		}
	} else if parent.Direction == servicedependents.Inverse && (!parent.DirectoryRestored || !historical && child.Phase != SecretStaticRotationPrepared && child.Phase != SecretStaticRotationStaged && child.Phase != SecretStaticRotationCutover) {
		return errors.New("store: native inverse is outside recoverable child phases")
	}
	// The immutable snapshot and local probe cannot be changed while adding a lease.
	base := step
	base.Challenge = ""
	base.NotBefore = time.Time{}
	base.Deadline = time.Time{}
	base.PreviousPIDs = nil
	a, _ := json.Marshal(base)
	b, _ := json.Marshal(next)
	if crypto.SHA256Hex(a) != crypto.SHA256Hex(b) {
		return errors.New("store: issued native snapshot differs from reviewed sequence")
	}
	raw, e := json.Marshal(step)
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `INSERT INTO service_account_rotation_steps(tenant_id,rotation_id,step_id,intent,direction,status,queued_at) VALUES($1,$2,$3,$4::jsonb,$5,'queued',$6)`, tenantID, parent.ID, step.ID, raw, step.Direction, at)
	if e != nil {
		return e
	}
	id, e := ensureSecretIntegrationOutboxTx(ctx, tx, tenantID, servicedependents.RotationDestination, "service-dependent-host:"+step.Ref.AgentID, "service-dependent-step:"+parent.ID+":"+step.ID, raw)
	if e != nil {
		return e
	}
	tag, e := tx.Exec(ctx, `UPDATE outbox SET required_agent_role='host',required_agent_id=$3 WHERE tenant_id=$1 AND id=$2 AND (required_agent_role IS NULL OR required_agent_role='' OR required_agent_role='host') AND (required_agent_id IS NULL OR required_agent_id=$3)`, tenantID, id, step.Ref.AgentID)
	if e != nil {
		return e
	}
	if tag.RowsAffected() != 1 {
		return ErrIdempotencyConflict
	}
	_, e = tx.Exec(ctx, `UPDATE service_account_rotation_steps SET outbox_id=$4 WHERE tenant_id=$1 AND rotation_id=$2 AND step_id=$3`, tenantID, parent.ID, step.ID, id)
	return e
}
func (s *Store) ApplyServiceDependentStepObservedTx(ctx context.Context, tx pgx.Tx, tenantID string, jobID int64, attempt int, report servicedependents.StepReport, statement, signature, fingerprint string, at time.Time) error {
	if jobID <= 0 || attempt <= 0 {
		return errors.New("store: dependent native receipt has no exact job attempt")
	}
	saved, e := s.GetServiceDependentStepTx(ctx, tx, tenantID, report.RotationID, report.StepID)
	if e != nil {
		return e
	}
	if e := report.Validate(saved.Intent); e != nil {
		return e
	}
	raw, e := json.Marshal(report)
	if e != nil {
		return e
	}
	if saved.Status != "queued" {
		retained, _ := json.Marshal(saved.Report)
		if crypto.SHA256Hex(retained) != crypto.SHA256Hex(raw) || saved.ReceiptJobID == nil || *saved.ReceiptJobID != jobID || saved.Attempt == nil || *saved.Attempt != attempt {
			return ErrIdempotencyConflict
		}
		return nil
	}
	_, e = tx.Exec(ctx, `UPDATE service_account_rotation_steps SET status=$4,report=$5::jsonb,receipt_job_id=$6,job_attempt=$7,receipt_statement=$8,receipt_signature=$9,signer_fingerprint=$10,received_at=$11 WHERE tenant_id=$1 AND rotation_id=$2 AND step_id=$3 AND status='queued'`, tenantID, report.RotationID, report.StepID, report.Status, raw, jobID, attempt, statement, signature, fingerprint, at)
	if e != nil {
		return e
	}
	// Replay may recreate a different unclaimed operational row. Signed source
	// preserves the historical job identity; never reclaim its already observed work.
	_, e = tx.Exec(ctx, `UPDATE outbox SET status='delivered',delivered_at=$4 WHERE tenant_id=$1 AND destination=$2 AND idempotency_key=$3 AND claimed_by_agent_id IS NULL AND status='pending'`, tenantID, servicedependents.RotationDestination, "service-dependent-step:"+report.RotationID+":"+report.StepID, at)
	return e
}

func dependentCanonicalUUID(value string) bool {
	id, e := uuid.Parse(value)
	return e == nil && id != uuid.Nil && id.String() == value
}

func (s *Store) ApplyServiceDependentDirectoryRestoredTx(ctx context.Context, tx pgx.Tx, tenantID, id, digest string, at time.Time) error {
	if at.IsZero() {
		return errors.New("store: native inverse observation has no time")
	}
	tag, e := tx.Exec(ctx, `UPDATE service_account_rotations SET directory_restored=true,updated_at=$4 WHERE tenant_id=$1 AND id=$2 AND intent_digest=$3 AND direction='inverse'`, tenantID, id, digest, at)
	if e != nil {
		return e
	}
	if tag.RowsAffected() != 1 {
		return ErrIdempotencyConflict
	}
	return nil
}

// ListServiceDependentSteps pages retained native evidence and current delivery
// independently. Delivered alone never changes a step into verified work.
func (s *Store) ListServiceDependentSteps(ctx context.Context, tenantID, rotationID, after string, limit int) ([]ServiceDependentStep, error) {
	if limit < 1 || limit > 256 {
		return nil, errors.New("store: dependent step page limit must be 1-256")
	}
	if after != "" {
		raw, e := hex.DecodeString(after)
		if e != nil || len(raw) != 16 || after != strings.ToLower(after) {
			return nil, errors.New("store: dependent step cursor must be a canonical step ID")
		}
	}
	var result []ServiceDependentStep
	e := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT s.intent,s.status,s.outbox_id,s.report,s.receipt_job_id,s.job_attempt,
 s.receipt_statement,s.receipt_signature,s.signer_fingerprint,s.queued_at,s.received_at,coalesce(o.status,'missing')
 FROM service_account_rotation_steps s LEFT JOIN outbox o ON o.tenant_id=$1 AND o.tenant_id=s.tenant_id
 AND o.id=s.outbox_id AND o.destination=$5 AND o.idempotency_key='service-dependent-step:'||s.rotation_id::text||':'||s.step_id
 WHERE s.tenant_id=$1 AND s.rotation_id=$2 AND s.step_id>$3 ORDER BY s.step_id LIMIT $4`, tenantID, rotationID, after, limit+1, servicedependents.RotationDestination)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			v, e := scanDependentStep(rows, true)
			if e != nil {
				return e
			}
			result = append(result, v)
		}
		return rows.Err()
	})
	return result, e
}

func (s *Store) ApplyServiceDependentDirectoryApplyStartedTx(ctx context.Context, tx pgx.Tx, tenantID, id, digest string, at time.Time) error {
	parent, e := s.GetServiceDependentRotationTx(ctx, tx, tenantID, id)
	if e != nil {
		return e
	}
	if parent.IntentDigest != digest || at.IsZero() || at.Before(parent.CreatedAt) || at.After(parent.Intent.Plan.ExpiresAt) {
		return errors.New("store: native apply intent is outside its reviewed authority")
	}
	if parent.DirectoryApplyStarted {
		return nil
	}
	next, e := s.NextServiceDependentStepTx(ctx, tx, parent, true)
	if e != nil {
		return e
	}
	if next != nil {
		return errors.New("store: native apply intent precedes complete host preflight")
	}
	_, e = tx.Exec(ctx, `UPDATE service_account_rotations SET directory_apply_started=true,updated_at=$4 WHERE tenant_id=$1 AND id=$2 AND intent_digest=$3`, tenantID, id, digest, at)
	return e
}
