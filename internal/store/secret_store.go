// SPDX-License-Identifier: MPL-2.0

package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/privacy"
)

// ErrSecretNotFound is returned when no sealed application secret matches the
// requested tenant/name/version. State changes use the immutable event projector;
// the production store exposes no direct application-secret mutator.
var ErrSecretNotFound = errors.New("store: secret not found")

// ErrSecretShareNotFound is returned when a one-time share token hash is absent,
// expired, or already consumed.
var ErrSecretShareNotFound = errors.New("store: secret share not found")

// ErrApplicationSecretTenantEpochMismatch means an immutable command belongs to
// a prior registration of the same tenant UUID. The projector treats that old
// lifecycle event as an inert retained-history record; a live command reports a
// conflict and cannot mutate the newly registered tenant.
var ErrApplicationSecretTenantEpochMismatch = errors.New("store: application-secret tenant lifecycle epoch differs")

// ErrApplicationSecretMutationInFlight means one secret already has a different
// non-terminal command fence. The conflict is local to that secret: a scheduler
// may defer this row and continue other due work, while ordinary API callers still
// see the enclosing ErrIdempotencyConflict.
var ErrApplicationSecretMutationInFlight = errors.New("store: application-secret mutation is already in flight")

// Secret is a sealed (envelope-encrypted) application secret at rest in the served
// secret store (GAP-006 / the served secrets API). Sealed holds ciphertext only —
// the plaintext never lives in the store (AN-8). It is identified within a tenant
// by Name; Version is the monotonic rotation counter. Every operation is
// tenant-scoped under RLS (AN-1).
type Secret struct {
	ID        string
	TenantID  string
	Name      string
	Sealed    []byte // envelope-encrypted ciphertext; never plaintext
	Version   int
	CreatedAt time.Time
	UpdatedAt time.Time
}

// SecretVersion is one sealed historical version of an application secret. Sealed
// is ciphertext only; opening it happens through the crypto/seal boundary.
type SecretVersion struct {
	TenantID             string
	Name                 string
	Version              int
	Sealed               []byte
	WrittenAt            time.Time
	RecoveredFromVersion *int
}

// ApplicationSecretTenantEpoch returns the durable lifecycle namespace used in
// deterministic application-secret event IDs. It is independent command state:
// offboarding deletes it and a later registration of the same UUID gets a new one.
func (s *Store) ApplicationSecretTenantEpoch(ctx context.Context, tenantID string) (string, error) {
	if tenantID == "" {
		return "", errors.New("store: application-secret tenant epoch requires a tenant id")
	}
	var epoch string
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := lockLiveTenantRegistrationTx(ctx, tx, tenantID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO application_secret_tenant_epochs (tenant_id, epoch_id)
			VALUES ($1, gen_random_uuid())
			ON CONFLICT (tenant_id) DO NOTHING`, tenantID); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `
			SELECT epoch_id::text
			  FROM application_secret_tenant_epochs
			 WHERE tenant_id = $1`, tenantID).Scan(&epoch)
	})
	return epoch, err
}

// ValidateApplicationSecretTenantEpochTx locks and compares the current tenant
// lifecycle epoch inside the caller's tenant transaction. The row lock makes an
// offboard delete serialize with the secret mutation instead of racing between
// an epoch check and the state change.
func (s *Store) ValidateApplicationSecretTenantEpochTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, tenantEpoch string,
) error {
	if tenantID == "" || tenantEpoch == "" {
		return ErrApplicationSecretTenantEpochMismatch
	}
	if err := lockLiveTenantRegistrationTx(ctx, tx, tenantID); err != nil {
		if errors.Is(err, ErrApplicationSecretTenantEpochMismatch) {
			return ErrApplicationSecretTenantEpochMismatch
		}
		return err
	}
	return validateApplicationSecretTenantEpochAfterLifecycleTx(ctx, tx, tenantID, tenantEpoch)
}

func validateApplicationSecretTenantEpochAfterLifecycleTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, tenantEpoch string,
) error {
	var current string
	err := tx.QueryRow(ctx, `
		SELECT epoch_id::text
		  FROM application_secret_tenant_epochs
		 WHERE tenant_id = $1
		 FOR KEY SHARE`, tenantID).Scan(&current)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrApplicationSecretTenantEpochMismatch
	}
	if err != nil {
		return err
	}
	if current != tenantEpoch {
		return ErrApplicationSecretTenantEpochMismatch
	}
	return nil
}

// ApplicationSecretMutation is the projector input for one immutable served
// rotate, recovery, overwrite, or deletion. Sealed is ciphertext only. The
// approval states are repeated here so the store can prove the capability names
// this exact version/result before spending it beside the mutation.
type ApplicationSecretMutation struct {
	TenantID        string
	TenantEpoch     string
	EventID         string
	SemanticDigest  string
	RequestBinding  string
	Action          string
	Name            string
	ExpectedVersion int
	ResultVersion   int
	Sealed          []byte
	SourceVersion   int
	SourceWrittenAt time.Time
	OccurredAt      time.Time
	ApprovalFrom    string
	ApprovalTo      string
	Approval        *OperationApprovalUse
}

// ApplicationSecretMutationReceipt is the independently backed-up proof that one
// deterministic served mutation already changed the sealed primary store. It holds
// only request/result metadata. RequestBinding is an HMAC, not secret plaintext.
// The API uses this receipt to reconcile the crash gap between the event/projector
// transaction committing and the HTTP idempotency response being recorded.
type ApplicationSecretMutationReceipt struct {
	TenantID        string
	EventID         string
	SemanticDigest  string
	RequestBinding  string
	Name            string
	Action          string
	ResultVersion   int
	ResultCreatedAt time.Time
	ResultUpdatedAt time.Time
}

// GetApplicationSecretMutationReceipt loads one exact mutation result in its
// tenant RLS context. A missing receipt returns an error matching IsNotFound.
func (s *Store) GetApplicationSecretMutationReceipt(ctx context.Context, tenantID, eventID string) (ApplicationSecretMutationReceipt, error) {
	var receipt ApplicationSecretMutationReceipt
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT tenant_id::text, event_id::text, semantic_sha256, request_binding,
			        secret_name, action, result_version, result_created_at, result_updated_at
			   FROM application_secret_mutation_receipts
			  WHERE tenant_id = $1 AND event_id = $2`, tenantID, eventID).
			Scan(&receipt.TenantID, &receipt.EventID, &receipt.SemanticDigest,
				&receipt.RequestBinding, &receipt.Name, &receipt.Action,
				&receipt.ResultVersion, &receipt.ResultCreatedAt, &receipt.ResultUpdatedAt)
	})
	return receipt, err
}

// ApplicationSecretMutationFence is the durable first-command winner for one
// tenant/name. Payload is ciphertext plus non-secret command bindings. Approval
// deliberately omits Requester: privacy erasure may rewrite that spelling in the
// event log and approval projection, so retries hydrate the current pseudonymized
// requester from the exact approval request.
type ApplicationSecretMutationFence struct {
	TenantID         string
	Name             string
	Operation        string
	EventID          string
	EventType        string
	SchemaVersion    int
	ApprovalRequired bool
	RequesterSealed  []byte
	RequesterRef     string
	RequestBinding   string
	Payload          []byte
	PayloadDigest    string
	EventTime        time.Time
	Approval         *ApplicationSecretFenceApproval
	Actor            *events.Actor
	ActorSubjectRef  string
	CreatedAt        time.Time
}

// ApplicationSecretFenceApproval is an exact approval capability with the one
// privacy-rewriteable field (Requester) removed. Every security field remains.
type ApplicationSecretFenceApproval struct {
	RequestID         string `json:"request_id"`
	IntentDigest      string `json:"intent_digest"`
	ResourceKind      string `json:"resource_kind"`
	ResourceID        string `json:"resource_id"`
	Action            string `json:"action"`
	FromState         string `json:"from_state,omitempty"`
	ToState           string `json:"to_state,omitempty"`
	TargetVersion     uint64 `json:"target_version"`
	RequiredApprovals int    `json:"required_approvals"`
}

func applicationSecretFenceApproval(use OperationApprovalUse) ApplicationSecretFenceApproval {
	return ApplicationSecretFenceApproval{
		RequestID: use.RequestID, IntentDigest: use.IntentDigest,
		ResourceKind: use.ResourceKind, ResourceID: use.ResourceID, Action: use.Action,
		FromState: use.FromState, ToState: use.ToState, TargetVersion: use.TargetVersion,
		RequiredApprovals: use.RequiredApprovals,
	}
}

func (a ApplicationSecretFenceApproval) use(requester string) OperationApprovalUse {
	return OperationApprovalUse{
		RequestID: a.RequestID, IntentDigest: a.IntentDigest, Requester: requester,
		ResourceKind: a.ResourceKind, ResourceID: a.ResourceID, Action: a.Action,
		FromState: a.FromState, ToState: a.ToState, TargetVersion: a.TargetVersion,
		RequiredApprovals: a.RequiredApprovals,
	}
}

func validateApplicationSecretMutationFence(f ApplicationSecretMutationFence) error {
	if f.TenantID == "" || f.Name == "" || f.Operation == "" || f.EventID == "" ||
		f.EventType == "" || f.SchemaVersion <= 0 || len(f.RequestBinding) != 64 ||
		len(f.Payload) == 0 {
		return errors.New("store: application-secret mutation fence is incomplete")
	}
	if f.ApprovalRequired && (len(f.RequesterSealed) == 0 || len(f.RequesterRef) != 64) {
		return errors.New("store: approval-required application-secret fence lacks its sealed requester/privacy selector")
	}
	if !f.ApprovalRequired && (len(f.RequesterSealed) != 0 || f.RequesterRef != "") {
		return errors.New("store: non-approval application-secret fence carries a requester")
	}
	if f.Actor == nil {
		if f.ActorSubjectRef != "" {
			return errors.New("store: unattributed application-secret fence carries an actor selector")
		}
	} else if f.Actor.Subject == "" || len(f.ActorSubjectRef) != 64 ||
		f.ActorSubjectRef != privacy.SubjectRef(f.TenantID, f.Actor.Subject) {
		return errors.New("store: application-secret fence actor/privacy selector is invalid")
	}
	return nil
}

func scanApplicationSecretMutationFence(row pgx.Row) (ApplicationSecretMutationFence, error) {
	var (
		out      ApplicationSecretMutationFence
		approval []byte
		actor    []byte
	)
	err := row.Scan(&out.TenantID, &out.Name, &out.Operation, &out.EventID,
		&out.EventType, &out.SchemaVersion, &out.ApprovalRequired, &out.RequesterSealed, &out.RequesterRef,
		&out.RequestBinding, &out.Payload,
		&out.PayloadDigest, &out.EventTime, &approval, &actor, &out.ActorSubjectRef, &out.CreatedAt)
	if err != nil {
		return ApplicationSecretMutationFence{}, err
	}
	if len(out.PayloadDigest) != 64 || crypto.SHA256Hex(out.Payload) != out.PayloadDigest {
		return ApplicationSecretMutationFence{}, errors.New("store: application-secret mutation fence payload digest mismatch")
	}
	if len(approval) > 0 {
		var capability ApplicationSecretFenceApproval
		if err := json.Unmarshal(approval, &capability); err != nil {
			return ApplicationSecretMutationFence{}, fmt.Errorf("store: decode application-secret fence approval: %w", err)
		}
		out.Approval = &capability
	}
	if len(actor) > 0 {
		var eventActor events.Actor
		if err := json.Unmarshal(actor, &eventActor); err != nil || eventActor.Subject == "" {
			if err == nil {
				err = errors.New("actor subject is empty")
			}
			return ApplicationSecretMutationFence{}, fmt.Errorf("store: decode application-secret fence actor: %w", err)
		}
		if out.ActorSubjectRef != "" &&
			out.ActorSubjectRef != privacy.SubjectRef(out.TenantID, eventActor.Subject) {
			return ApplicationSecretMutationFence{}, errors.New("store: application-secret fence actor privacy selector mismatch")
		}
		if !applicationSecretActorRolesAreCanonical(eventActor.Roles) {
			return ApplicationSecretMutationFence{}, errors.New("store: application-secret fence actor roles are not canonical")
		}
		out.Actor = &eventActor
	}
	return out, nil
}

// #nosec G101 -- SQL column identifiers only; this constant contains no credential material.
const applicationSecretMutationFenceColumns = `
	tenant_id::text, secret_name, operation, event_id::text, event_type,
		schema_version, approval_required, requester_sealed, coalesce(requester_ref, ''), request_binding, command_payload, payload_sha256,
	coalesce(event_time, '0001-01-01 00:00:00+00'::timestamptz), approval, actor, coalesce(actor_subject_ref, ''), created_at`

// GetApplicationSecretMutationFence returns the currently reserved command for a
// tenant/name. Missing uses the store's standard not-found shape.
func (s *Store) GetApplicationSecretMutationFence(ctx context.Context, tenantID, name string) (ApplicationSecretMutationFence, error) {
	var out ApplicationSecretMutationFence
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		out, err = scanApplicationSecretMutationFence(tx.QueryRow(ctx,
			`SELECT `+applicationSecretMutationFenceColumns+`
			   FROM application_secret_mutation_fences
			  WHERE tenant_id = $1 AND secret_name = $2`, tenantID, name))
		return err
	})
	return out, err
}

// ListApplicationSecretMutationFences returns all in-flight commands for one
// tenant. Startup reconciliation walks this bounded, tenant-RLS-scoped inventory;
// it never needs plaintext or a raw Idempotency-Key.
func (s *Store) ListApplicationSecretMutationFences(ctx context.Context, tenantID string) ([]ApplicationSecretMutationFence, error) {
	out := []ApplicationSecretMutationFence{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+applicationSecretMutationFenceColumns+`
			   FROM application_secret_mutation_fences
			  WHERE tenant_id = $1
			  ORDER BY secret_name`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			fence, err := scanApplicationSecretMutationFence(rows)
			if err != nil {
				return err
			}
			out = append(out, fence)
		}
		return rows.Err()
	})
	return out, err
}

// ClaimApplicationSecretMutationFence commits the canonical sealed command before
// approval creation or broker append. The per-secret primary key makes one command
// win under concurrency. An exact retry gets the original payload and timestamp;
// a different request fails before it can create competing approval authority.
func (s *Store) ClaimApplicationSecretMutationFence(ctx context.Context, candidate ApplicationSecretMutationFence) (ApplicationSecretMutationFence, error) {
	var canonical ApplicationSecretMutationFence
	err := s.WithApplicationSecretMutationPrivacyBarrier(ctx, candidate.TenantID,
		func(barrierCtx context.Context) error {
			var err error
			canonical, err = s.claimApplicationSecretMutationFenceUnbarriered(barrierCtx, candidate)
			return err
		})
	return canonical, err
}

func (s *Store) claimApplicationSecretMutationFenceUnbarriered(
	ctx context.Context,
	candidate ApplicationSecretMutationFence,
) (ApplicationSecretMutationFence, error) {
	if candidate.Actor != nil {
		candidate.Actor = canonicalApplicationSecretClaimActor(candidate.Actor)
		candidate.ActorSubjectRef = privacy.SubjectRef(candidate.TenantID, candidate.Actor.Subject)
	}
	if err := validateApplicationSecretMutationFence(candidate); err != nil {
		return ApplicationSecretMutationFence{}, err
	}
	candidate.PayloadDigest = crypto.SHA256Hex(candidate.Payload)
	var actorJSON any
	if candidate.Actor != nil {
		encoded, err := marshalApplicationSecretActor(candidate.Actor)
		if err != nil {
			return ApplicationSecretMutationFence{}, err
		}
		actorJSON = string(encoded)
	}
	var canonical ApplicationSecretMutationFence
	err := s.WithTenant(ctx, candidate.TenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO application_secret_mutation_fences
			       (tenant_id, secret_name, operation, event_id, event_type,
			        schema_version, approval_required, requester_sealed, requester_ref,
			        request_binding, command_payload, payload_sha256, actor, actor_subject_ref)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULLIF($9, ''), $10, $11, $12, $13::jsonb, NULLIF($14, ''))
			ON CONFLICT DO NOTHING`, candidate.TenantID, candidate.Name,
			candidate.Operation, candidate.EventID, candidate.EventType,
			candidate.SchemaVersion, candidate.ApprovalRequired, candidate.RequesterSealed, candidate.RequesterRef,
			candidate.RequestBinding, candidate.Payload,
			candidate.PayloadDigest, actorJSON, candidate.ActorSubjectRef); err != nil {
			return err
		}
		var err error
		canonical, err = scanApplicationSecretMutationFence(tx.QueryRow(ctx,
			`SELECT `+applicationSecretMutationFenceColumns+`
			   FROM application_secret_mutation_fences
			  WHERE tenant_id = $1 AND secret_name = $2
			  FOR UPDATE`, candidate.TenantID, candidate.Name))
		if err != nil {
			return err
		}
		// Migration 0149 could not derive requester_ref from pre-existing
		// tenant ciphertext in SQL. An otherwise exact retry is the first safe
		// point where the application knows that one-way selector again. Backfill
		// it while the still-unbound fence is row-locked; once approval is bound,
		// requester identity belongs to the approval projection instead.
		if canonical.ApprovalRequired && canonical.Approval == nil &&
			len(canonical.RequesterSealed) > 0 && canonical.RequesterRef == "" &&
			canonical.EventID == candidate.EventID && canonical.Operation == candidate.Operation &&
			canonical.EventType == candidate.EventType && canonical.SchemaVersion == candidate.SchemaVersion &&
			crypto.ConstantTimeEqual([]byte(canonical.RequestBinding), []byte(candidate.RequestBinding)) {
			if _, err := tx.Exec(ctx,
				`UPDATE application_secret_mutation_fences
				    SET requester_ref = $3
				  WHERE tenant_id = $1 AND secret_name = $2 AND requester_ref IS NULL`,
				candidate.TenantID, candidate.Name, candidate.RequesterRef); err != nil {
				return err
			}
			canonical.RequesterRef = candidate.RequesterRef
		}
		if canonical.EventID != candidate.EventID || canonical.Operation != candidate.Operation ||
			canonical.EventType != candidate.EventType || canonical.SchemaVersion != candidate.SchemaVersion ||
			canonical.ApprovalRequired != candidate.ApprovalRequired || canonical.RequesterRef != candidate.RequesterRef ||
			canonical.ActorSubjectRef != candidate.ActorSubjectRef || !reflect.DeepEqual(canonical.Actor, candidate.Actor) ||
			!crypto.ConstantTimeEqual([]byte(canonical.RequestBinding), []byte(candidate.RequestBinding)) {
			replaceable, err := applicationSecretFenceTerminalTx(ctx, tx, canonical, time.Now().UTC())
			if err != nil {
				return err
			}
			if !replaceable {
				return fmt.Errorf("%w: %w for %s", ErrIdempotencyConflict, ErrApplicationSecretMutationInFlight, candidate.Name)
			}
			if _, err := tx.Exec(ctx,
				`DELETE FROM application_secret_mutation_fences
				  WHERE tenant_id = $1 AND secret_name = $2 AND event_id = $3`,
				candidate.TenantID, candidate.Name, canonical.EventID); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO application_secret_mutation_fences
				       (tenant_id, secret_name, operation, event_id, event_type,
				        schema_version, approval_required, requester_sealed, requester_ref,
				        request_binding, command_payload, payload_sha256, actor, actor_subject_ref)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULLIF($9, ''), $10, $11, $12, $13::jsonb, NULLIF($14, ''))`,
				candidate.TenantID, candidate.Name, candidate.Operation, candidate.EventID,
				candidate.EventType, candidate.SchemaVersion, candidate.ApprovalRequired,
				candidate.RequesterSealed, candidate.RequesterRef, candidate.RequestBinding,
				candidate.Payload, candidate.PayloadDigest, actorJSON, candidate.ActorSubjectRef); err != nil {
				return err
			}
			canonical, err = scanApplicationSecretMutationFence(tx.QueryRow(ctx,
				`SELECT `+applicationSecretMutationFenceColumns+`
				   FROM application_secret_mutation_fences
				  WHERE tenant_id = $1 AND secret_name = $2
				  FOR UPDATE`, candidate.TenantID, candidate.Name))
			return err
		}
		return nil
	})
	return canonical, err
}

func pseudonymizeApplicationSecretActor(
	actor *events.Actor,
	tenantID, subject string,
) (*events.Actor, bool, error) {
	if actor == nil {
		return nil, false, nil
	}
	if strings.TrimSpace(actor.Subject) == "" {
		return nil, false, errors.New("application-secret recovery actor subject is empty")
	}
	rewritten, changed := events.PseudonymizeActorForSubject(actor, tenantID, subject)
	if !changed {
		return actor, false, nil
	}
	// Initial commands bind roles as a canonical semantic set. An authorized
	// privacy rewrite can change lexical ordering and can collapse two distinct
	// spellings to the same placeholder. Restore sorted order for restart-safe
	// reads, but do not compact here: duplicate cardinality is immutable audit
	// evidence after the first command has been recorded.
	if rewritten.Roles != nil {
		slices.Sort(rewritten.Roles)
	}
	return rewritten, true, nil
}

func canonicalApplicationSecretClaimActor(actor *events.Actor) *events.Actor {
	if actor == nil {
		return nil
	}
	canonical := *actor
	if actor.Roles == nil {
		return &canonical
	}
	roles := append([]string{}, actor.Roles...)
	slices.Sort(roles)
	roles = slices.Compact(roles)
	first := 0
	for first < len(roles) && roles[first] == "" {
		first++
	}
	roles = roles[first:]
	if len(roles) == 0 {
		roles = nil
	}
	canonical.Roles = roles
	return &canonical
}

func applicationSecretActorRolesAreCanonical(roles []string) bool {
	if !slices.IsSorted(roles) {
		return false
	}
	for _, role := range roles {
		if role == "" {
			return false
		}
	}
	return true
}

func marshalApplicationSecretActor(actor *events.Actor) ([]byte, error) {
	if actor == nil || actor.Roles == nil {
		return json.Marshal(actor)
	}
	// events.Actor intentionally omits empty roles in ordinary envelopes. The
	// recovery fence is a shape-preserving SQL receiver, so an explicit empty
	// slice remains [] across rewrite and restart instead of becoming nil.
	return json.Marshal(struct {
		Subject string   `json:"subject"`
		Roles   []string `json:"roles"`
	}{Subject: actor.Subject, Roles: actor.Roles})
}

// WithApplicationSecretMutationPrivacyBarrier keeps a target append outside an
// in-progress event-history rewrite. Privacy erasure owns the exclusive form of
// this deployment-wide lock through its post-cutover completion callback. A
// mutation owns the shared form while it reloads its fence and appends/projects,
// so a command that read raw attribution before cutover cannot publish it into the
// already-pseudonymized generation after cutover.
func (s *Store) WithApplicationSecretMutationPrivacyBarrier(
	ctx context.Context,
	tenantID string,
	fn func(context.Context) error,
) error {
	return s.WithPrivacyRecoveryBarrier(ctx, tenantID,
		"application-secret privacy barrier", fn)
}

// PseudonymizeApplicationSecretMutationFences is the PostgreSQL half of the
// privacy rewrite's post-cutover completion. It runs while the caller owns the
// exclusive history-operation lock. In one tenant transaction it either removes
// a pre-finalization command or rewrites the finalized command actor AND the exact
// approval requester it will hydrate during recovery. That atomic pairing closes
// the crash/race window where restart could otherwise append a placeholder actor
// with a raw approval requester (or vice versa).
func (s *Store) PseudonymizeApplicationSecretMutationFences(
	ctx context.Context,
	tenantID, subject string,
) (int, error) {
	if tenantID == "" || strings.TrimSpace(subject) == "" {
		return 0, errors.New("store: application-secret fence pseudonymization requires tenant and subject")
	}
	subjectRef := privacy.SubjectRef(tenantID, subject)
	placeholder := privacy.Placeholder(subjectRef)
	type row struct {
		name         string
		eventTime    *time.Time
		approval     []byte
		actor        []byte
		requesterRef string
		actorRef     string
	}
	changed := 0
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT f.secret_name, f.event_time, f.approval, f.actor,
			       coalesce(f.requester_ref, ''), coalesce(f.actor_subject_ref, '')
			  FROM application_secret_mutation_fences f
			 WHERE f.tenant_id = $1
			 ORDER BY f.secret_name
			 FOR UPDATE`, tenantID)
		if err != nil {
			return err
		}
		var pending []row
		for rows.Next() {
			var item row
			if err := rows.Scan(&item.name, &item.eventTime, &item.approval, &item.actor,
				&item.requesterRef, &item.actorRef); err != nil {
				rows.Close()
				return err
			}
			pending = append(pending, item)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()

		for _, item := range pending {
			affected := item.requesterRef == subjectRef || item.actorRef == subjectRef
			var actorValue any
			if len(item.actor) != 0 {
				var actor events.Actor
				if err := json.Unmarshal(item.actor, &actor); err != nil {
					return fmt.Errorf("store: decode application-secret fence actor during privacy rewrite: %w", err)
				}
				if actor.Subject == "" {
					return errors.New("store: application-secret fence actor subject is empty during privacy rewrite")
				}
				rewritten, actorChanged, err := pseudonymizeApplicationSecretActor(&actor, tenantID, subject)
				if err != nil {
					return fmt.Errorf("store: application-secret fence actor during privacy rewrite: %w", err)
				}
				affected = affected || actorChanged
				encoded, err := marshalApplicationSecretActor(rewritten)
				if err != nil {
					return err
				}
				actorValue = string(encoded)
			}

			if len(item.approval) != 0 {
				var capability ApplicationSecretFenceApproval
				if err := json.Unmarshal(item.approval, &capability); err != nil {
					return fmt.Errorf("store: decode application-secret fence approval during privacy rewrite: %w", err)
				}
				if capability.RequestID == "" {
					return errors.New("store: application-secret fence approval request ID is empty during privacy rewrite")
				}
				var requester string
				if err := tx.QueryRow(ctx, `SELECT requester
					FROM operation_approval_requests
					WHERE tenant_id = $1 AND id = $2
					FOR UPDATE`, tenantID, capability.RequestID).Scan(&requester); err != nil {
					return err
				}
				switch requester {
				case subject:
					affected = true
					if _, err := tx.Exec(ctx, `UPDATE operation_approval_requests
						SET requester = $3,
						    reason = '',
						    evidence_refs = '[]'::jsonb,
						    status = CASE WHEN status IN ('pending', 'approved') THEN 'superseded' ELSE status END
						WHERE tenant_id = $1 AND id = $2`, tenantID, capability.RequestID, placeholder); err != nil {
						return err
					}
				case placeholder:
					affected = true
				default:
					// This fence can still be affected only through an actor role. Its
					// unrelated approval requester is immutable and stays byte-exact.
				}
			}
			if !affected {
				continue
			}

			// Claim and approval binding are not points of no return. A command is
			// recoverable only after it owns event_time. Delete every earlier state,
			// including an approved command, after atomically revoking/pseudonymizing
			// its exact approval request above. Actor-only native/Vault creates and
			// approval-disabled rotations reach this path without an approval.
			if item.eventTime == nil {
				tag, err := tx.Exec(ctx, `DELETE FROM application_secret_mutation_fences
					WHERE tenant_id = $1 AND secret_name = $2 AND event_time IS NULL`,
					tenantID, item.name)
				if err != nil {
					return err
				}
				if tag.RowsAffected() != 0 {
					changed++
				}
				continue
			}

			tag, err := tx.Exec(ctx, `UPDATE application_secret_mutation_fences
				SET actor = $3::jsonb,
				    actor_subject_ref = CASE WHEN actor_subject_ref = $4 THEN NULL ELSE actor_subject_ref END,
				    requester_sealed = CASE WHEN requester_ref = $4 THEN NULL ELSE requester_sealed END,
				    requester_ref = CASE WHEN requester_ref = $4 THEN NULL ELSE requester_ref END
				WHERE tenant_id = $1 AND secret_name = $2`, tenantID, item.name, actorValue, subjectRef)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return errors.New("store: application-secret fence disappeared during privacy rewrite")
			}
			changed++
		}
		return nil
	})
	return changed, err
}

func applicationSecretFenceTerminalTx(ctx context.Context, tx pgx.Tx, fence ApplicationSecretMutationFence, now time.Time) (bool, error) {
	// Once event_time is durable, Append may already have succeeded. No caller or
	// later command may release or replace that fence; only its exact projection
	// and receipt transaction can retire it.
	if !fence.EventTime.IsZero() || fence.Approval == nil {
		return false, nil
	}
	request, err := scanOperationApproval(tx.QueryRow(ctx,
		`SELECT `+operationApprovalColumns+` FROM operation_approval_requests r
		  WHERE r.tenant_id = $1 AND r.id = $2
		  FOR UPDATE`, fence.TenantID, fence.Approval.RequestID))
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := validateOperationApprovalUseBinding(request, fence.Approval.use(request.Requester)); err != nil {
		return false, err
	}
	switch request.Status {
	case ApprovalStatusDenied, ApprovalStatusExpired, ApprovalStatusSuperseded:
		return true, nil
	case ApprovalStatusPending, ApprovalStatusApproved:
		return !now.Before(request.ExpiresAt), nil
	default:
		return false, nil
	}
}

// BindApplicationSecretMutationFenceApproval records the exact pending request
// capability without marking the fence appendable. This is what later proves a
// denied/expired/superseded abandoned command is safe to replace. It never releases
// a fence itself and cannot alter a finalized fence.
func (s *Store) BindApplicationSecretMutationFenceApproval(
	ctx context.Context,
	tenantID, name, eventID string,
	use OperationApprovalUse,
) (ApplicationSecretMutationFence, error) {
	var canonical ApplicationSecretMutationFence
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		canonical, err = scanApplicationSecretMutationFence(tx.QueryRow(ctx,
			`SELECT `+applicationSecretMutationFenceColumns+`
			   FROM application_secret_mutation_fences
			  WHERE tenant_id = $1 AND secret_name = $2
			  FOR UPDATE`, tenantID, name))
		if err != nil {
			return err
		}
		if canonical.EventID != eventID || !canonical.EventTime.IsZero() {
			return fmt.Errorf("%w: application-secret fence cannot bind pending approval", ErrIdempotencyConflict)
		}
		if !canonical.ApprovalRequired {
			return fmt.Errorf("%w: application-secret fence does not require approval", ErrIdempotencyConflict)
		}
		request, err := s.getOperationApprovalTx(ctx, tx, tenantID, use.RequestID, true)
		if err != nil {
			return err
		}
		if err := validateOperationApprovalUseBinding(request, use); err != nil {
			return err
		}
		if canonical.Actor != nil && use.Requester != canonical.Actor.Subject {
			return ErrApprovalDrifted
		}
		capability := applicationSecretFenceApproval(use)
		if canonical.Approval != nil && *canonical.Approval != capability {
			return fmt.Errorf("%w: application-secret fence pending approval differs", ErrIdempotencyConflict)
		}
		encoded, err := json.Marshal(capability)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE application_secret_mutation_fences
			   SET approval = $4::jsonb, requester_sealed = NULL, requester_ref = NULL
			 WHERE tenant_id = $1 AND secret_name = $2 AND event_id = $3`,
			tenantID, name, eventID, string(encoded)); err != nil {
			return err
		}
		canonical.Approval = &capability
		canonical.RequesterSealed = nil
		canonical.RequesterRef = ""
		return nil
	})
	return canonical, err
}

// FinalizeApplicationSecretMutationFence reserves a stable append timestamp and
// exact capability while that capability is valid. A later crash retry may use
// this committed append intent after the broker dedupe window or approval expiry;
// it cannot substitute a different capability.
func (s *Store) FinalizeApplicationSecretMutationFence(
	ctx context.Context,
	tenantID, name, eventID string,
	use *OperationApprovalUse,
	now time.Time,
) (ApplicationSecretMutationFence, error) {
	var canonical ApplicationSecretMutationFence
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		canonical, err = scanApplicationSecretMutationFence(tx.QueryRow(ctx,
			`SELECT `+applicationSecretMutationFenceColumns+`
			   FROM application_secret_mutation_fences
			  WHERE tenant_id = $1 AND secret_name = $2
			  FOR UPDATE`, tenantID, name))
		if err != nil {
			return err
		}
		if canonical.EventID != eventID {
			return fmt.Errorf("%w: application-secret fence event differs", ErrIdempotencyConflict)
		}
		if canonical.ApprovalRequired != (use != nil) {
			return fmt.Errorf("%w: application-secret fence admission policy differs", ErrIdempotencyConflict)
		}
		var approvalJSON any
		if use != nil {
			if canonical.Actor != nil && use.Requester != canonical.Actor.Subject {
				return ErrApprovalDrifted
			}
			capability := applicationSecretFenceApproval(*use)
			if canonical.EventTime.IsZero() {
				if canonical.Approval != nil && *canonical.Approval != capability {
					return fmt.Errorf("%w: application-secret fence approval differs", ErrIdempotencyConflict)
				}
				// Finalization is the durable pre-Append point of no return. Spend the
				// one-shot authority into this exact event ID in the same transaction as
				// event_time/approval. A crash can then append and project after the
				// request's wall-clock expiry without reopening or replacing authority.
				if err := s.ConsumeOperationApprovalTx(ctx, tx, tenantID, *use, eventID, now.UTC()); err != nil {
					return err
				}
			} else if canonical.Approval == nil || *canonical.Approval != capability {
				return fmt.Errorf("%w: application-secret fence approval differs", ErrIdempotencyConflict)
			}
			encoded, marshalErr := json.Marshal(capability)
			if marshalErr != nil {
				return marshalErr
			}
			approvalJSON = string(encoded)
		} else if !canonical.EventTime.IsZero() && canonical.Approval != nil {
			return fmt.Errorf("%w: application-secret fence requires approval", ErrIdempotencyConflict)
		}
		if canonical.EventTime.IsZero() {
			if _, err := tx.Exec(ctx, `
				UPDATE application_secret_mutation_fences
				   SET event_time = $4, approval = $5::jsonb, requester_sealed = NULL, requester_ref = NULL
				 WHERE tenant_id = $1 AND secret_name = $2 AND event_id = $3`,
				tenantID, name, eventID, now.UTC(), approvalJSON); err != nil {
				return err
			}
			canonical, err = scanApplicationSecretMutationFence(tx.QueryRow(ctx,
				`SELECT `+applicationSecretMutationFenceColumns+`
				   FROM application_secret_mutation_fences
				  WHERE tenant_id = $1 AND secret_name = $2`, tenantID, name))
			return err
		}
		return nil
	})
	return canonical, err
}

// ApplicationSecretMutationFenceApprovalUse restores only Requester from the
// current exact approval projection. A privacy rewrite may change that spelling;
// every other stored capability field must still match byte-for-byte.
func (s *Store) ApplicationSecretMutationFenceApprovalUse(
	ctx context.Context,
	tenantID string,
	fence ApplicationSecretMutationFence,
) (*OperationApprovalUse, error) {
	if fence.Approval == nil {
		return nil, nil
	}
	request, err := s.GetOperationApproval(ctx, tenantID, fence.Approval.RequestID)
	if err != nil {
		return nil, err
	}
	use := fence.Approval.use(request.Requester)
	if err := validateOperationApprovalUseBinding(request, use); err != nil {
		return nil, err
	}
	// These are two durable copies of the same authenticated principal. Privacy
	// completion rewrites them atomically. A mismatch is therefore a partial or
	// poisoned recovery state, never permission to hydrate raw PII into a new
	// immutable target event.
	if fence.Actor != nil && request.Requester != fence.Actor.Subject {
		return nil, ErrApprovalDrifted
	}
	return &use, nil
}

// SecretShare is a durable, tenant-scoped one-time share row. TokenHash is a
// SHA-256 hex digest of the bearer token; Sealed is ciphertext only.
type SecretShare struct {
	TenantID  string
	TokenHash string
	ShareID   string
	Sealed    []byte
	ExpiresAt time.Time
	CreatedAt time.Time
}

// PutSecretShare stores a sealed one-time share keyed by SHA-256(token). It never
// stores the bearer token or plaintext. Tenant-scoped under RLS (AN-1).
func (s *Store) PutSecretShare(ctx context.Context, tenantID, tokenHash, shareID string, sealed []byte, expiresAt time.Time) error {
	return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO secret_shares (tenant_id, token_sha256, share_id, sealed, expires_at)
			 VALUES ($1, $2, $3, $4, $5)`,
			tenantID, tokenHash, shareID, sealed, expiresAt.UTC())
		return err
	})
}

// ConsumeSecretShare atomically deletes and returns a still-valid one-time share.
// DELETE ... RETURNING makes a successful redemption single-use under concurrency.
// Expired shares are removed opportunistically and reported as not found.
func (s *Store) ConsumeSecretShare(ctx context.Context, tenantID, tokenHash string, now time.Time) (SecretShare, error) {
	var out SecretShare
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx,
			`DELETE FROM secret_shares
			  WHERE tenant_id = $1 AND token_sha256 = $2 AND expires_at > $3
			  RETURNING tenant_id::text, token_sha256, share_id, sealed, expires_at, created_at`,
			tenantID, tokenHash, now.UTC()).
			Scan(&out.TenantID, &out.TokenHash, &out.ShareID, &out.Sealed, &out.ExpiresAt, &out.CreatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			_, _ = tx.Exec(ctx,
				`DELETE FROM secret_shares
				  WHERE tenant_id = $1 AND token_sha256 = $2 AND expires_at <= $3`,
				tenantID, tokenHash, now.UTC())
			return err
		}
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return SecretShare{}, ErrSecretShareNotFound
	}
	return out, err
}

// GetSecret loads a sealed application secret for (tenant, name). It returns
// ErrSecretNotFound when absent. Tenant-scoped under RLS (AN-1).
func (s *Store) GetSecret(ctx context.Context, tenantID, name string) (Secret, error) {
	var out Secret
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, name, sealed, version, created_at, updated_at
			   FROM secret_store
			  WHERE tenant_id = $1 AND name = $2`,
			tenantID, name).
			Scan(&out.ID, &out.TenantID, &out.Name, &out.Sealed, &out.Version, &out.CreatedAt, &out.UpdatedAt)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Secret{}, ErrSecretNotFound
	}
	return out, err
}

// ApplicationSecretApprovalTargetTx serializes a reviewer decision with the
// authoritative application-secret generation. The advisory lock also covers an
// absent row, which is required for create approvals: a row lock cannot protect a
// name that does not exist yet. ApplyApplicationSecretMutationTx takes this same
// lock before changing the target, so the decision observes one exact generation.
// Only the non-secret version is returned; sealed bytes never cross this boundary.
func (s *Store) ApplicationSecretApprovalTargetTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, name string,
) (version int, exists bool, err error) {
	if tenantID == "" || name == "" {
		return 0, false, ErrApprovalDrifted
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		applicationSecretMutationLockKey(tenantID, name)); err != nil {
		return 0, false, fmt.Errorf("store: lock application-secret approval target: %w", err)
	}
	err = tx.QueryRow(ctx, `
		SELECT version FROM secret_store
		 WHERE tenant_id = $1 AND name = $2
		 FOR UPDATE`, tenantID, name).Scan(&version)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	if version <= 0 {
		return 0, false, ErrApprovalDrifted
	}
	return version, true, nil
}

// GetSecretVersion loads one sealed historical version for (tenant, name, version).
// It returns ErrSecretNotFound when the tenant/name/version is absent. Tenant-scoped
// under RLS (AN-1).
func (s *Store) GetSecretVersion(ctx context.Context, tenantID, name string, version int) (SecretVersion, error) {
	var out SecretVersion
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var recovered sql.NullInt64
		if err := tx.QueryRow(ctx,
			`SELECT tenant_id::text, name, version, sealed, written_at, recovered_from_version
			   FROM secret_store_versions
			  WHERE tenant_id = $1 AND name = $2 AND version = $3`,
			tenantID, name, version).
			Scan(&out.TenantID, &out.Name, &out.Version, &out.Sealed, &out.WrittenAt, &recovered); err != nil {
			return err
		}
		if recovered.Valid {
			v := int(recovered.Int64)
			out.RecoveredFromVersion = &v
		}
		return nil
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return SecretVersion{}, ErrSecretNotFound
	}
	return out, err
}

// GetSecretVersionAt returns the immutable source a point-in-time recovery would
// choose, without changing the current secret. The eventual mutation rechecks the
// exact version and written timestamp under the current-row lock.
func (s *Store) GetSecretVersionAt(ctx context.Context, tenantID, name string, at time.Time) (SecretVersion, error) {
	var out SecretVersion
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var recovered sql.NullInt64
		if err := tx.QueryRow(ctx,
			`SELECT tenant_id::text, name, version, sealed, written_at, recovered_from_version
			   FROM secret_store_versions
			  WHERE tenant_id = $1 AND name = $2 AND written_at <= $3
			  ORDER BY written_at DESC, version DESC
			  LIMIT 1`, tenantID, name, at.UTC()).
			Scan(&out.TenantID, &out.Name, &out.Version, &out.Sealed, &out.WrittenAt, &recovered); err != nil {
			return err
		}
		if recovered.Valid {
			v := int(recovered.Int64)
			out.RecoveredFromVersion = &v
		}
		return nil
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return SecretVersion{}, ErrSecretNotFound
	}
	return out, err
}

// ApplyApplicationSecretMutationTx consumes exact approval authority and applies
// the sealed secret change in one tenant transaction. A replay of the same
// approved event is a no-op; a different event, version, result, or source fails
// closed before any secret row changes.
func (s *Store) ApplyApplicationSecretMutationTx(ctx context.Context, tx pgx.Tx, mutation ApplicationSecretMutation) error {
	if mutation.TenantID == "" || mutation.TenantEpoch == "" || mutation.EventID == "" || len(mutation.SemanticDigest) != 64 ||
		len(mutation.RequestBinding) != 64 || mutation.Name == "" ||
		mutation.ExpectedVersion < 0 || mutation.OccurredAt.IsZero() {
		return errors.New("store: application-secret mutation is incomplete")
	}
	switch mutation.Action {
	case "create":
		if mutation.ExpectedVersion != 0 || mutation.ResultVersion != 1 || len(mutation.Sealed) == 0 || mutation.Approval != nil {
			return errors.New("store: application-secret create result is incomplete")
		}
	case "rotate", "recover":
		if mutation.ResultVersion != mutation.ExpectedVersion+1 || len(mutation.Sealed) == 0 {
			return errors.New("store: application-secret version result is incomplete")
		}
	case "delete":
		if mutation.ResultVersion != 0 || len(mutation.Sealed) != 0 {
			return errors.New("store: application-secret deletion result is invalid")
		}
	default:
		return fmt.Errorf("store: unsupported application-secret action %q", mutation.Action)
	}
	if err := s.ValidateApplicationSecretTenantEpochTx(ctx, tx, mutation.TenantID, mutation.TenantEpoch); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		applicationSecretMutationLockKey(mutation.TenantID, mutation.Name)); err != nil {
		return err
	}
	var receiptDigest, receiptBinding, receiptName, receiptAction string
	receiptErr := tx.QueryRow(ctx,
		`SELECT semantic_sha256, request_binding, secret_name, action
		   FROM application_secret_mutation_receipts
		  WHERE tenant_id = $1 AND event_id = $2
		  FOR UPDATE`, mutation.TenantID, mutation.EventID).
		Scan(&receiptDigest, &receiptBinding, &receiptName, &receiptAction)
	switch {
	case receiptErr == nil:
		if receiptDigest != mutation.SemanticDigest || receiptBinding != mutation.RequestBinding ||
			receiptName != mutation.Name || receiptAction != mutation.Action {
			return fmt.Errorf("%w: application-secret event %s", ErrIdempotencyConflict, mutation.EventID)
		}
		// Rebuild truncates/replays approval projections but deliberately preserves
		// the independently backed-up sealed secret + receipt. Re-spend the rebuilt
		// authority against the SAME target event, without applying the secret twice.
		if mutation.Approval != nil {
			if err := s.ConsumeOperationApprovalTx(ctx, tx, mutation.TenantID, *mutation.Approval,
				mutation.EventID, mutation.OccurredAt); err != nil {
				return err
			}
		}
		return deleteApplicationSecretMutationFenceTx(ctx, tx, mutation.TenantID, mutation.Name, mutation.EventID)
	case !errors.Is(receiptErr, pgx.ErrNoRows):
		return receiptErr
	}
	if mutation.Action == "create" {
		var created Secret
		if err := tx.QueryRow(ctx,
			`INSERT INTO secret_store (tenant_id, name, sealed, version, created_at, updated_at)
			 VALUES ($1, $2, $3, 1, $4, $4)
			 ON CONFLICT (tenant_id, name) DO NOTHING
			 RETURNING id::text, tenant_id::text, name, sealed, version, created_at, updated_at`,
			mutation.TenantID, mutation.Name, mutation.Sealed, mutation.OccurredAt.UTC()).
			Scan(&created.ID, &created.TenantID, &created.Name, &created.Sealed,
				&created.Version, &created.CreatedAt, &created.UpdatedAt); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrApprovalDrifted
			}
			return err
		}
		if err := insertSecretVersion(ctx, tx, mutation.TenantID, mutation.Name, 1,
			mutation.Sealed, mutation.OccurredAt, nil); err != nil {
			return err
		}
		if err := insertApplicationSecretMutationReceiptTx(ctx, tx, mutation, mutation.OccurredAt); err != nil {
			return err
		}
		return deleteApplicationSecretMutationFenceTx(ctx, tx, mutation.TenantID, mutation.Name, mutation.EventID)
	}

	if mutation.Approval != nil {
		if mutation.Approval.ResourceKind != "secret" || mutation.Approval.ResourceID != "secret:"+mutation.Name ||
			mutation.Approval.Action != mutation.Action || mutation.Approval.TargetVersion != uint64(mutation.ExpectedVersion) ||
			mutation.Approval.FromState != mutation.ApprovalFrom || mutation.Approval.ToState != mutation.ApprovalTo {
			return ErrApprovalDrifted
		}
		// Finalized application-secret fences pre-consume authority before broker
		// Append. Consume is deliberately idempotent for that same event ID and still
		// validates/consumes historical events that predate the durable fence.
		if err := s.ConsumeOperationApprovalTx(ctx, tx, mutation.TenantID, *mutation.Approval, mutation.EventID, mutation.OccurredAt); err != nil {
			return err
		}
	}

	var current Secret
	err := tx.QueryRow(ctx,
		`SELECT id::text, tenant_id::text, name, sealed, version, created_at, updated_at
		   FROM secret_store
		  WHERE tenant_id = $1 AND name = $2
		  FOR UPDATE`, mutation.TenantID, mutation.Name).
		Scan(&current.ID, &current.TenantID, &current.Name, &current.Sealed,
			&current.Version, &current.CreatedAt, &current.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrSecretNotFound
	}
	if err != nil {
		return err
	}
	if current.Version != mutation.ExpectedVersion {
		return ErrApprovalDrifted
	}

	var recoveredFrom *int
	if mutation.Action == "recover" {
		if mutation.SourceVersion <= 0 || mutation.SourceWrittenAt.IsZero() {
			return errors.New("store: application-secret recovery source is incomplete")
		}
		var sourceSealed []byte
		var sourceWrittenAt time.Time
		if err := tx.QueryRow(ctx,
			`SELECT sealed, written_at FROM secret_store_versions
			  WHERE tenant_id = $1 AND name = $2 AND version = $3`,
			mutation.TenantID, mutation.Name, mutation.SourceVersion).
			Scan(&sourceSealed, &sourceWrittenAt); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrSecretNotFound
			}
			return err
		}
		if !sourceWrittenAt.Equal(mutation.SourceWrittenAt) || !bytes.Equal(sourceSealed, mutation.Sealed) {
			return ErrApprovalDrifted
		}
		source := mutation.SourceVersion
		recoveredFrom = &source
	}
	if mutation.Action == "delete" {
		if _, err := tx.Exec(ctx,
			`DELETE FROM secret_store WHERE tenant_id = $1 AND name = $2 AND version = $3`,
			mutation.TenantID, mutation.Name, mutation.ExpectedVersion); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`DELETE FROM secret_store_versions WHERE tenant_id = $1 AND name = $2`,
			mutation.TenantID, mutation.Name); err != nil {
			return err
		}
		if err := insertApplicationSecretMutationReceiptTx(ctx, tx, mutation, current.CreatedAt); err != nil {
			return err
		}
		return deleteApplicationSecretMutationFenceTx(ctx, tx, mutation.TenantID, mutation.Name, mutation.EventID)
	}
	tag, err := tx.Exec(ctx,
		`UPDATE secret_store
		    SET sealed = $4, version = $3, updated_at = $5
		  WHERE tenant_id = $1 AND name = $2 AND version = $6`,
		mutation.TenantID, mutation.Name, mutation.ResultVersion, mutation.Sealed,
		mutation.OccurredAt.UTC(), mutation.ExpectedVersion)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrApprovalDrifted
	}
	if err := insertSecretVersion(ctx, tx, mutation.TenantID, mutation.Name,
		mutation.ResultVersion, mutation.Sealed, mutation.OccurredAt, recoveredFrom); err != nil {
		return err
	}
	if err := insertApplicationSecretMutationReceiptTx(ctx, tx, mutation, current.CreatedAt); err != nil {
		return err
	}
	return deleteApplicationSecretMutationFenceTx(ctx, tx, mutation.TenantID, mutation.Name, mutation.EventID)
}

func applicationSecretMutationLockKey(tenantID, name string) string {
	return "application-secret\x1f" + tenantID + "\x1f" + name
}

func insertApplicationSecretMutationReceiptTx(
	ctx context.Context,
	tx pgx.Tx,
	mutation ApplicationSecretMutation,
	resultCreatedAt time.Time,
) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO application_secret_mutation_receipts
		       (tenant_id, event_id, semantic_sha256, request_binding, secret_name, action,
		        result_version, result_created_at, result_updated_at, applied_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9)`,
		mutation.TenantID, mutation.EventID, mutation.SemanticDigest, mutation.RequestBinding,
		mutation.Name, mutation.Action, mutation.ResultVersion, resultCreatedAt.UTC(), mutation.OccurredAt.UTC())
	return err
}

func deleteApplicationSecretMutationFenceTx(ctx context.Context, tx pgx.Tx, tenantID, name, eventID string) error {
	_, err := tx.Exec(ctx,
		`DELETE FROM application_secret_mutation_fences
		  WHERE tenant_id = $1 AND secret_name = $2 AND event_id = $3`,
		tenantID, name, eventID)
	return err
}

// ListSecretNames returns the names (no values) of the tenant's secrets, ordered by
// name, for the served list endpoint. It NEVER returns the sealed bytes — a list is
// metadata only, so a secret value never leaks through enumeration (AN-8).
// Tenant-scoped under RLS (AN-1).
func (s *Store) ListSecretNames(ctx context.Context, tenantID string, limit int) ([]Secret, error) {
	var out []Secret
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, name, version, created_at, updated_at
			   FROM secret_store
			  WHERE tenant_id = $1
			  ORDER BY name
			  LIMIT $2`,
			tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var m Secret
			if err := rows.Scan(&m.ID, &m.TenantID, &m.Name, &m.Version, &m.CreatedAt, &m.UpdatedAt); err != nil {
				return err
			}
			out = append(out, m)
		}
		return rows.Err()
	})
	return out, err
}

func insertSecretVersion(ctx context.Context, tx pgx.Tx, tenantID, name string, version int, sealed []byte, writtenAt time.Time, recoveredFromVersion *int) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO secret_store_versions (tenant_id, name, version, sealed, written_at, recovered_from_version)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		tenantID, name, version, sealed, writtenAt.UTC(), recoveredFromVersion)
	return err
}
