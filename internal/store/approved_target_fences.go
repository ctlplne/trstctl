// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/codesigningref"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/privacy"
)

const (
	ApprovedTargetEphemeralCertificate = "ephemeral_certificate"
	ApprovedTargetCodeSigningCommand   = "code_signing_command"
	ApprovedTargetClaimed              = "claimed"
)

// ApprovedTargetFence is the independently durable first command that claimed
// one approval capability. Payload is the exact event data prepared before
// Append. SemanticDigest normally carries the canonical privacy-stable digest
// the target projector recomputes before retirement. A privacy-rewritten legacy
// schema-v2 code-signing fence intentionally carries its atomically rewritten
// historical-compatibility digest until retirement: that digest preserves the
// sole proof of the original event timestamp below PostgreSQL's microsecond
// precision and must not be replaced with the canonical digest early.
type ApprovedTargetFence struct {
	TenantID       string
	TargetKind     string
	CommandKey     string
	RequestBinding string
	EventID        string
	EventType      string
	SchemaVersion  int
	EventTime      time.Time
	Actor          *events.Actor
	Payload        []byte
	PayloadDigest  string
	SemanticDigest string
	Approval       ApprovedTargetFenceApproval
	ClaimState     string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// ApprovedTargetFenceApproval persists every immutable capability field except
// Requester. Privacy erasure is allowed to pseudonymize that one spelling, so a
// retry hydrates it from the exact current approval projection while every
// security-relevant field below must remain identical.
type ApprovedTargetFenceApproval struct {
	RequestID         string                            `json:"request_id"`
	IntentDigest      string                            `json:"intent_digest"`
	ResourceKind      string                            `json:"resource_kind"`
	ResourceID        string                            `json:"resource_id"`
	Action            string                            `json:"action"`
	FromState         string                            `json:"from_state,omitempty"`
	ToState           string                            `json:"to_state,omitempty"`
	TargetVersion     uint64                            `json:"target_version"`
	RequiredApprovals int                               `json:"required_approvals"`
	Reason            string                            `json:"reason,omitempty"`
	EvidenceRefs      []string                          `json:"evidence_refs,omitempty"`
	Issuance          *OperationApprovalIssuanceBinding `json:"issuance,omitempty"`
}

func approvedTargetFenceApproval(use OperationApprovalUse) ApprovedTargetFenceApproval {
	return ApprovedTargetFenceApproval{
		RequestID: use.RequestID, IntentDigest: use.IntentDigest,
		ResourceKind: use.ResourceKind, ResourceID: use.ResourceID, Action: use.Action,
		FromState: use.FromState, ToState: use.ToState, TargetVersion: use.TargetVersion,
		RequiredApprovals: use.RequiredApprovals, Reason: use.Reason,
		EvidenceRefs: append([]string(nil), use.EvidenceRefs...), Issuance: use.Issuance,
	}
}

func (a ApprovedTargetFenceApproval) use(requester string) OperationApprovalUse {
	return OperationApprovalUse{
		RequestID: a.RequestID, IntentDigest: a.IntentDigest, Requester: requester,
		ResourceKind: a.ResourceKind, ResourceID: a.ResourceID, Action: a.Action,
		FromState: a.FromState, ToState: a.ToState, TargetVersion: a.TargetVersion,
		RequiredApprovals: a.RequiredApprovals, Reason: a.Reason,
		EvidenceRefs: append([]string(nil), a.EvidenceRefs...), Issuance: a.Issuance,
	}
}

// ValidateApprovedTargetPrivacyRewrite proves that a retained target event's
// approval differs from the durable first command only by the event-log erasure
// transform for the requester already represented by current. Retention leaves
// source history unchanged, so a retained requester accepts only the exact
// original approval. Callers use this only after LockApprovedTargetFenceTx has
// returned privacyRewritten=true.
func ValidateApprovedTargetPrivacyRewrite(
	tenantID string,
	original, current, retained OperationApprovalUse,
) error {
	if current.Reason != "" || len(current.EvidenceRefs) != 0 ||
		(!privacy.IsPlaceholder(current.Requester) && !strings.HasPrefix(current.Requester, "retained:")) {
		return ErrApprovalDrifted
	}
	if reflect.DeepEqual(retained, original) {
		return nil
	}
	if reflect.DeepEqual(retained, current) {
		return nil
	}
	if !privacy.IsPlaceholder(current.Requester) || original.Requester == "" ||
		privacy.Placeholder(privacy.SubjectRef(tenantID, original.Requester)) != current.Requester {
		return ErrApprovalDrifted
	}
	erased := original
	erased.Requester = strings.ReplaceAll(erased.Requester, original.Requester, current.Requester)
	erased.Reason = strings.ReplaceAll(erased.Reason, original.Requester, current.Requester)
	erased.EvidenceRefs = append([]string(nil), erased.EvidenceRefs...)
	for i := range erased.EvidenceRefs {
		erased.EvidenceRefs[i] = strings.ReplaceAll(erased.EvidenceRefs[i], original.Requester, current.Requester)
	}
	if !reflect.DeepEqual(retained, erased) {
		return ErrApprovalDrifted
	}
	return nil
}

// ValidateApprovedTargetActorPrivacyRewrite applies the same narrow rule to the
// event envelope actor. Subject and custom role strings may receive the exact
// tenant-bound replacement, while the role order and cardinality stay fixed. An
// optional erasedSubject lets recovery validate a role-only occurrence when the
// actor subject is a different principal. Older callers omit it and retain the
// original actor-subject behavior.
func ValidateApprovedTargetActorPrivacyRewrite(
	tenantID string,
	original *events.Actor,
	currentRequester string,
	retained *events.Actor,
	erasedSubjects ...string,
) error {
	candidates := erasedSubjects
	if len(candidates) == 0 {
		if original == nil {
			candidates = []string(nil)
		} else {
			candidates = []string{original.Subject}
		}
	}
	if reflect.DeepEqual(retained, original) {
		// An exact actor is valid when this erasure did not touch it (or when
		// retention deliberately leaves source history intact). If the caller
		// supplies the raw erased subject and the current requester is its privacy
		// placeholder, however, an unchanged occurrence would preserve PII.
		if privacy.IsPlaceholder(currentRequester) && original != nil {
			for _, subject := range candidates {
				if subject == "" || privacy.Placeholder(privacy.SubjectRef(tenantID, subject)) != currentRequester {
					continue
				}
				if _, changed := events.PseudonymizeActorForSubject(original, tenantID, subject); changed {
					return ErrApprovalDrifted
				}
			}
		}
		return nil
	}
	if original == nil || retained == nil || !privacy.IsPlaceholder(currentRequester) {
		return ErrApprovalDrifted
	}
	for _, subject := range candidates {
		if subject == "" || privacy.Placeholder(privacy.SubjectRef(tenantID, subject)) != currentRequester {
			continue
		}
		erased, changed := events.PseudonymizeActorForSubject(original, tenantID, subject)
		if changed && reflect.DeepEqual(retained, erased) {
			return nil
		}
	}
	return ErrApprovalDrifted
}

func validateApprovedTargetFence(f ApprovedTargetFence) error {
	if f.TenantID == "" || f.TargetKind == "" || f.CommandKey == "" ||
		f.EventID == "" || f.EventType == "" || f.SchemaVersion <= 0 ||
		f.EventTime.IsZero() || len(f.Payload) == 0 || f.SemanticDigest == "" {
		return errors.New("store: approved target fence is incomplete")
	}
	if f.TargetKind != ApprovedTargetEphemeralCertificate && f.TargetKind != ApprovedTargetCodeSigningCommand {
		return fmt.Errorf("store: unsupported approved target kind %q", f.TargetKind)
	}
	if f.TargetKind == ApprovedTargetCodeSigningCommand && f.SchemaVersion >= 3 &&
		!f.EventTime.Equal(f.EventTime.UTC().Truncate(time.Microsecond)) {
		return errors.New("store: privacy-safe code-signing fence time is not PostgreSQL-exact")
	}
	for name, digest := range map[string]string{
		"request binding": f.RequestBinding,
		"semantic":        f.SemanticDigest,
	} {
		if len(digest) != 64 {
			return fmt.Errorf("store: approved target %s digest is not SHA-256 hex", name)
		}
		if _, err := hex.DecodeString(digest); err != nil {
			return fmt.Errorf("store: approved target %s digest is not SHA-256 hex: %w", name, err)
		}
	}
	if len(f.Approval.IntentDigest) != len("sha256:")+64 || !strings.HasPrefix(f.Approval.IntentDigest, "sha256:") {
		return errors.New("store: approved target intent digest is not prefixed SHA-256 hex")
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(f.Approval.IntentDigest, "sha256:")); err != nil {
		return fmt.Errorf("store: approved target intent digest is not prefixed SHA-256 hex: %w", err)
	}
	if f.Approval.RequestID == "" || f.Approval.ResourceKind == "" || f.Approval.ResourceID == "" ||
		f.Approval.Action == "" || f.Approval.RequiredApprovals <= 0 {
		return errors.New("store: approved target fence capability is incomplete")
	}
	return nil
}

// #nosec G101 -- SQL column identifiers only; this constant contains no credential material.
const approvedTargetFenceColumns = `
	tenant_id::text, target_kind, command_key, request_binding,
	approval_request_id::text, approval_intent_digest, event_id::text,
	event_type, schema_version, event_time, event_actor, event_payload, payload_sha256,
	semantic_sha256, approval, claim_state, created_at, updated_at`

func scanApprovedTargetFence(row pgx.Row) (ApprovedTargetFence, error) {
	var (
		out      ApprovedTargetFence
		actor    []byte
		approval []byte
	)
	if err := row.Scan(&out.TenantID, &out.TargetKind, &out.CommandKey, &out.RequestBinding,
		&out.Approval.RequestID, &out.Approval.IntentDigest, &out.EventID,
		&out.EventType, &out.SchemaVersion, &out.EventTime, &actor, &out.Payload,
		&out.PayloadDigest, &out.SemanticDigest, &approval, &out.ClaimState,
		&out.CreatedAt, &out.UpdatedAt); err != nil {
		return ApprovedTargetFence{}, err
	}
	if len(actor) != 0 {
		if err := json.Unmarshal(actor, &out.Actor); err != nil {
			return ApprovedTargetFence{}, fmt.Errorf("store: decode approved target fence actor: %w", err)
		}
	}
	if len(out.PayloadDigest) != 64 || crypto.SHA256Hex(out.Payload) != out.PayloadDigest {
		return ApprovedTargetFence{}, errors.New("store: approved target fence payload digest mismatch")
	}
	if err := json.Unmarshal(approval, &out.Approval); err != nil {
		return ApprovedTargetFence{}, fmt.Errorf("store: decode approved target fence capability: %w", err)
	}
	if out.ClaimState != ApprovedTargetClaimed {
		return ApprovedTargetFence{}, fmt.Errorf("store: approved target fence has invalid claim state %q", out.ClaimState)
	}
	return out, nil
}

// GetApprovedTargetFence returns a surviving command fence in the tenant's RLS
// context. Missing rows use the store's standard not-found error shape.
func (s *Store) GetApprovedTargetFence(ctx context.Context, tenantID, targetKind, commandKey string) (ApprovedTargetFence, error) {
	var out ApprovedTargetFence
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		out, err = scanApprovedTargetFence(tx.QueryRow(ctx,
			`SELECT `+approvedTargetFenceColumns+`
			   FROM approved_target_event_fences
			  WHERE tenant_id = $1 AND target_kind = $2 AND command_key = $3`,
			tenantID, targetKind, commandKey))
		return err
	})
	return out, err
}

// ListApprovedTargetFences returns all incomplete approved targets for one
// tenant. Startup reconciliation may safely walk it because rows contain public
// certificate data or already-sealed code-signing commands, never private keys.
func (s *Store) ListApprovedTargetFences(ctx context.Context, tenantID string) ([]ApprovedTargetFence, error) {
	out := []ApprovedTargetFence{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+approvedTargetFenceColumns+`
			FROM approved_target_event_fences WHERE tenant_id = $1
			ORDER BY target_kind, command_key`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			fence, err := scanApprovedTargetFence(rows)
			if err != nil {
				return err
			}
			out = append(out, fence)
		}
		return rows.Err()
	})
	return out, err
}

// PseudonymizeApprovedTargetFences rewrites every surviving first-command copy
// with the same byte-preserving transform already applied to event history. It
// runs inside privacy erasure's post-cutover completion callback, before the
// raw approval projection is cleared, so a crash cannot strand PII in recovery
// state or make the rewritten canonical event unverifiable.
func (s *Store) PseudonymizeApprovedTargetFences(ctx context.Context, tenantID, subject string) (int, error) {
	if tenantID == "" || strings.TrimSpace(subject) == "" {
		return 0, errors.New("store: approved target fence pseudonymization requires tenant and subject")
	}
	type row struct {
		targetKind, commandKey, eventID, eventType string
		approvalRequestID, approvalIntentDigest    string
		schema                                     int
		eventTime                                  time.Time
		actor, payload, approval                   []byte
		payloadDigest, semantic                    string
	}
	changed := 0
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT target_kind, command_key, event_id::text, event_type,
			schema_version, event_time, event_actor, event_payload, approval,
			approval_request_id::text, approval_intent_digest, payload_sha256, semantic_sha256
			FROM approved_target_event_fences WHERE tenant_id = $1
			ORDER BY target_kind, command_key FOR UPDATE`, tenantID)
		if err != nil {
			return err
		}
		var pending []row
		for rows.Next() {
			var item row
			if err := rows.Scan(&item.targetKind, &item.commandKey, &item.eventID,
				&item.eventType, &item.schema, &item.eventTime, &item.actor, &item.payload,
				&item.approval, &item.approvalRequestID, &item.approvalIntentDigest,
				&item.payloadDigest, &item.semantic); err != nil {
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
			if crypto.SHA256Hex(item.payload) != item.payloadDigest {
				return fmt.Errorf("store: approved target fence %s payload digest mismatch before privacy rewrite", item.eventID)
			}
			rewritten, payloadChanged, err := events.PseudonymizeEventDataForSubject(
				item.payload, tenantID, subject, item.eventType, item.schema,
			)
			if err != nil {
				return fmt.Errorf("store: pseudonymize approved target payload %s/%s: %w", item.targetKind, item.commandKey, err)
			}
			rewrittenApproval, approvalChanged := events.PseudonymizeDataForSubject(item.approval, tenantID, subject)
			var rewrittenActor []byte
			actorChanged := false
			if len(item.actor) != 0 {
				var actor events.Actor
				if err := json.Unmarshal(item.actor, &actor); err != nil {
					return fmt.Errorf("store: decode approved target actor %s/%s: %w", item.targetKind, item.commandKey, err)
				}
				rewritten, changed := events.PseudonymizeActorForSubject(&actor, tenantID, subject)
				actorChanged = changed
				var err error
				rewrittenActor, err = json.Marshal(rewritten)
				if err != nil {
					return err
				}
			}
			if !payloadChanged && !approvalChanged && !actorChanged {
				continue
			}
			semantic := item.semantic
			if item.targetKind == ApprovedTargetCodeSigningCommand && item.schema == 2 {
				semantic, err = rewriteLegacyApprovedCodeSigningFenceSemantic(legacyApprovedCodeSigningFenceRewrite{
					TenantID: tenantID, CommandKey: item.commandKey,
					EventID: item.eventID, EventType: item.eventType,
					SchemaVersion: item.schema, EventTime: item.eventTime,
					ApprovalRequestID:    item.approvalRequestID,
					ApprovalIntentDigest: item.approvalIntentDigest,
					OriginalActor:        item.actor, OriginalPayload: item.payload,
					RewrittenActor: rewrittenActor, RewrittenPayload: rewritten,
					StoredSemantic: item.semantic,
				})
				if err != nil {
					return fmt.Errorf("store: rewrite legacy approved code-signing fence %s semantic: %w", item.eventID, err)
				}
			}
			var actorValue any
			if len(rewrittenActor) != 0 {
				actorValue = string(rewrittenActor)
			}
			tag, err := tx.Exec(ctx, `UPDATE approved_target_event_fences
				SET event_actor = $4::jsonb, event_payload = $5, payload_sha256 = $6,
				    approval = $7::jsonb, semantic_sha256 = $8, updated_at = now()
				WHERE tenant_id = $1 AND target_kind = $2 AND command_key = $3`,
				tenantID, item.targetKind, item.commandKey, actorValue, rewritten,
				crypto.SHA256Hex(rewritten), string(rewrittenApproval), semantic)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return fmt.Errorf("store: approved target fence disappeared during privacy rewrite")
			}
			changed++
		}
		return nil
	})
	return changed, err
}

type legacyApprovedCodeSigningFenceRewrite struct {
	TenantID, CommandKey, EventID, EventType string
	ApprovalRequestID, ApprovalIntentDigest  string
	SchemaVersion                            int
	EventTime                                time.Time
	OriginalActor, OriginalPayload           []byte
	RewrittenActor, RewrittenPayload         []byte
	StoredSemantic                           string
}

type legacyApprovedCodeSigningFenceCommand struct {
	OperationID       string                `json:"operation_id"`
	IdempotencyKey    string                `json:"idempotency_key,omitempty"`
	IdempotencyKeyRef string                `json:"idempotency_key_ref,omitempty"`
	RequestBinding    string                `json:"request_binding,omitempty"`
	Mode              string                `json:"mode"`
	RequestHash       string                `json:"request_hash"`
	SealedCommand     []byte                `json:"sealed_command"`
	Approval          *OperationApprovalUse `json:"approval,omitempty"`
}

// rewriteLegacyApprovedCodeSigningFenceSemantic keeps a pre-projection schema-v2
// command recoverable while its only durable payload copy is pseudonymized. The
// old historical SHA is also the sole surviving proof of the event timestamp's
// PostgreSQL-truncated nanosecond remainder, so the rewrite must recover exactly
// one remainder before it changes any bytes and bind that exact time into the new
// historical compatibility SHA.
func rewriteLegacyApprovedCodeSigningFenceSemantic(in legacyApprovedCodeSigningFenceRewrite) (string, error) {
	if in.SchemaVersion != 2 || in.EventType != "codesign.commanded" || in.EventTime.IsZero() {
		return "", errors.New("legacy approved code-signing fence envelope is invalid")
	}
	original, originalActor, err := decodeLegacyApprovedCodeSigningFenceBasis(
		in, in.OriginalPayload, in.OriginalActor,
	)
	if err != nil {
		return "", err
	}
	exactTime, err := recoverUniquePostgresNanosecondRemainder(
		in.EventTime, in.StoredSemantic,
		func(candidate time.Time) (string, error) {
			return legacyApprovedCodeSigningFenceHistoricalSemanticDigest(
				in, candidate, originalActor, original,
			)
		},
	)
	if err != nil {
		return "", err
	}
	rewritten, rewrittenActor, err := decodeLegacyApprovedCodeSigningFenceBasis(
		in, in.RewrittenPayload, in.RewrittenActor,
	)
	if err != nil {
		return "", err
	}
	return legacyApprovedCodeSigningFenceHistoricalSemanticDigest(
		in, exactTime, rewrittenActor, rewritten,
	)
}

func decodeLegacyApprovedCodeSigningFenceBasis(
	in legacyApprovedCodeSigningFenceRewrite,
	payload, actorJSON []byte,
) (legacyApprovedCodeSigningFenceCommand, *events.Actor, error) {
	var command legacyApprovedCodeSigningFenceCommand
	if err := json.Unmarshal(payload, &command); err != nil {
		return command, nil, fmt.Errorf("decode legacy approved code-signing command: %w", err)
	}
	if command.OperationID != in.CommandKey || command.IdempotencyKey == "" ||
		command.IdempotencyKeyRef != "" || command.RequestBinding != "" ||
		command.Approval == nil || command.Approval.RequestID != in.ApprovalRequestID ||
		command.Approval.IntentDigest != in.ApprovalIntentDigest {
		return command, nil, fmt.Errorf(
			"%w: legacy approved code-signing command identity differs",
			ErrIdempotencyConflict,
		)
	}
	keyDigest := ""
	switch {
	case LegacyCodeSigningOperationID(in.TenantID, command.IdempotencyKey) == command.OperationID:
		keyDigest = CodeSigningIdempotencyKeyDigest(command.IdempotencyKey)
	default:
		var ok bool
		keyDigest, ok = LegacyCodeSigningStorageKeyDigest(
			command.IdempotencyKey, command.OperationID,
		)
		if !ok {
			return command, nil, fmt.Errorf(
				"%w: legacy approved code-signing key identity differs",
				ErrIdempotencyConflict,
			)
		}
	}
	if _, err := codesigningref.LegacyApprovedCommandSemanticDigest(
		codesigningref.LegacyApprovedCommandSemanticBasis{
			EventID: in.EventID, TenantID: in.TenantID, EventTime: in.EventTime,
			OperationID: command.OperationID, KeyDigest: keyDigest, Mode: command.Mode,
			RequestHash: command.RequestHash, SealedCommand: command.SealedCommand,
			ApprovalRequestID:    command.Approval.RequestID,
			ApprovalIntentDigest: command.Approval.IntentDigest,
		},
	); err != nil {
		return command, nil, err
	}
	var actor *events.Actor
	if len(actorJSON) != 0 {
		actor = &events.Actor{}
		if err := json.Unmarshal(actorJSON, actor); err != nil {
			return command, nil, fmt.Errorf("decode legacy approved code-signing actor: %w", err)
		}
	}
	return command, actor, nil
}

func legacyApprovedCodeSigningFenceHistoricalSemanticDigest(
	in legacyApprovedCodeSigningFenceRewrite,
	eventTime time.Time,
	actor *events.Actor,
	command legacyApprovedCodeSigningFenceCommand,
) (string, error) {
	normalized := command
	use := *command.Approval
	use.Requester = ""
	use.Reason = ""
	use.EvidenceRefs = nil
	normalized.Approval = &use
	if actor != nil {
		copyActor := *actor
		copyActor.Subject = ""
		copyActor.Roles = append([]string(nil), actor.Roles...)
		actor = &copyActor
	}
	basis := struct {
		ID            string                                `json:"id"`
		Type          string                                `json:"type"`
		TenantID      string                                `json:"tenant_id"`
		Time          time.Time                             `json:"time"`
		SchemaVersion int                                   `json:"schema_version"`
		Actor         *events.Actor                         `json:"actor,omitempty"`
		Payload       legacyApprovedCodeSigningFenceCommand `json:"payload"`
	}{in.EventID, in.EventType, in.TenantID, eventTime.UTC(), in.SchemaVersion, actor, normalized}
	raw, err := json.Marshal(basis)
	if err != nil {
		return "", err
	}
	return crypto.SHA256Hex(append(
		[]byte("trstctl:approved-code-signing-event:v1\x00"), raw...,
	)), nil
}

func recoverUniquePostgresNanosecondRemainder(
	storedTime time.Time,
	wantSemantic string,
	semanticAt func(time.Time) (string, error),
) (time.Time, error) {
	decoded, decodeErr := hex.DecodeString(wantSemantic)
	if len(wantSemantic) != 64 || strings.ToLower(wantSemantic) != wantSemantic ||
		decodeErr != nil || len(decoded) != 32 || semanticAt == nil {
		return time.Time{}, fmt.Errorf(
			"%w: legacy approved code-signing semantic digest is invalid",
			ErrIdempotencyConflict,
		)
	}
	base := storedTime.UTC().Truncate(time.Microsecond)
	matches := 0
	var exact time.Time
	for remainder := range 1_000 {
		candidate := base.Add(time.Duration(remainder) * time.Nanosecond)
		semantic, err := semanticAt(candidate)
		if err != nil {
			return time.Time{}, err
		}
		if semantic == wantSemantic {
			exact = candidate
			matches++
		}
	}
	if matches != 1 {
		return time.Time{}, fmt.Errorf(
			"%w: legacy approved code-signing semantic matched %d nanosecond remainders",
			ErrIdempotencyConflict, matches,
		)
	}
	return exact, nil
}

// ClaimApprovedTargetFence atomically stores the first canonical event and
// consumes the exact approval into that event ID before Append. A broker ACK can
// now be lost with the SQL projection without making the grant reusable: the
// independently backed-up row is sufficient to find/project or republish the
// exact same command. A concurrent exact caller receives the first payload;
// changed command bindings or different approval capabilities fail closed.
func (s *Store) ClaimApprovedTargetFence(
	ctx context.Context,
	candidate ApprovedTargetFence,
	use OperationApprovalUse,
) (ApprovedTargetFence, bool, error) {
	var (
		canonical ApprovedTargetFence
		created   bool
	)
	err := s.WithPrivacyRecoveryBarrier(ctx, candidate.TenantID,
		"approved-target claim privacy barrier", func(barrierCtx context.Context) error {
			var err error
			canonical, created, err = s.claimApprovedTargetFenceUnbarriered(barrierCtx, candidate, use)
			return err
		})
	return canonical, created, err
}

func (s *Store) claimApprovedTargetFenceUnbarriered(
	ctx context.Context,
	candidate ApprovedTargetFence,
	use OperationApprovalUse,
) (ApprovedTargetFence, bool, error) {
	candidate.Approval = approvedTargetFenceApproval(use)
	candidate.PayloadDigest = crypto.SHA256Hex(candidate.Payload)
	candidate.ClaimState = ApprovedTargetClaimed
	if err := validateApprovedTargetFence(candidate); err != nil {
		return ApprovedTargetFence{}, false, err
	}
	approvalJSON, err := json.Marshal(candidate.Approval)
	if err != nil {
		return ApprovedTargetFence{}, false, err
	}
	var actorJSON any
	if candidate.Actor != nil {
		raw, marshalErr := json.Marshal(candidate.Actor)
		if marshalErr != nil {
			return ApprovedTargetFence{}, false, marshalErr
		}
		actorJSON = string(raw)
	}
	var (
		canonical ApprovedTargetFence
		created   bool
	)
	err = s.WithTenant(ctx, candidate.TenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			INSERT INTO approved_target_event_fences
			       (tenant_id, target_kind, command_key, request_binding,
			        approval_request_id, approval_intent_digest, event_id,
			        event_type, schema_version, event_time, event_actor, event_payload,
			        payload_sha256, semantic_sha256, approval, claim_state)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $12, $13, $14, $15::jsonb, 'claimed')
			ON CONFLICT DO NOTHING`, candidate.TenantID, candidate.TargetKind,
			candidate.CommandKey, candidate.RequestBinding, candidate.Approval.RequestID,
			candidate.Approval.IntentDigest, candidate.EventID, candidate.EventType,
			candidate.SchemaVersion, candidate.EventTime.UTC(), actorJSON, candidate.Payload,
			candidate.PayloadDigest, candidate.SemanticDigest, string(approvalJSON))
		if err != nil {
			return err
		}
		created = tag.RowsAffected() == 1
		canonical, err = scanApprovedTargetFence(tx.QueryRow(ctx,
			`SELECT `+approvedTargetFenceColumns+`
			   FROM approved_target_event_fences
			  WHERE tenant_id = $1 AND target_kind = $2 AND command_key = $3
			  FOR UPDATE`, candidate.TenantID, candidate.TargetKind, candidate.CommandKey))
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: approved target event identity is already fenced by another command", ErrIdempotencyConflict)
		}
		if err != nil {
			return err
		}
		if canonical.EventID != candidate.EventID || canonical.EventType != candidate.EventType ||
			canonical.SchemaVersion != candidate.SchemaVersion || canonical.RequestBinding != candidate.RequestBinding ||
			!reflect.DeepEqual(canonical.Actor, candidate.Actor) || !reflect.DeepEqual(canonical.Approval, candidate.Approval) {
			return fmt.Errorf("%w: approved target command or capability differs", ErrIdempotencyConflict)
		}
		// Use the current requester's spelling so a privacy rewrite does not make the
		// otherwise immutable capability unusable. Every other field is the fenced copy.
		request, err := s.getOperationApprovalTx(ctx, tx, candidate.TenantID, canonical.Approval.RequestID, true)
		if err != nil {
			return err
		}
		canonicalUse := canonical.Approval.use(request.Requester)
		if err := s.ConsumeOperationApprovalTx(ctx, tx, candidate.TenantID, canonicalUse,
			canonical.EventID, canonical.EventTime); err != nil {
			return err
		}
		return nil
	})
	return canonical, created, err
}

// LockApprovedTargetFenceTx locks a fence and restores its exact approval use
// inside the caller's projection transaction. The grant must already be consumed
// by this fence's event; ConsumeOperationApprovalTx performs that idempotent proof.
func (s *Store) LockApprovedTargetFenceTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, targetKind, commandKey string,
) (ApprovedTargetFence, OperationApprovalUse, bool, error) {
	fence, err := scanApprovedTargetFence(tx.QueryRow(ctx,
		`SELECT `+approvedTargetFenceColumns+`
		   FROM approved_target_event_fences
		  WHERE tenant_id = $1 AND target_kind = $2 AND command_key = $3
		  FOR UPDATE`, tenantID, targetKind, commandKey))
	if err != nil {
		return ApprovedTargetFence{}, OperationApprovalUse{}, false, err
	}
	request, err := s.getOperationApprovalTx(ctx, tx, tenantID, fence.Approval.RequestID, true)
	if err != nil {
		return ApprovedTargetFence{}, OperationApprovalUse{}, false, err
	}
	if request.Status != ApprovalStatusConsumed || request.ConsumedEventID != fence.EventID {
		return ApprovedTargetFence{}, OperationApprovalUse{}, false, ErrApprovalDrifted
	}
	use := fence.Approval.use(request.Requester)
	if err := validateOperationApprovalUseBinding(request, use); err == nil {
		return fence, use, false, nil
	}

	// Privacy erasure/retention is the one authorized rewrite of an already-spent
	// approval. It is deliberately recognizable without guesswork: the requester
	// is a product placeholder, reviewer text is physically gone, and the request
	// is consumed by this exact fenced event. Rebuild uses the still-immutable
	// intent/resource/state fields below; a live approved request or an ordinary
	// requester can never enter this branch.
	privacyRequester := privacy.IsPlaceholder(request.Requester) || strings.HasPrefix(request.Requester, "retained:")
	if !privacyRequester || request.Reason != "" || len(request.EvidenceRefs) != 0 {
		return ApprovedTargetFence{}, OperationApprovalUse{}, false, ErrApprovalDrifted
	}
	use.Reason = request.Reason
	use.EvidenceRefs = append([]string(nil), request.EvidenceRefs...)
	use.Issuance = nil
	if err := validateOperationApprovalUseBinding(request, use); err != nil {
		return ApprovedTargetFence{}, OperationApprovalUse{}, false, err
	}
	return fence, use, true, nil
}

// CompleteApprovedTargetFenceTx retires the independent command only after the
// matching target event has passed its projector and domain mutation. Exact event
// bytes normally match PayloadDigest. SemanticDigest is either the canonical
// normalized digest or, only for a privacy-rewritten legacy schema-v2 code-signing
// fence, the rewritten historical-compatibility digest that retained the exact
// nanosecond proof until this retirement check.
func (s *Store) CompleteApprovedTargetFenceTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, targetKind, commandKey string,
	eventID, eventType string,
	schemaVersion int,
	eventTime time.Time,
	semanticDigest []byte,
) error {
	fence, err := scanApprovedTargetFence(tx.QueryRow(ctx,
		`SELECT `+approvedTargetFenceColumns+`
		   FROM approved_target_event_fences
		  WHERE tenant_id = $1 AND target_kind = $2 AND command_key = $3
		  FOR UPDATE`, tenantID, targetKind, commandKey))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if fence.EventID != eventID || fence.EventType != eventType ||
		fence.SchemaVersion != schemaVersion ||
		!approvedTargetFenceTimesMatch(fence, eventTime, schemaVersion) ||
		!crypto.ConstantTimeEqual([]byte(fence.SemanticDigest), semanticDigest) {
		return fmt.Errorf("%w: projected approved target differs from durable fence", ErrIdempotencyConflict)
	}
	command, err := tx.Exec(ctx, `DELETE FROM approved_target_event_fences WHERE tenant_id = $1 AND target_kind = $2 AND command_key = $3 AND event_id = $4`,
		tenantID, targetKind, commandKey, eventID)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return fmt.Errorf("%w: approved target fence disappeared while completing", ErrIdempotencyConflict)
	}
	return nil
}

func approvedTargetFenceTimesMatch(fence ApprovedTargetFence, eventTime time.Time, schemaVersion int) bool {
	if fence.TargetKind == ApprovedTargetCodeSigningCommand && schemaVersion < 3 {
		return fence.EventTime.Equal(eventTime.UTC().Truncate(time.Microsecond))
	}
	return fence.EventTime.Equal(eventTime.UTC())
}
