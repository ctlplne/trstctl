// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	ApprovalStatusPending    = "pending"
	ApprovalStatusApproved   = "approved"
	ApprovalStatusDenied     = "denied"
	ApprovalStatusExpired    = "expired"
	ApprovalStatusSuperseded = "superseded"
	ApprovalStatusConsumed   = "consumed"

	ApprovalDecisionApprove = "approve"
	ApprovalDecisionDeny    = "deny"
)

var (
	ErrApprovalRequestNotFound = errors.New("store: approval request not found")
	ErrApprovalDigestMismatch  = errors.New("store: approval intent digest mismatch")
	ErrApprovalSelfDecision    = errors.New("store: approval requester cannot decide their own request")
	ErrApprovalExpired         = errors.New("store: approval request expired")
	ErrApprovalSuperseded      = errors.New("store: approval request superseded")
	ErrApprovalConsumed        = errors.New("store: approval authority already consumed")
	ErrApprovalDrifted         = errors.New("store: approval target version or state drifted")
	ErrApprovalNotReady        = errors.New("store: approval request has not reached quorum")
)

// OperationApprovalRequest is the tenant-scoped projection of one immutable
// operation intent. ID and IntentDigest, together, are the capability reviewers
// decide and the eventual operation consumes. Resource/action alone is never
// authority because a later operation can have the same words.
type OperationApprovalRequest struct {
	ID                string
	TenantID          string
	IntentDigest      string
	ResourceKind      string
	ResourceID        string
	ResourceName      string
	Action            string
	Requester         string
	FromState         string
	ToState           string
	TargetVersion     uint64
	Reason            string
	EvidenceRefs      []string
	RequiredApprovals int
	ApprovalCount     int
	Status            string
	CreatedAt         time.Time
	ExpiresAt         time.Time
	UpdatedAt         time.Time
	ConsumedAt        *time.Time
	ConsumedEventID   string
}

// OperationApprovalDomainVisibility keeps the shared queue from flattening
// independent review authorities. A caller sees only the closed-set operation
// families for which the served API already proved its real domain permission.
// Unknown kind/action pairs match no family and therefore stay hidden until an
// explicit authorization mapping is added.
type OperationApprovalDomainVisibility struct {
	CertificateOperations bool
	SecretOperations      bool
	ManagedKeyOperations  bool
}

// AllOperationApprovalDomains is for trusted internal callers and tests that need
// the complete tenant projection. Served reviewer traffic constructs the narrower
// visibility from the authenticated principal instead.
func AllOperationApprovalDomains() OperationApprovalDomainVisibility {
	return OperationApprovalDomainVisibility{
		CertificateOperations: true,
		SecretOperations:      true,
		ManagedKeyOperations:  true,
	}
}

// OperationApprovalListOptions is a stable newest-first keyset page. CreatedAt
// alone is not unique, so the cursor binds both created_at and id.
type OperationApprovalListOptions struct {
	Status         string
	AfterCreatedAt *time.Time
	AfterID        string
	Limit          int
	Visibility     OperationApprovalDomainVisibility
}

// OperationApprovalDecision is one immutable principal decision over an exact
// request digest. EventID makes projection replay distinguish a retry from a
// conflicting second fact.
type OperationApprovalDecision struct {
	TenantID     string
	RequestID    string
	IntentDigest string
	Approver     string
	Decision     string
	Reason       string
	EventID      string
	DecidedAt    time.Time
	// Expected* bind compatibility routes to the object/action shown to the
	// reviewer. Empty means the canonical request-ID route was used.
	ExpectedResourceKind string
	ExpectedResourceID   string
	ExpectedAction       string
}

const (
	operationApprovalEvidenceProfileNamePrefix       = "profile:"
	operationApprovalEvidenceProfileIDPrefix         = "profile-id:"
	operationApprovalEvidenceProfileVersionPrefix    = "profile-version:"
	operationApprovalEvidenceProfileSpecDigestPrefix = "profile-spec-digest:"
	operationApprovalEvidenceRequestedTTLPrefix      = "issuance-requested-ttl-seconds:"
	operationApprovalEvidenceEffectiveTTLPrefix      = "issuance-effective-ttl-seconds:"
)

// OperationApprovalIssuanceBinding is the exact certificate-policy revision and
// validity reviewed for one identity issuance. ProfileName by itself is only a
// display/routing label; ProfileID+Version+SpecDigest are the immutable semantics.
// RequestedTTLSeconds and EffectiveTTLSeconds are both carried so a future TTL
// clamp cannot silently turn the reviewed request into a different certificate.
type OperationApprovalIssuanceBinding struct {
	ProfileName         string `json:"profile_name,omitempty"`
	ProfileID           string `json:"profile_id,omitempty"`
	ProfileVersion      int    `json:"profile_version,omitempty"`
	ProfileSpecDigest   string `json:"profile_spec_digest,omitempty"`
	RequestedTTLSeconds int64  `json:"requested_ttl_seconds"`
	EffectiveTTLSeconds int64  `json:"effective_ttl_seconds"`
}

// EvidenceRefs returns the non-secret canonical approval evidence for this
// issuance binding. The operation-approval intent digest covers these refs.
func (b OperationApprovalIssuanceBinding) EvidenceRefs() ([]string, error) {
	if err := validateOperationApprovalIssuanceBinding(b); err != nil {
		return nil, err
	}
	refs := []string{
		operationApprovalEvidenceRequestedTTLPrefix + strconv.FormatInt(b.RequestedTTLSeconds, 10),
		operationApprovalEvidenceEffectiveTTLPrefix + strconv.FormatInt(b.EffectiveTTLSeconds, 10),
	}
	if b.ProfileName != "" {
		refs = append(refs, operationApprovalEvidenceProfileNamePrefix+b.ProfileName)
	}
	if b.ProfileID != "" {
		refs = append(refs,
			operationApprovalEvidenceProfileIDPrefix+b.ProfileID,
			operationApprovalEvidenceProfileVersionPrefix+strconv.Itoa(b.ProfileVersion),
			operationApprovalEvidenceProfileSpecDigestPrefix+b.ProfileSpecDigest,
		)
	}
	return refs, nil
}

// OperationApprovalUse is embedded in the immutable event that performs the
// authorized mutation. Projecting that event marks the same request consumed in
// the caller's transaction, beside the domain read model and outbox intent.
type OperationApprovalUse struct {
	RequestID         string                            `json:"request_id"`
	IntentDigest      string                            `json:"intent_digest"`
	Requester         string                            `json:"requester"`
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

	// approvedTargetPrivacyRecovery is an in-memory capability set only after
	// LockApprovedTargetFenceTx locks the exact consumed-event fence and proves
	// the SQL row is the privacy preparation's closed marker. It is never encoded
	// into an event, so replayed input cannot manufacture this bypass.
	approvedTargetPrivacyRecovery bool
}

// OperationApprovalAttempt contains the parts of a requester command that stay
// reconstructible after its target has already moved to the approved state. It is
// used only to recover a consumed result across the narrow receiver-commit / HTTP-
// result crash gap; it never makes pending or standing authority executable.
type OperationApprovalAttempt struct {
	ResourceKind         string
	ResourceID           string
	Action               string
	Requester            string
	ToState              string
	Reason               string
	IdempotencyKeyDigest string
	SubjectCSRDigest     string
}

const operationApprovalColumns = `
	r.id::text, r.tenant_id::text, r.intent_digest, r.resource_kind,
	r.resource_id, r.resource_name, r.action, r.requester, r.from_state,
	r.to_state, r.target_version, r.reason, r.evidence_refs,
	r.required_approvals,
	(SELECT count(*) FROM operation_approval_decisions d
	  WHERE d.tenant_id = r.tenant_id AND d.request_id = r.id AND d.decision = 'approve'),
	r.status, r.created_at, r.expires_at, r.updated_at, r.consumed_at,
	coalesce(r.consumed_event_id::text, '')`

func scanOperationApproval(row pgx.Row) (OperationApprovalRequest, error) {
	var (
		out      OperationApprovalRequest
		version  int64
		evidence []byte
	)
	err := row.Scan(&out.ID, &out.TenantID, &out.IntentDigest, &out.ResourceKind,
		&out.ResourceID, &out.ResourceName, &out.Action, &out.Requester,
		&out.FromState, &out.ToState, &version, &out.Reason, &evidence,
		&out.RequiredApprovals, &out.ApprovalCount, &out.Status, &out.CreatedAt,
		&out.ExpiresAt, &out.UpdatedAt, &out.ConsumedAt, &out.ConsumedEventID)
	if err != nil {
		return OperationApprovalRequest{}, err
	}
	if version < 0 {
		return OperationApprovalRequest{}, fmt.Errorf("store: approval target version is negative")
	}
	out.TargetVersion = uint64(version)
	if len(evidence) > 0 {
		if err := json.Unmarshal(evidence, &out.EvidenceRefs); err != nil {
			return OperationApprovalRequest{}, fmt.Errorf("store: decode approval evidence refs: %w", err)
		}
	}
	if out.EvidenceRefs == nil {
		out.EvidenceRefs = []string{}
	}
	return out, nil
}

// ApplyOperationApprovalRequestedTx is the only writer for the request read
// model. Replaying the identical event is a no-op; reusing its ID for different
// immutable content fails closed.
func (s *Store) ApplyOperationApprovalRequestedTx(ctx context.Context, tx pgx.Tx, r OperationApprovalRequest) error {
	if r.TargetVersion > math.MaxInt64 {
		return fmt.Errorf("store: approval target version exceeds PostgreSQL bigint")
	}
	targetVersion := int64(r.TargetVersion) // #nosec G115 -- the explicit MaxInt64 bound above prevents narrowing (CWE-190).
	evidence, err := json.Marshal(r.EvidenceRefs)
	if err != nil {
		return err
	}
	if err := lockUpsertArbiterTx(ctx, tx, "operation_approval_requests", r.TenantID, r.ID); err != nil {
		return err
	}
	command, err := tx.Exec(ctx, `
		INSERT INTO operation_approval_requests
		       (tenant_id, id, intent_digest, resource_kind, resource_id,
		        resource_name, action, requester, from_state, to_state,
		        target_version, reason, evidence_refs, required_approvals,
		        status, created_at, expires_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
		        $11, $12, $13::jsonb, $14, 'pending', $15, $16, $15)
		ON CONFLICT (tenant_id, id) DO NOTHING`,
		r.TenantID, r.ID, r.IntentDigest, r.ResourceKind, r.ResourceID,
		r.ResourceName, r.Action, r.Requester, r.FromState, r.ToState,
		targetVersion, r.Reason, evidence, r.RequiredApprovals,
		r.CreatedAt, r.ExpiresAt)
	if err != nil {
		return err
	}
	if command.RowsAffected() == 0 {
		// An exact request-event replay is a real no-op. In particular, it must not
		// rewrite updated_at after later decision/consume events made the request
		// terminal. Validate every immutable field with PostgreSQL's own timestamptz
		// coercion, then leave the current row untouched.
		var exact bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS (
			  SELECT 1 FROM operation_approval_requests
			   WHERE tenant_id = $1 AND id = $2 AND intent_digest = $3
			     AND resource_kind = $4 AND resource_id = $5 AND resource_name = $6
			     AND action = $7 AND requester = $8 AND from_state = $9 AND to_state = $10
			     AND target_version = $11 AND reason = $12 AND evidence_refs = $13::jsonb
			     AND required_approvals = $14 AND created_at = $15 AND expires_at = $16
			)`, r.TenantID, r.ID, r.IntentDigest, r.ResourceKind, r.ResourceID,
			r.ResourceName, r.Action, r.Requester, r.FromState, r.ToState,
			targetVersion, r.Reason, evidence, r.RequiredApprovals,
			r.CreatedAt, r.ExpiresAt).Scan(&exact); err != nil {
			return err
		}
		if !exact {
			return fmt.Errorf("%w: approval request %s", ErrIdempotencyConflict, r.ID)
		}
	}
	return nil
}

// ApplyOperationApprovalDecisionTx projects an exact review decision. All
// authorization checks live here as well as in the command side, so an imported
// or replayed malformed event cannot create authority.
func (s *Store) ApplyOperationApprovalDecisionTx(ctx context.Context, tx pgx.Tx, d OperationApprovalDecision) error {
	r, err := scanOperationApproval(tx.QueryRow(ctx,
		`SELECT `+operationApprovalColumns+` FROM operation_approval_requests r
		  WHERE r.tenant_id = $1 AND r.id = $2 FOR UPDATE`, d.TenantID, d.RequestID))
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrApprovalRequestNotFound
	}
	if err != nil {
		return err
	}
	if r.IntentDigest != d.IntentDigest {
		return ErrApprovalDigestMismatch
	}
	if d.Approver == "" {
		return ErrAnonymousIssuanceApproval
	}
	if r.Requester == d.Approver {
		return ErrApprovalSelfDecision
	}
	if d.ExpectedResourceKind != "" && d.ExpectedResourceKind != r.ResourceKind ||
		d.ExpectedResourceID != "" && d.ExpectedResourceID != r.ResourceID ||
		d.ExpectedAction != "" && d.ExpectedAction != r.Action {
		return ErrApprovalDigestMismatch
	}
	if d.Decision != ApprovalDecisionApprove && d.Decision != ApprovalDecisionDeny {
		return fmt.Errorf("store: invalid approval decision %q", d.Decision)
	}
	// Projection catch-up can encounter this exact decision after the target
	// operation has already consumed the request inline. Recognize the immutable
	// event before consulting the request's current terminal status; replaying an
	// old fact must not try to grant authority again or poison the tail.
	if found, err := validateExistingOperationApprovalDecision(ctx, tx, d); err != nil {
		return err
	} else if found {
		return nil
	}
	if !d.DecidedAt.Before(r.ExpiresAt) {
		return ErrApprovalExpired
	}
	switch r.Status {
	case ApprovalStatusPending, ApprovalStatusApproved:
	case ApprovalStatusExpired:
		return ErrApprovalExpired
	case ApprovalStatusSuperseded:
		return ErrApprovalSuperseded
	case ApprovalStatusConsumed:
		return ErrApprovalConsumed
	default:
		return ErrApprovalNotReady
	}
	if err := lockUpsertArbiterTx(ctx, tx, "operation_approval_decisions", d.TenantID, d.RequestID, d.Approver); err != nil {
		return err
	}
	command, err := tx.Exec(ctx, `
		INSERT INTO operation_approval_decisions
		       (tenant_id, request_id, intent_digest, approver, decision,
		        reason, event_id, decided_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (tenant_id, request_id, approver) DO NOTHING`,
		d.TenantID, d.RequestID, d.IntentDigest, d.Approver, d.Decision,
		d.Reason, d.EventID, d.DecidedAt)
	if err != nil {
		return err
	}
	if command.RowsAffected() == 0 {
		_, err := validateExistingOperationApprovalDecision(ctx, tx, d)
		return err
	}
	status := ApprovalStatusPending
	if d.Decision == ApprovalDecisionDeny {
		status = ApprovalStatusDenied
	} else {
		var count int
		if err := tx.QueryRow(ctx, `
			SELECT count(*) FROM operation_approval_decisions
			 WHERE tenant_id = $1 AND request_id = $2 AND decision = 'approve'`,
			d.TenantID, d.RequestID).Scan(&count); err != nil {
			return err
		}
		if count >= r.RequiredApprovals {
			status = ApprovalStatusApproved
		}
	}
	_, err = tx.Exec(ctx, `
		UPDATE operation_approval_requests
		   SET status = $3, updated_at = $4
		 WHERE tenant_id = $1 AND id = $2`, d.TenantID, d.RequestID, status, d.DecidedAt)
	return err
}

func validateExistingOperationApprovalDecision(ctx context.Context, tx pgx.Tx, d OperationApprovalDecision) (bool, error) {
	var eventID, digest, priorDecision, priorReason string
	var sameDecidedAt bool
	// timestamptz stores microseconds while the retained JSON event can carry
	// nanoseconds. Compare inside PostgreSQL so its parameter coercion applies to
	// both sides; a Go time.Time comparison would falsely reject that exact event
	// during restart catch-up.
	err := tx.QueryRow(ctx, `
		SELECT event_id::text, intent_digest, decision, reason, decided_at = $4
		  FROM operation_approval_decisions
		 WHERE tenant_id = $1 AND request_id = $2 AND approver = $3`,
		d.TenantID, d.RequestID, d.Approver, d.DecidedAt).Scan(
		&eventID, &digest, &priorDecision, &priorReason, &sameDecidedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if eventID != d.EventID || digest != d.IntentDigest ||
		priorDecision != d.Decision || priorReason != d.Reason || !sameDecidedAt {
		return true, fmt.Errorf("%w: approval decision for %s", ErrIdempotencyConflict, d.RequestID)
	}
	return true, nil
}

// MatchOperationApprovalDecisionCommandTx distinguishes an exact command replay
// from a second command by the same principal. DecidedAt is deliberately omitted:
// it is assigned by the first command and an identical retry cannot reproduce that
// clock reading. The event ID, digest, decision, and caller-supplied reason are the
// immutable command identity; the request row separately binds the expected target.
func (s *Store) MatchOperationApprovalDecisionCommandTx(ctx context.Context, tx pgx.Tx, d OperationApprovalDecision) (bool, error) {
	var eventID, digest, priorDecision, priorReason string
	err := tx.QueryRow(ctx, `
		SELECT event_id::text, intent_digest, decision, reason
		  FROM operation_approval_decisions
		 WHERE tenant_id = $1 AND request_id = $2 AND approver = $3`,
		d.TenantID, d.RequestID, d.Approver).Scan(
		&eventID, &digest, &priorDecision, &priorReason)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if eventID != d.EventID || digest != d.IntentDigest ||
		priorDecision != d.Decision || priorReason != d.Reason {
		return true, fmt.Errorf("%w: approval decision for %s", ErrIdempotencyConflict, d.RequestID)
	}
	return true, nil
}

// ApplyOperationApprovalStatusTx projects expiry/supersession. A terminal or
// consumed request never moves backwards to a reusable state.
func (s *Store) ApplyOperationApprovalStatusTx(ctx context.Context, tx pgx.Tx, tenantID, requestID, digest, status string, at time.Time) error {
	if status != ApprovalStatusExpired && status != ApprovalStatusSuperseded {
		return fmt.Errorf("store: invalid approval terminal status %q", status)
	}
	command, err := tx.Exec(ctx, `
		UPDATE operation_approval_requests
		   SET status = $4, updated_at = $5
		 WHERE tenant_id = $1 AND id = $2 AND intent_digest = $3
		   AND status IN ('pending', 'approved')`, tenantID, requestID, digest, status, at)
	if err != nil {
		return err
	}
	if command.RowsAffected() == 0 {
		r, getErr := s.getOperationApprovalTx(ctx, tx, tenantID, requestID, false)
		if getErr != nil {
			return getErr
		}
		if r.IntentDigest != digest {
			return ErrApprovalDigestMismatch
		}
		if r.Status == status || r.Status == ApprovalStatusConsumed || r.Status == ApprovalStatusDenied {
			return nil
		}
		return ErrApprovalNotReady
	}
	return nil
}

func (s *Store) getOperationApprovalTx(ctx context.Context, tx pgx.Tx, tenantID, requestID string, lock bool) (OperationApprovalRequest, error) {
	locking := ""
	if lock {
		locking = " FOR UPDATE"
	}
	r, err := scanOperationApproval(tx.QueryRow(ctx,
		`SELECT `+operationApprovalColumns+` FROM operation_approval_requests r
		  WHERE r.tenant_id = $1 AND r.id = $2`+locking, tenantID, requestID))
	if errors.Is(err, pgx.ErrNoRows) {
		return OperationApprovalRequest{}, ErrApprovalRequestNotFound
	}
	return r, err
}

func (s *Store) GetOperationApproval(ctx context.Context, tenantID, requestID string) (OperationApprovalRequest, error) {
	var out OperationApprovalRequest
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		out, err = s.GetOperationApprovalTx(ctx, tx, tenantID, requestID)
		return err
	})
	return out, err
}

// GetOperationApprovalTx reads one exact approval through the caller's existing
// tenant transaction. Command paths use this after taking their scope advisory
// lock, so the not-found check and any replacement events share one serial order.
func (s *Store) GetOperationApprovalTx(ctx context.Context, tx pgx.Tx, tenantID, requestID string) (OperationApprovalRequest, error) {
	return s.getOperationApprovalTx(ctx, tx, tenantID, requestID, false)
}

// GetOperationApprovalForUpdateTx holds the exact request row through final
// decision validation, event append, and projection. This closes the race where a
// supersession or consumption could commit after a command-side read but before
// its decision event was projected.
func (s *Store) GetOperationApprovalForUpdateTx(ctx context.Context, tx pgx.Tx, tenantID, requestID string) (OperationApprovalRequest, error) {
	return s.getOperationApprovalTx(ctx, tx, tenantID, requestID, true)
}

// LockOperationApprovalScopeTx serializes every requester-side command that can
// replace live authority for one tenant/kind/resource/action/requester tuple. A
// database row cannot be locked when the first request does not exist, so this
// transaction-scoped advisory lock is the missing-row fence. Length-prefixing
// each untrusted field keeps different tuples from aliasing through delimiters.
func (s *Store) LockOperationApprovalScopeTx(ctx context.Context, tx pgx.Tx, tenantID, resourceKind, resourceID, action, requester string) error {
	if tenantID == "" || resourceKind == "" || resourceID == "" || action == "" || requester == "" {
		return errors.New("store: operation approval scope is incomplete")
	}
	lockKey := fmt.Sprintf("operation-approval-scope:v1|%d:%s|%d:%s|%d:%s|%d:%s|%d:%s",
		len(tenantID), tenantID, len(resourceKind), resourceKind, len(resourceID), resourceID,
		len(action), action, len(requester), requester)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, lockKey); err != nil {
		return fmt.Errorf("store: lock operation approval scope: %w", err)
	}
	return nil
}

// ListOperationApprovals is the genuine reviewer queue. pending never includes
// already-expired rows, even if an expiry command has not yet projected their
// terminal status; time cannot turn an invalid grant back into authority.
func (s *Store) ListOperationApprovals(ctx context.Context, tenantID, status string, limit int) ([]OperationApprovalRequest, error) {
	return s.ListOperationApprovalsPage(ctx, tenantID, OperationApprovalListOptions{
		Status: status, Limit: limit, Visibility: AllOperationApprovalDomains(),
	})
}

// ListOperationApprovalsPage returns one tenant-scoped reviewer page. Status is
// evaluated using effective time, not only the last projected status: an approved
// row whose deadline passed appears under expired and can never leak through an
// approved filter. The visibility predicate is repeated in SQL and in the API so
// neither an adapter bug nor an unknown producer vocabulary broadens authority.
func (s *Store) ListOperationApprovalsPage(ctx context.Context, tenantID string, options OperationApprovalListOptions) ([]OperationApprovalRequest, error) {
	if options.Limit <= 0 || options.Limit > 500 {
		options.Limit = 200
	}
	if !options.Visibility.CertificateOperations && !options.Visibility.SecretOperations && !options.Visibility.ManagedKeyOperations {
		return []OperationApprovalRequest{}, nil
	}
	afterID := options.AfterID
	if options.AfterCreatedAt == nil {
		afterID = ZeroUUID
	}
	var out []OperationApprovalRequest
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		// PostgreSQL's now() is fixed at transaction start. Use that same instant
		// when shaping effective status after the SQL filter so a request that
		// crosses its deadline while rows are being read cannot appear as
		// "expired" inside a pending/approved page.
		var (
			effectiveAt    time.Time
			scopedTenantID string
		)
		// WithTenant has already established this request's tenant-scoped RLS
		// transaction. Reading the transaction clock must not additionally require
		// a materialized tenants row: the authenticated blank-install journey can
		// legitimately reach an empty approval projection before any domain event
		// creates that row. Coupling the clock read to tenants turned an empty queue
		// into pgx.ErrNoRows and the served API translated that into a false 404.
		// Return the RLS GUC beside the clock and verify it before reading rows, so
		// this control query proves the transaction did not drift out of its tenant.
		if err := tx.QueryRow(ctx,
			`SELECT now(), COALESCE(current_setting('trstctl.tenant_id', true), '')`).Scan(
			&effectiveAt, &scopedTenantID); err != nil {
			return err
		}
		if scopedTenantID != tenantID {
			return fmt.Errorf("store: approval queue tenant scope mismatch")
		}
		rows, err := tx.Query(ctx, `
			SELECT `+operationApprovalColumns+` FROM operation_approval_requests r
			 WHERE r.tenant_id = $1
			   AND CASE
			         WHEN $2 = '' THEN TRUE
			         WHEN $2 = 'pending' THEN r.status = 'pending' AND r.expires_at > now()
			         WHEN $2 = 'approved' THEN r.status = 'approved' AND r.expires_at > now()
			         WHEN $2 = 'expired' THEN r.status = 'expired'
			              OR (r.status IN ('pending', 'approved') AND r.expires_at <= now())
			         ELSE r.status = $2
			       END
			   AND ($3::timestamptz IS NULL OR r.created_at < $3
			        OR (r.created_at = $3 AND r.id < $4::uuid))
			   AND (
			        ($6 AND (
			          (r.resource_kind = 'identity' AND r.action IN ('issue', 'rotate', 'revoke', 'sign'))
			          OR (r.resource_kind = 'ephemeral' AND r.action = 'issue')
			          OR (r.resource_kind = 'code_signing' AND r.action = 'sign')
			        ))
			        OR ($7 AND r.resource_kind = 'secret' AND r.action IN ('create', 'rotate', 'recover', 'delete'))
			        OR ($8 AND r.resource_kind = 'managed_key'
			             AND r.action IN ('managedkey:rotate', 'managedkey:revoke', 'managedkey:zeroize'))
			       )
			 ORDER BY r.created_at DESC, r.id DESC LIMIT $5`,
			tenantID, options.Status, options.AfterCreatedAt, afterID, options.Limit,
			options.Visibility.CertificateOperations, options.Visibility.SecretOperations,
			options.Visibility.ManagedKeyOperations)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanOperationApproval(rows)
			if err != nil {
				return err
			}
			if (r.Status == ApprovalStatusPending || r.Status == ApprovalStatusApproved) && !effectiveAt.Before(r.ExpiresAt) {
				r.Status = ApprovalStatusExpired
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	if out == nil {
		out = []OperationApprovalRequest{}
	}
	return out, err
}

// ConsumedOperationApprovalForAttempt finds the one already-spent authority for
// an exact requester attempt. It intentionally excludes every pending/approved
// request: callers may use the result only to reconstruct an operation that has
// already committed, never to grant fresh execution. A raw Idempotency-Key is not
// stored here: the caller supplies its non-secret digest and, when present, the
// caller's CSR digest. Mutable policy-derived evidence (for example profile labels)
// remains authoritative on the original request and is deliberately not re-derived.
func (s *Store) ConsumedOperationApprovalForAttempt(ctx context.Context, tenantID string, attempt OperationApprovalAttempt) (OperationApprovalRequest, bool, error) {
	attempt.ResourceKind = strings.TrimSpace(attempt.ResourceKind)
	attempt.ResourceID = strings.TrimSpace(attempt.ResourceID)
	attempt.Action = strings.TrimSpace(attempt.Action)
	attempt.Requester = strings.TrimSpace(attempt.Requester)
	attempt.ToState = strings.TrimSpace(attempt.ToState)
	attempt.Reason = strings.TrimSpace(attempt.Reason)
	attempt.IdempotencyKeyDigest = strings.TrimSpace(attempt.IdempotencyKeyDigest)
	attempt.SubjectCSRDigest = strings.TrimSpace(attempt.SubjectCSRDigest)
	if tenantID == "" || attempt.ResourceKind == "" || attempt.ResourceID == "" ||
		attempt.Action == "" || attempt.Requester == "" || attempt.ToState == "" ||
		attempt.IdempotencyKeyDigest == "" {
		return OperationApprovalRequest{}, false, errors.New("store: consumed approval attempt is incomplete")
	}
	idempotencyEvidence := "idempotency-key-sha256:" + attempt.IdempotencyKeyDigest
	csrEvidence := ""
	if attempt.SubjectCSRDigest != "" {
		csrEvidence = "csr-sha256:" + attempt.SubjectCSRDigest
	}

	var matches []OperationApprovalRequest
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT `+operationApprovalColumns+` FROM operation_approval_requests r
			 WHERE r.tenant_id = $1 AND r.resource_kind = $2 AND r.resource_id = $3
			   AND r.action = $4 AND r.requester = $5
			   AND r.to_state = $6 AND r.reason = $7
			   AND r.evidence_refs @> jsonb_build_array($8::text)
			   AND (
			       ($9 <> '' AND r.evidence_refs @> jsonb_build_array($9::text))
			       OR ($9 = '' AND NOT EXISTS (
			           SELECT 1 FROM jsonb_array_elements_text(r.evidence_refs) AS evidence(value)
			            WHERE evidence.value LIKE 'csr-sha256:%'
			       ))
			   )
			   AND r.status = 'consumed' AND r.consumed_event_id IS NOT NULL
			 ORDER BY r.consumed_at DESC, r.id
			 LIMIT 2`, tenantID, attempt.ResourceKind, attempt.ResourceID,
			attempt.Action, attempt.Requester, attempt.ToState, attempt.Reason,
			idempotencyEvidence, csrEvidence)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			match, err := scanOperationApproval(rows)
			if err != nil {
				return err
			}
			matches = append(matches, match)
		}
		return rows.Err()
	})
	if err != nil {
		return OperationApprovalRequest{}, false, err
	}
	if len(matches) == 0 {
		return OperationApprovalRequest{}, false, nil
	}
	if len(matches) != 1 {
		return OperationApprovalRequest{}, false,
			fmt.Errorf("%w: multiple consumed approvals match one requester attempt", ErrIdempotencyConflict)
	}
	return matches[0], true, nil
}

// ActiveOperationApprovalsForScope returns only live authority for the exact
// requester/resource/action tuple. It is used to supersede an older digest when
// a new target version is requested.
func (s *Store) ActiveOperationApprovalsForScope(ctx context.Context, tenantID, resourceKind, resourceID, action, requester string) ([]OperationApprovalRequest, error) {
	var out []OperationApprovalRequest
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		out, err = s.ActiveOperationApprovalsForScopeTx(ctx, tx, tenantID,
			resourceKind, resourceID, action, requester)
		return err
	})
	return out, err
}

// ActiveOperationApprovalsForScopeTx returns and row-locks every live request in
// the caller's already scope-locked transaction. Row locks keep a concurrent
// reviewer/consumer from changing an old request between this read and its
// supersession event projection.
func (s *Store) ActiveOperationApprovalsForScopeTx(ctx context.Context, tx pgx.Tx, tenantID, resourceKind, resourceID, action, requester string) ([]OperationApprovalRequest, error) {
	rows, err := tx.Query(ctx, `
		SELECT `+operationApprovalColumns+` FROM operation_approval_requests r
		 WHERE r.tenant_id = $1 AND r.resource_kind = $2 AND r.resource_id = $3
		   AND r.action = $4 AND r.requester = $5
		   AND r.status IN ('pending', 'approved')
		 ORDER BY r.created_at, r.id
		 FOR UPDATE OF r`, tenantID, resourceKind, resourceID, action, requester)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OperationApprovalRequest
	for rows.Next() {
		r, err := scanOperationApproval(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// IdentityApprovalTarget returns the lifecycle state and immutable projection
// sequence an identity approval must bind. Sequence 0 is the created-but-never-
// transitioned state. The transaction form locks the identity row so a target
// event can validate, append, project, enqueue, and consume without a second
// lifecycle command slipping between those steps.
func (s *Store) IdentityApprovalTarget(ctx context.Context, tenantID, identityID string) (Identity, uint64, error) {
	var (
		identity Identity
		version  uint64
	)
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		identity, version, err = s.IdentityApprovalTargetTx(ctx, tx, tenantID, identityID, false)
		return err
	})
	return identity, version, err
}

func (s *Store) IdentityApprovalTargetTx(ctx context.Context, tx pgx.Tx, tenantID, identityID string, lock bool) (Identity, uint64, error) {
	locking := ""
	if lock {
		locking = " FOR UPDATE OF i"
	}
	var (
		identity Identity
		kind     string
		attrs    []byte
		version  int64
	)
	err := tx.QueryRow(ctx, `
		SELECT i.id::text, i.tenant_id::text, i.kind, i.name, i.owner_id::text,
		       i.issuer_id::text, i.status, i.not_before, i.not_after,
		       i.attributes, i.created_at,
		       coalesce((SELECT max(t.seq) FROM identity_transitions t
		                  WHERE t.tenant_id = i.tenant_id AND t.identity_id = i.id), 0)
		  FROM identities i
		 WHERE i.tenant_id = $1 AND i.id = $2`+locking,
		tenantID, identityID).Scan(&identity.ID, &identity.TenantID, &kind,
		&identity.Name, &identity.OwnerID, &identity.IssuerID, &identity.Status,
		&identity.NotBefore, &identity.NotAfter, &attrs, &identity.CreatedAt, &version)
	if err != nil {
		return Identity{}, 0, err
	}
	if version < 0 {
		return Identity{}, 0, fmt.Errorf("store: identity lifecycle version is negative")
	}
	identity.Kind = IdentityKind(kind)
	identity.Attributes = attrs
	return identity, uint64(version), nil
}

// ValidateOperationApprovalUseTx locks and validates the exact one-shot grant.
// Call it before appending the target event; ConsumeOperationApprovalTx then runs
// while the same row lock is held, after projecting that event.
func (s *Store) ValidateOperationApprovalUseTx(ctx context.Context, tx pgx.Tx, tenantID string, use OperationApprovalUse, now time.Time) (OperationApprovalRequest, error) {
	r, err := s.getOperationApprovalTx(ctx, tx, tenantID, use.RequestID, true)
	if err != nil {
		return OperationApprovalRequest{}, err
	}
	if err := validateOperationApprovalUseBinding(r, use); err != nil {
		return OperationApprovalRequest{}, err
	}
	if !now.Before(r.ExpiresAt) || r.Status == ApprovalStatusExpired {
		return OperationApprovalRequest{}, ErrApprovalExpired
	}
	switch r.Status {
	case ApprovalStatusApproved:
		if r.ApprovalCount < r.RequiredApprovals {
			return OperationApprovalRequest{}, ErrApprovalNotReady
		}
		return r, nil
	case ApprovalStatusSuperseded:
		return OperationApprovalRequest{}, ErrApprovalSuperseded
	case ApprovalStatusConsumed:
		return OperationApprovalRequest{}, ErrApprovalConsumed
	default:
		return OperationApprovalRequest{}, ErrApprovalNotReady
	}
}

// ConsumeOperationApprovalTx makes the exact authority single-use. Replaying the
// same target event is idempotent; a different event can never reuse the grant.
func (s *Store) ConsumeOperationApprovalTx(ctx context.Context, tx pgx.Tx, tenantID string, use OperationApprovalUse, eventID string, at time.Time) error {
	r, err := s.getOperationApprovalTx(ctx, tx, tenantID, use.RequestID, true)
	if err != nil {
		return err
	}
	if bindingErr := validateOperationApprovalUseBinding(r, use); bindingErr != nil {
		if !use.approvedTargetPrivacyRecovery || r.Status != ApprovalStatusConsumed ||
			r.ConsumedEventID != eventID {
			return bindingErr
		}
		if err := validatePreparedApprovedTargetPrivacyUse(r, use); err != nil {
			return err
		}
		return nil
	}
	if r.Status == ApprovalStatusConsumed {
		if r.ConsumedEventID == eventID {
			return nil
		}
		return ErrApprovalConsumed
	}
	if _, err := s.ValidateOperationApprovalUseTx(ctx, tx, tenantID, use, at); err != nil {
		return err
	}
	command, err := tx.Exec(ctx, `
		UPDATE operation_approval_requests
		   SET status = 'consumed', consumed_at = $5, consumed_event_id = $4,
		       updated_at = $5
		 WHERE tenant_id = $1 AND id = $2 AND intent_digest = $3
		   AND status = 'approved'`, tenantID, use.RequestID, use.IntentDigest, eventID, at)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrApprovalConsumed
	}
	return nil
}

func validateOperationApprovalUseBinding(r OperationApprovalRequest, use OperationApprovalUse) error {
	if r.IntentDigest != use.IntentDigest {
		return ErrApprovalDigestMismatch
	}
	if r.Requester != use.Requester || r.ResourceKind != use.ResourceKind ||
		r.ResourceID != use.ResourceID || r.Action != use.Action ||
		r.FromState != use.FromState || r.ToState != use.ToState ||
		r.TargetVersion != use.TargetVersion || r.RequiredApprovals != use.RequiredApprovals {
		return ErrApprovalDrifted
	}
	// New exact-command producers carry the complete reviewer-visible reason and
	// evidence set. Nil remains readable for historical/non-lifecycle events; v4
	// lifecycle projection requires a non-nil set before it can consume authority.
	// Nil remains the legacy event shape. Every producer that carries reviewer
	// evidence, including an explicitly empty v4 slice, must match the projected
	// request exactly. The durable approved-target fence has a separate,
	// consumed-event-only privacy recovery path; weakening this generic validator
	// would let a fresh command disguise evidence drift as erasure.
	if use.EvidenceRefs != nil &&
		(r.Reason != use.Reason || !sameOperationApprovalEvidence(r.EvidenceRefs, use.EvidenceRefs)) {
		return ErrApprovalDrifted
	}
	expectedIssuance, err := operationApprovalIssuanceBindingFromEvidence(r.EvidenceRefs)
	if err != nil || !sameOperationApprovalIssuanceBinding(expectedIssuance, use.Issuance) {
		return ErrApprovalDrifted
	}
	return nil
}

// ValidateOperationApprovalUseBinding verifies that an event capability still
// names the exact immutable request reviewers approved. It deliberately does
// not inspect mutable execution state (quorum, expiry, supersession, or
// consumption), so recovery callers can prove identity before deciding whether
// a consumed event is an exact replay.
func ValidateOperationApprovalUseBinding(r OperationApprovalRequest, use OperationApprovalUse) error {
	return validateOperationApprovalUseBinding(r, use)
}

// OperationApprovalUseFromRequest reconstructs the complete event capability
// from the immutable projected request. It is used for receiver-commit/HTTP-result
// recovery, where today's active profile must not replace the revision carried by
// the already-consumed event.
func OperationApprovalUseFromRequest(r OperationApprovalRequest) (OperationApprovalUse, error) {
	issuance, err := operationApprovalIssuanceBindingFromEvidence(r.EvidenceRefs)
	if err != nil {
		return OperationApprovalUse{}, err
	}
	return OperationApprovalUse{
		RequestID: r.ID, IntentDigest: r.IntentDigest, Requester: r.Requester,
		ResourceKind: r.ResourceKind, ResourceID: r.ResourceID, Action: r.Action,
		FromState: r.FromState, ToState: r.ToState, TargetVersion: r.TargetVersion,
		RequiredApprovals: r.RequiredApprovals, Reason: r.Reason,
		EvidenceRefs: append([]string(nil), r.EvidenceRefs...), Issuance: issuance,
	}, nil
}

func sameOperationApprovalEvidence(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func operationApprovalIssuanceBindingFromEvidence(refs []string) (*OperationApprovalIssuanceBinding, error) {
	var (
		binding                               OperationApprovalIssuanceBinding
		profileNameSeen, profileIDSeen        bool
		profileVersionSeen, profileDigestSeen bool
		requestedTTLSeen, effectiveTTLSeen    bool
	)
	setString := func(ref, prefix string, seen *bool, dest *string) error {
		if !strings.HasPrefix(ref, prefix) {
			return nil
		}
		if *seen {
			return fmt.Errorf("store: approval evidence repeats %s", strings.TrimSuffix(prefix, ":"))
		}
		*seen = true
		*dest = strings.TrimSpace(strings.TrimPrefix(ref, prefix))
		return nil
	}
	for _, ref := range refs {
		switch {
		case strings.HasPrefix(ref, operationApprovalEvidenceProfileIDPrefix):
			if err := setString(ref, operationApprovalEvidenceProfileIDPrefix, &profileIDSeen, &binding.ProfileID); err != nil {
				return nil, err
			}
		case strings.HasPrefix(ref, operationApprovalEvidenceProfileVersionPrefix):
			if profileVersionSeen {
				return nil, errors.New("store: approval evidence repeats profile-version")
			}
			profileVersionSeen = true
			version, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(ref, operationApprovalEvidenceProfileVersionPrefix)))
			if err != nil {
				return nil, fmt.Errorf("store: approval evidence has invalid profile-version: %w", err)
			}
			binding.ProfileVersion = version
		case strings.HasPrefix(ref, operationApprovalEvidenceProfileSpecDigestPrefix):
			if err := setString(ref, operationApprovalEvidenceProfileSpecDigestPrefix, &profileDigestSeen, &binding.ProfileSpecDigest); err != nil {
				return nil, err
			}
		case strings.HasPrefix(ref, operationApprovalEvidenceRequestedTTLPrefix):
			if requestedTTLSeen {
				return nil, errors.New("store: approval evidence repeats issuance-requested-ttl-seconds")
			}
			requestedTTLSeen = true
			seconds, err := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(ref, operationApprovalEvidenceRequestedTTLPrefix)), 10, 64)
			if err != nil {
				return nil, fmt.Errorf("store: approval evidence has invalid requested TTL: %w", err)
			}
			binding.RequestedTTLSeconds = seconds
		case strings.HasPrefix(ref, operationApprovalEvidenceEffectiveTTLPrefix):
			if effectiveTTLSeen {
				return nil, errors.New("store: approval evidence repeats issuance-effective-ttl-seconds")
			}
			effectiveTTLSeen = true
			seconds, err := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(ref, operationApprovalEvidenceEffectiveTTLPrefix)), 10, 64)
			if err != nil {
				return nil, fmt.Errorf("store: approval evidence has invalid effective TTL: %w", err)
			}
			binding.EffectiveTTLSeconds = seconds
		case strings.HasPrefix(ref, operationApprovalEvidenceProfileNamePrefix):
			if err := setString(ref, operationApprovalEvidenceProfileNamePrefix, &profileNameSeen, &binding.ProfileName); err != nil {
				return nil, err
			}
		}
	}
	hasRevision := profileIDSeen || profileVersionSeen || profileDigestSeen
	hasTTL := requestedTTLSeen || effectiveTTLSeen
	if !hasRevision && !hasTTL {
		// A lone profile:<name> ref is the historical label-only shape. It stays
		// readable, but creates no revision-bound issuance capability.
		return nil, nil
	}
	if profileNameSeen && !hasRevision {
		return nil, errors.New("store: approval evidence names a profile without an exact revision binding")
	}
	if hasRevision && (!profileNameSeen || !profileIDSeen || !profileVersionSeen || !profileDigestSeen) {
		return nil, errors.New("store: approval evidence has an incomplete profile revision binding")
	}
	if !requestedTTLSeen || !effectiveTTLSeen {
		return nil, errors.New("store: approval evidence must bind requested and effective issuance TTL")
	}
	if err := validateOperationApprovalIssuanceBinding(binding); err != nil {
		return nil, err
	}
	return &binding, nil
}

func validateOperationApprovalIssuanceBinding(b OperationApprovalIssuanceBinding) error {
	b.ProfileName = strings.TrimSpace(b.ProfileName)
	b.ProfileID = strings.TrimSpace(b.ProfileID)
	b.ProfileSpecDigest = strings.TrimSpace(b.ProfileSpecDigest)
	if b.RequestedTTLSeconds <= 0 || b.EffectiveTTLSeconds <= 0 ||
		b.EffectiveTTLSeconds > b.RequestedTTLSeconds {
		return errors.New("store: approval issuance TTL binding is invalid")
	}
	hasRevision := b.ProfileName != "" || b.ProfileID != "" || b.ProfileVersion != 0 || b.ProfileSpecDigest != ""
	if hasRevision && (b.ProfileName == "" || b.ProfileID == "" || b.ProfileVersion <= 0 ||
		len(b.ProfileSpecDigest) != len("sha256:")+64 || !strings.HasPrefix(b.ProfileSpecDigest, "sha256:")) {
		return errors.New("store: approval profile revision binding is incomplete")
	}
	return nil
}

func sameOperationApprovalIssuanceBinding(a, b *OperationApprovalIssuanceBinding) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}
