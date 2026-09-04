// SPDX-License-Identifier: MPL-2.0

package store

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/codesigningref"
	"trstctl.com/trstctl/internal/privacy"
)

// PrivacyErasureSelectors names the read-model rows that must be pseudonymized
// for one subject erasure. It carries stable identifiers, not the erased subject.
type PrivacyErasureSelectors struct {
	OwnerIDs                []string                   `json:"owner_ids,omitempty"`
	IdentityIDs             []string                   `json:"identity_ids,omitempty"`
	CertificateRefs         []string                   `json:"certificate_refs,omitempty"`
	CertificateFingerprints []string                   `json:"certificate_fingerprints,omitempty"`
	SSHKeyIDs               []string                   `json:"ssh_key_ids,omitempty"`
	AttestationIDs          []string                   `json:"attestation_ids,omitempty"`
	ApprovalRequests        []PrivacyApprovalSelector  `json:"approval_requests,omitempty"`
	Approvals               []PrivacyApprovalSelector  `json:"approvals,omitempty"`
	ProfileIDs              []string                   `json:"profile_ids,omitempty"`
	AgentIDs                []string                   `json:"agent_ids,omitempty"`
	AgentOffboardActorIDs   []string                   `json:"agent_offboard_actor_ids,omitempty"`
	AgentOffboardReasonIDs  []string                   `json:"agent_offboard_reason_ids,omitempty"`
	CodeSigningOperationIDs []string                   `json:"code_signing_operation_ids,omitempty"`
	ReadModels              []PrivacyReadModelSelector `json:"read_models,omitempty"`
}

// PrivacyApprovalSelector is the non-PII row key for one dual-control actor tie.
// The raw requester/approver is deliberately excluded from privacy events.
type PrivacyApprovalSelector struct {
	// BindingRef is a tenant-bound one-way reference to resource+action. New
	// privacy events use only this field because both legacy key components are
	// arbitrary text and may themselves contain the erased subject.
	BindingRef string `json:"binding_ref,omitempty"`
	Resource   string `json:"resource,omitempty"`
	Action     string `json:"action,omitempty"`
}

// PrivacyReadModelSelector is a non-PII row key for newer operational read models.
// Some models have a UUID row id; a small number use a parent id or threshold value
// because their primary key includes the raw subject being erased.
type PrivacyReadModelSelector struct {
	Table         string `json:"table"`
	ID            string `json:"id,omitempty"`
	ParentID      string `json:"parent_id,omitempty"`
	ThresholdDays int    `json:"threshold_days,omitempty"`
}

var privacyReadModelSelectorTables = map[string]struct{}{
	"operation_approval_requests": {}, "operation_approval_decisions": {},
	"pam_sessions": {}, "discovery_sources": {}, "discovery_findings": {},
	"notification_threshold_deliveries": {}, "incident_executions": {},
	"nhi_access_review_campaigns": {}, "nhi_access_review_items": {},
	"access_change_requests": {}, "access_change_request_decisions": {},
	"discovery_runs": {}, "notification_routing_policies": {},
	"remediation_playbook_runs": {}, "compliance_report_schedules": {},
	"incident_fleet_reissuance_runs": {}, "ownership_readiness_exceptions": {},
}

// ValidatePrivacyErasureSelectorsV3 proves that every selector emitted by the
// current producer is a UUID or a tenant-bound one-way reference. Legacy v1/v2
// composite approval keys and raw certificate fingerprints remain replayable,
// but a v3 event may never carry them back into sanitized history.
func ValidatePrivacyErasureSelectorsV3(selectors PrivacyErasureSelectors) error {
	if len(selectors.CertificateFingerprints) != 0 {
		return errors.New("store: privacy v3 selectors contain legacy raw certificate fingerprints")
	}
	for _, ref := range selectors.CertificateRefs {
		if !IsPrivacyReference(ref) {
			return errors.New("store: privacy v3 certificate selector is not a one-way reference")
		}
	}
	for _, group := range [][]string{
		selectors.OwnerIDs, selectors.IdentityIDs, selectors.SSHKeyIDs,
		selectors.AttestationIDs, selectors.ProfileIDs, selectors.AgentIDs,
		selectors.AgentOffboardActorIDs, selectors.AgentOffboardReasonIDs,
	} {
		for _, id := range group {
			if !validPrivacyUUID(id) {
				return errors.New("store: privacy v3 selector contains a non-UUID row key")
			}
		}
	}
	for _, operationID := range selectors.CodeSigningOperationIDs {
		if !validCodeSigningOperationID(operationID) {
			return errors.New("store: privacy v3 code-signing selector is not a canonical operation id")
		}
	}
	for _, selector := range append(
		append([]PrivacyApprovalSelector(nil), selectors.ApprovalRequests...),
		selectors.Approvals...,
	) {
		if selector.Resource != "" || selector.Action != "" ||
			!IsPrivacyReference(selector.BindingRef) {
			return errors.New("store: privacy v3 approval selector contains a raw or invalid composite key")
		}
	}
	for _, selector := range selectors.ReadModels {
		if _, ok := privacyReadModelSelectorTables[selector.Table]; !ok {
			return fmt.Errorf("store: privacy v3 selector table %q is unsupported", selector.Table)
		}
		for _, id := range []string{selector.ID, selector.ParentID} {
			if id == "" {
				continue
			}
			if !validPrivacyUUID(id) {
				return fmt.Errorf("store: privacy v3 %s selector contains a non-UUID row key", selector.Table)
			}
		}
		if selector.Table == "notification_threshold_deliveries" {
			if selector.ID != "" || selector.ParentID != "" || selector.ThresholdDays <= 0 {
				return errors.New("store: privacy v3 notification threshold selector is malformed")
			}
		} else if selector.ID == "" || selector.ThresholdDays != 0 {
			return fmt.Errorf("store: privacy v3 %s selector is incomplete", selector.Table)
		}
	}
	return nil
}

func validPrivacyUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed.String() == value
}

func validCodeSigningOperationID(value string) bool {
	const prefix = "codesign-"
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	return validPrivacyUUID(strings.TrimPrefix(value, prefix))
}

// IsPrivacyReference reports whether a value is the canonical lowercase
// SHA-256 shape emitted by privacy.SubjectRef. It validates only the opaque
// storage shape; the tenant/raw-subject binding is proved by the producer.
func IsPrivacyReference(ref string) bool {
	if len(ref) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(ref)
	return err == nil && len(decoded) == 32 && strings.ToLower(ref) == ref
}

// ValidatePrivacyErasureCountsV3 rejects arbitrary map keys that could smuggle
// subject text into the v3 event. Values are aggregate row counts only.
func ValidatePrivacyErasureCountsV3(counts map[string]int) error {
	allowed := map[string]struct{}{
		"owners": {}, "identities": {}, "certificates": {}, "ssh_keys": {},
		"attestations": {}, "approval_requests": {}, "approvals": {},
		"profiles": {}, "agents": {}, "agent_offboard_actors": {},
		"agent_offboard_reasons": {}, "api_tokens": {}, "tenant_members": {},
		"read_models": {}, "application_secret_mutation_fences": {},
		"approved_target_event_fences": {}, "code_signing_operations": {},
		"read_model_snapshots": {}, "secret_rotation_schedule_ticks": {},
		"secret_rotation_schedule_tick_rows":         {},
		"secret_rotation_schedule_commands":          {},
		"secret_rotation_schedule_outer_resolutions": {},
	}
	for table := range privacyReadModelSelectorTables {
		allowed[table] = struct{}{}
	}
	for key, count := range counts {
		if _, ok := allowed[key]; !ok || count < 0 {
			return fmt.Errorf("store: privacy v3 count %q is unsupported or negative", key)
		}
	}
	return nil
}

// PrivacySubjectErasure is the projected evidence for one subject erasure.
type PrivacySubjectErasure struct {
	TenantID       string
	SubjectRef     string
	RequestedByRef string
	Reason         string
	Selectors      PrivacyErasureSelectors
	Counts         map[string]int
	ErasedAt       time.Time
}

// PrivacySubjectErasureOperation is the durable, tenant-scoped AN-5 receiver
// populated from a v2 privacy.subject.erased event. Unlike ordinary read models,
// PostgreSQL backup/rebuild preserves it because the event may already live only
// in a signed retention archive. It is never overwritten by a later erasure.
type PrivacySubjectErasureOperation struct {
	PrivacySubjectErasure
	OperationID    string
	RequestBinding string
	EventID        string
	EventSequence  uint64
}

// PRIVACY-004: a data-subject ACCESS/PORTABILITY export. Erasure already enumerates
// the rows tied to a subject (SelectPrivacySubjectErasure → selectors), but an
// operator answering a subject-access request also needs the actual record CONTENT
// the subject can see — the inverse capability. SelectPrivacySubjectExport collects
// every subject-linked record across the privacy catalog (owners, identities,
// certificates, SSH keys, attestations, tenant members, API tokens, dual-control
// approvals, including exact operation-approval authority) for one tenant under
// RLS (AN-1). It is a pure READ: it carries no secret material (API-token hashes
// are never selected; only the principal subject and non-secret metadata), so the
// result is safe to hand to the subject or an auditor. It is the served basis for
// export; rectify/erase reuse the existing event-sourced erasure/retention
// machinery.

// PrivacyOwnerRecord is one owner row linked to the subject.
type PrivacyOwnerRecord struct {
	ID                  string     `json:"id"`
	Kind                string     `json:"kind"`
	Name                string     `json:"name"`
	Email               string     `json:"email"`
	ApplicationID       string     `json:"application_id,omitempty"`
	Service             string     `json:"service,omitempty"`
	BusinessUnit        string     `json:"business_unit,omitempty"`
	Environment         string     `json:"environment,omitempty"`
	EscalationChain     []string   `json:"escalation_chain,omitempty"`
	OwnershipVerifiedBy string     `json:"ownership_verified_by,omitempty"`
	OwnershipVerifiedAt *time.Time `json:"ownership_verified_at,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
}

// PrivacyIdentityRecord is one identity row linked to the subject (by name or an
// attribute value).
type PrivacyIdentityRecord struct {
	ID         string    `json:"id"`
	Kind       string    `json:"kind"`
	Name       string    `json:"name"`
	Status     string    `json:"status"`
	Attributes string    `json:"attributes"`
	CreatedAt  time.Time `json:"created_at"`
}

// PrivacyCertificateRecord is one certificate row whose subject/SAN matches.
type PrivacyCertificateRecord struct {
	BrokerIssuance     *BrokerIssuance `json:"broker_issuance,omitempty"`
	Fingerprint        string          `json:"fingerprint"`
	Subject            string          `json:"subject"`
	SANs               []string        `json:"sans"`
	Serial             string          `json:"serial"`
	Issuer             string          `json:"issuer"`
	DeploymentLocation string          `json:"deployment_location"`
	Source             string          `json:"source"`
	CreatedAt          time.Time       `json:"created_at"`
}

// PrivacySSHKeyRecord is one SSH key row whose comment/location matches.
type PrivacySSHKeyRecord struct {
	ID          string    `json:"id"`
	Fingerprint string    `json:"fingerprint"`
	KeyType     string    `json:"key_type"`
	Comment     string    `json:"comment"`
	Location    string    `json:"location"`
	CreatedAt   time.Time `json:"created_at"`
}

// PrivacyAttestationRecord is one attestation row whose evidence references the
// subject. Evidence is the free-form JSON payload (already tenant-scoped).
type PrivacyAttestationRecord struct {
	ID        string    `json:"id"`
	Evidence  string    `json:"evidence"`
	CreatedAt time.Time `json:"created_at"`
}

// PrivacyMemberRecord is one tenant_members row for the subject (RBAC membership).
type PrivacyMemberRecord struct {
	Subject     string   `json:"subject"`
	DisplayName string   `json:"display_name"`
	Email       string   `json:"email"`
	Roles       []string `json:"roles"`
	Status      string   `json:"status"`
}

// PrivacyTokenRecord is one api_tokens row for the subject. The token hash is NEVER
// included — only the principal subject, scopes, and lifecycle timestamps.
type PrivacyTokenRecord struct {
	ID        string     `json:"id"`
	Subject   string     `json:"subject"`
	Scopes    []string   `json:"scopes"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// PrivacyApprovalRecord is one dual-control approval/request actor tie to the
// subject (requester or approver).
type PrivacyApprovalRecord struct {
	Resource string    `json:"resource"`
	Action   string    `json:"action"`
	Role     string    `json:"role"` // "requester" | "approver"
	At       time.Time `json:"at"`
}

// PrivacyReadModelRecord is a generic export row for PII-bearing operational read
// models that do not need a dedicated public DTO. Data is JSON text containing only
// the non-secret columns from that read model.
type PrivacyReadModelRecord struct {
	Table    string    `json:"table"`
	ID       string    `json:"id"`
	ParentID string    `json:"parent_id,omitempty"`
	Data     string    `json:"data"`
	At       time.Time `json:"at"`
}

// PrivacySubjectExport is the assembled data-subject access/portability view for one
// subject in one tenant. Counts mirrors the per-category record totals so a caller
// can verify completeness at a glance. It contains no secret material.
type PrivacySubjectExport struct {
	TenantID     string                     `json:"tenant_id"`
	Subject      string                     `json:"subject"`
	SubjectRef   string                     `json:"subject_ref"`
	Owners       []PrivacyOwnerRecord       `json:"owners"`
	Identities   []PrivacyIdentityRecord    `json:"identities"`
	Certificates []PrivacyCertificateRecord `json:"certificates"`
	SSHKeys      []PrivacySSHKeyRecord      `json:"ssh_keys"`
	Attestations []PrivacyAttestationRecord `json:"attestations"`
	Members      []PrivacyMemberRecord      `json:"tenant_members"`
	Tokens       []PrivacyTokenRecord       `json:"api_tokens"`
	Approvals    []PrivacyApprovalRecord    `json:"approvals"`
	ReadModels   []PrivacyReadModelRecord   `json:"read_models"`
	Counts       map[string]int             `json:"counts"`
	GeneratedAt  time.Time                  `json:"generated_at"`
}

// SelectPrivacySubjectExport gathers every subject-linked record across the privacy
// catalog for one tenant (PRIVACY-004 data-subject access/portability). It is
// tenant-scoped under RLS (AN-1) and read-only — no event is emitted for an export,
// and no secret material (e.g. api_tokens.token_hash) is read. The subject is
// matched the same way erasure matches it: owner email/name, identity name/attribute,
// certificate subject/SAN, SSH comment/location, attestation evidence, and the
// tenant-bound subject_ref for members/tokens/approvals.
func (s *Store) SelectPrivacySubjectExport(ctx context.Context, tenantID, subject string) (PrivacySubjectExport, error) {
	if tenantID == "" {
		return PrivacySubjectExport{}, fmt.Errorf("store: privacy export requires a tenant id (AN-1)")
	}
	if subject == "" {
		return PrivacySubjectExport{}, fmt.Errorf("store: privacy export requires a subject")
	}
	out := PrivacySubjectExport{
		TenantID:    tenantID,
		Subject:     subject,
		SubjectRef:  privacy.SubjectRef(tenantID, subject),
		Counts:      map[string]int{},
		GeneratedAt: time.Now().UTC(),
	}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		// Owners (matched by email or name).
		rows, err := tx.Query(ctx,
			`SELECT id::text, kind, name, email,
			        coalesce(application_id, ''), coalesce(service, ''),
			        coalesce(business_unit, ''), coalesce(environment, ''),
			        escalation_chain, coalesce(ownership_verified_by, ''),
			        ownership_verified_at, created_at
			   FROM owners
			  WHERE tenant_id = $1
			    AND (email = $2 OR position($2 in name) > 0
			      OR position($2 in coalesce(application_id, '')) > 0
			      OR position($2 in coalesce(service, '')) > 0
			      OR position($2 in coalesce(business_unit, '')) > 0
			      OR escalation_chain @> jsonb_build_array($2::text)
			      OR coalesce(ownership_verified_by, '') = $2)
			  ORDER BY id`, tenantID, subject)
		if err != nil {
			return err
		}
		for rows.Next() {
			var r PrivacyOwnerRecord
			if err := rows.Scan(&r.ID, &r.Kind, &r.Name, &r.Email,
				&r.ApplicationID, &r.Service, &r.BusinessUnit, &r.Environment,
				&r.EscalationChain, &r.OwnershipVerifiedBy, &r.OwnershipVerifiedAt,
				&r.CreatedAt); err != nil {
				rows.Close()
				return err
			}
			out.Owners = append(out.Owners, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		// Identities (matched by name or an attribute value).
		rows, err = tx.Query(ctx,
			`SELECT id::text, kind, name, status, attributes::text, created_at
			   FROM identities
			  WHERE tenant_id = $1 AND (name = $2 OR position($2 in attributes::text) > 0)
			  ORDER BY id`, tenantID, subject)
		if err != nil {
			return err
		}
		for rows.Next() {
			var r PrivacyIdentityRecord
			if err := rows.Scan(&r.ID, &r.Kind, &r.Name, &r.Status, &r.Attributes, &r.CreatedAt); err != nil {
				rows.Close()
				return err
			}
			out.Identities = append(out.Identities, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		// Certificates (matched by subject, SAN, deployment location, or source).
		rows, err = tx.Query(ctx,
			`SELECT fingerprint, subject, sans, serial, issuer, deployment_location, source, created_at, broker_issuance
				  FROM certificates
				  WHERE tenant_id = $1
				    AND (subject = $2 OR subject = 'CN=' || $2 OR $2 = ANY(sans) OR deployment_location = $2 OR source = $2
				      OR position($2 in coalesce(broker_issuance::text, '')) > 0)
				  ORDER BY fingerprint`, tenantID, subject)
		if err != nil {
			return err
		}
		for rows.Next() {
			var r PrivacyCertificateRecord
			if err := rows.Scan(&r.Fingerprint, &r.Subject, &r.SANs, &r.Serial, &r.Issuer, &r.DeploymentLocation, &r.Source, &r.CreatedAt, &r.BrokerIssuance); err != nil {
				rows.Close()
				return err
			}
			out.Certificates = append(out.Certificates, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		// SSH keys (matched by comment or location).
		rows, err = tx.Query(ctx,
			`SELECT id::text, fingerprint, key_type, comment, location, created_at
			   FROM ssh_keys
			  WHERE tenant_id = $1 AND (comment = $2 OR location = $2)
			  ORDER BY id`, tenantID, subject)
		if err != nil {
			return err
		}
		for rows.Next() {
			var r PrivacySSHKeyRecord
			if err := rows.Scan(&r.ID, &r.Fingerprint, &r.KeyType, &r.Comment, &r.Location, &r.CreatedAt); err != nil {
				rows.Close()
				return err
			}
			out.SSHKeys = append(out.SSHKeys, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		// Attestations (evidence references the subject).
		rows, err = tx.Query(ctx,
			`SELECT id::text, evidence::text, created_at
			   FROM attestations
			  WHERE tenant_id = $1 AND position($2 in evidence::text) > 0
			  ORDER BY id`, tenantID, subject)
		if err != nil {
			return err
		}
		for rows.Next() {
			var r PrivacyAttestationRecord
			if err := rows.Scan(&r.ID, &r.Evidence, &r.CreatedAt); err != nil {
				rows.Close()
				return err
			}
			out.Attestations = append(out.Attestations, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		// Tenant members (matched by subject_ref).
		rows, err = tx.Query(ctx,
			`SELECT subject, display_name, email, roles, status
			   FROM tenant_members
			  WHERE tenant_id = $1 AND subject_ref = $2
			  ORDER BY subject`, tenantID, out.SubjectRef)
		if err != nil {
			return err
		}
		for rows.Next() {
			var r PrivacyMemberRecord
			if err := rows.Scan(&r.Subject, &r.DisplayName, &r.Email, &r.Roles, &r.Status); err != nil {
				rows.Close()
				return err
			}
			out.Members = append(out.Members, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		// API tokens (matched by subject_ref). token_hash is deliberately NOT selected.
		rows, err = tx.Query(ctx,
			`SELECT id::text, subject, scopes, expires_at, created_at
			   FROM api_tokens
			  WHERE tenant_id = $1 AND subject_ref = $2
			  ORDER BY id`, tenantID, out.SubjectRef)
		if err != nil {
			return err
		}
		for rows.Next() {
			var r PrivacyTokenRecord
			if err := rows.Scan(&r.ID, &r.Subject, &r.Scopes, &r.ExpiresAt, &r.CreatedAt); err != nil {
				rows.Close()
				return err
			}
			out.Tokens = append(out.Tokens, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		// Dual-control approvals: requester ties and approver ties.
		rows, err = tx.Query(ctx,
			`SELECT resource, action, 'requester' AS role, created_at AS at
			   FROM issuance_approval_requests
			  WHERE tenant_id = $1 AND requester = $2
			  UNION ALL
			 SELECT resource, action, 'approver' AS role, approved_at AS at
			   FROM issuance_approvals
			  WHERE tenant_id = $1 AND approver = $2
			  ORDER BY at`, tenantID, subject)
		if err != nil {
			return err
		}
		for rows.Next() {
			var r PrivacyApprovalRecord
			if err := rows.Scan(&r.Resource, &r.Action, &r.Role, &r.At); err != nil {
				rows.Close()
				return err
			}
			out.Approvals = append(out.Approvals, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		// Newer served read models with operator/requester/reviewer/free-form PII.
		for _, q := range privacyReadModelExportQueries(tenantID, subject) {
			if err := appendPrivacyReadModelRecords(ctx, tx, &out.ReadModels, q.table, q.sql, q.args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return PrivacySubjectExport{}, err
	}
	out.Counts = map[string]int{
		"owners":         len(out.Owners),
		"identities":     len(out.Identities),
		"certificates":   len(out.Certificates),
		"ssh_keys":       len(out.SSHKeys),
		"attestations":   len(out.Attestations),
		"tenant_members": len(out.Members),
		"api_tokens":     len(out.Tokens),
		"approvals":      len(out.Approvals),
		"read_models":    len(out.ReadModels),
	}
	for _, r := range out.ReadModels {
		out.Counts[r.Table]++
	}
	return out, nil
}

// PrivacyRetentionCutoffs is the non-PII payload that makes a retention run
// replayable. The event carries time boundaries, not the raw subjects/approvers
// being anonymized.
type PrivacyRetentionCutoffs struct {
	OwnerInactiveBefore       time.Time `json:"owner_inactive_before"`
	IdentityTerminalBefore    time.Time `json:"identity_terminal_before"`
	CertificateTerminalBefore time.Time `json:"certificate_terminal_before"`
	SSHStaleBefore            time.Time `json:"ssh_stale_before"`
	AccessTerminalBefore      time.Time `json:"access_terminal_before"`
	ApprovalActorBefore       time.Time `json:"approval_actor_before"`
	ProfileActorBefore        time.Time `json:"profile_actor_before"`
	AttestationEvidenceBefore time.Time `json:"attestation_evidence_before"`
	AgentStaleBefore          time.Time `json:"agent_stale_before"`
}

// PrivacyRetentionRun is projected evidence for one non-audit PII retention pass.
type PrivacyRetentionRun struct {
	TenantID       string
	RunID          string
	RequestedByRef string
	Cutoffs        PrivacyRetentionCutoffs
	Counts         map[string]int
	EnforcedAt     time.Time
}

// PrivacyArchiveErasureAttestation is the projected evidence that an operator
// handled pre-erasure backups or signed audit archives for one erased subject.
// It stores the tenant-bound subject_ref, never the raw subject value.
type PrivacyArchiveErasureAttestation struct {
	TenantID       string
	AttestationID  string
	SubjectRef     string
	RequestedByRef string
	ArtifactType   string
	ArtifactURI    string
	Action         string
	Reason         string
	EvidenceRefs   []string
	HeldUntil      *time.Time
	AttestedAt     time.Time
}

// Total reports the number of rows selected for anonymization.
func (r PrivacyRetentionRun) Total() int {
	var n int
	for _, c := range r.Counts {
		n += c
	}
	return n
}

// SelectPrivacySubjectErasure resolves a raw subject into non-PII selectors that
// can be recorded in the privacy.subject.erased event.
func (s *Store) SelectPrivacySubjectErasure(ctx context.Context, tenantID, subject string) (PrivacySubjectErasure, error) {
	if tenantID == "" {
		return PrivacySubjectErasure{}, fmt.Errorf("store: privacy erasure requires a tenant id (AN-1)")
	}
	if subject == "" {
		return PrivacySubjectErasure{}, fmt.Errorf("store: privacy erasure requires a subject")
	}
	var out PrivacySubjectErasure
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return s.selectPrivacySubjectErasureTx(ctx, tx, tenantID, subject, &out)
	})
	return out, err
}

// selectPrivacySubjectErasureTx captures every stable selector on the caller's
// transaction. Privacy rewrite preparation uses this form so no SQL recovery
// fence or approval authority can change between selection and its pre-cutover
// pseudonymization.
func (s *Store) selectPrivacySubjectErasureTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, subject string,
	out *PrivacySubjectErasure,
) error {
	if out == nil {
		return errors.New("store: privacy erasure selector output is nil")
	}
	*out = PrivacySubjectErasure{
		TenantID:   tenantID,
		SubjectRef: privacy.SubjectRef(tenantID, subject),
		Counts:     map[string]int{},
	}
	var err error
	if out.Selectors.OwnerIDs, err = selectStrings(ctx, tx,
		`SELECT id::text FROM owners
			  WHERE tenant_id = $1
			    AND (email = $2 OR position($2 in name) > 0
			      OR position($2 in coalesce(application_id, '')) > 0
			      OR position($2 in coalesce(service, '')) > 0
			      OR position($2 in coalesce(business_unit, '')) > 0
			      OR escalation_chain @> jsonb_build_array($2::text)
			      OR coalesce(ownership_verified_by, '') = $2)
			  ORDER BY id`, tenantID, subject); err != nil {
		return err
	}
	if out.Selectors.IdentityIDs, err = selectStrings(ctx, tx,
		`SELECT id::text FROM identities
			  WHERE tenant_id = $1 AND (name = $2 OR position($2 in attributes::text) > 0)
			  ORDER BY id`, tenantID, subject); err != nil {
		return err
	}
	certificateFingerprints, err := selectStrings(ctx, tx,
		`SELECT fingerprint FROM certificates
			  WHERE tenant_id = $1
			    AND (subject = $2 OR subject = 'CN=' || $2 OR $2 = ANY(sans) OR deployment_location = $2 OR source = $2
			      OR position($2 in coalesce(broker_issuance::text, '')) > 0)
			  ORDER BY fingerprint`, tenantID, subject)
	if err != nil {
		return err
	}
	for _, fingerprint := range certificateFingerprints {
		out.Selectors.CertificateRefs = append(out.Selectors.CertificateRefs,
			privacyCertificateRef(tenantID, fingerprint))
	}
	if out.Selectors.SSHKeyIDs, err = selectStrings(ctx, tx,
		`SELECT id::text FROM ssh_keys
			  WHERE tenant_id = $1 AND (comment = $2 OR location = $2)
			  ORDER BY id`, tenantID, subject); err != nil {
		return err
	}
	if out.Selectors.AttestationIDs, err = selectStrings(ctx, tx,
		`SELECT id::text FROM attestations
			  WHERE tenant_id = $1 AND position($2 in evidence::text) > 0
			  ORDER BY id`, tenantID, subject); err != nil {
		return err
	}
	if out.Selectors.ApprovalRequests, err = selectPrivacyApprovalSelectors(ctx, tx, tenantID,
		`SELECT resource, action
			   FROM issuance_approval_requests
			  WHERE tenant_id = $1 AND requester = $2
			  ORDER BY resource, action`, tenantID, subject); err != nil {
		return err
	}
	if out.Selectors.Approvals, err = selectPrivacyApprovalSelectors(ctx, tx, tenantID,
		`SELECT resource, action
			   FROM issuance_approvals
			  WHERE tenant_id = $1 AND approver = $2
			  ORDER BY resource, action`, tenantID, subject); err != nil {
		return err
	}
	if out.Selectors.ProfileIDs, err = selectStrings(ctx, tx,
		`SELECT id::text FROM certificate_profiles
			  WHERE tenant_id = $1 AND created_by = $2
			  ORDER BY id`, tenantID, subject); err != nil {
		return err
	}
	if out.Selectors.AgentIDs, err = selectStrings(ctx, tx,
		`SELECT id::text FROM agents
				  WHERE tenant_id = $1 AND name = $2
				  ORDER BY id`, tenantID, subject); err != nil {
		return err
	}
	if out.Selectors.AgentOffboardActorIDs, err = selectStrings(ctx, tx,
		`SELECT id::text FROM agents
			  WHERE tenant_id = $1 AND COALESCE(offboarded_by, '') = $2
			  ORDER BY id`, tenantID, subject); err != nil {
		return err
	}
	if out.Selectors.AgentOffboardReasonIDs, err = selectStrings(ctx, tx,
		`SELECT id::text FROM agents
			  WHERE tenant_id = $1 AND position($2 in COALESCE(offboard_reason, '')) > 0
			  ORDER BY id`, tenantID, subject); err != nil {
		return err
	}
	for _, q := range privacyReadModelSelectorQueries(tenantID, subject) {
		if err := appendPrivacyReadModelSelectors(ctx, tx, &out.Selectors.ReadModels, q.table, q.sql, q.args...); err != nil {
			return err
		}
	}
	if out.Selectors.CodeSigningOperationIDs, err = selectLegacyCodeSigningOperationsForSubject(
		ctx, tx, tenantID, subject,
	); err != nil {
		return err
	}
	memberCount, err := selectCount(ctx, tx,
		`SELECT count(*) FROM tenant_members WHERE tenant_id = $1 AND subject_ref = $2`,
		tenantID, out.SubjectRef)
	if err != nil {
		return err
	}
	tokenCount, err := selectCount(ctx, tx,
		`SELECT count(*) FROM api_tokens WHERE tenant_id = $1 AND subject_ref = $2`,
		tenantID, out.SubjectRef)
	if err != nil {
		return err
	}
	out.Counts["tenant_members"] = memberCount
	out.Counts["api_tokens"] = tokenCount
	fenceCount, err := selectCount(ctx, tx,
		`SELECT count(*) FROM application_secret_mutation_fences
			  WHERE tenant_id = $1
			    AND ((requester_ref = $2 AND event_time IS NULL AND approval IS NULL)
			         OR actor_subject_ref = $2)`, tenantID, out.SubjectRef)
	if err != nil {
		return err
	}
	out.Counts["application_secret_mutation_fences"] = fenceCount
	for k, v := range countsForPrivacySelectors(out.Selectors) {
		if _, ok := out.Counts[k]; !ok {
			out.Counts[k] = v
		}
	}
	return nil
}

// selectLegacyCodeSigningOperationsForSubject keeps the raw mutation key inside
// the selecting transaction. Only rows whose historical v1/v2 UUID derivation
// proves that the stored value is the original key become event selectors; a v3
// digest that happens to contain the subject text is never misclassified.
func selectLegacyCodeSigningOperationsForSubject(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, subject string,
) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT operation_id, idempotency_key
		FROM code_signing_operations
		WHERE tenant_id = $1 AND position($2 in idempotency_key) > 0
		ORDER BY operation_id`, tenantID, subject)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var operationIDs []string
	for rows.Next() {
		var operationID, idempotencyKey string
		if err := rows.Scan(&operationID, &idempotencyKey); err != nil {
			return nil, err
		}
		if LegacyCodeSigningOperationID(tenantID, idempotencyKey) == operationID {
			operationIDs = append(operationIDs, operationID)
		}
	}
	return operationIDs, rows.Err()
}

// pseudonymizeLegacyCodeSigningOperationKeysTx converges a warm row with the
// privacy-rewritten v1/v2 event representation. The exact operation selector is
// the durable mapping: raw legacy keys are accepted only when they derive that
// historical UUID, and current v3 identities can never cross this branch.
func pseudonymizeLegacyCodeSigningOperationKeysTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID string,
	operationIDs []string,
) error {
	if len(operationIDs) == 0 {
		return nil
	}
	type operation struct {
		operationID, idempotencyKey, mode, requestHash string
		sealedCommand                                  []byte
		createdAt                                      time.Time
		sourceEventID, approvalRequestID               string
		approvalIntentDigest, semanticDigest           string
	}
	rows, err := tx.Query(ctx, `SELECT operation_id, idempotency_key, mode, request_hash,
		sealed_command, created_at, COALESCE(source_event_id::text, ''),
		COALESCE(approval_request_id::text, ''), COALESCE(approval_intent_digest, ''),
		COALESCE(command_semantic_sha256, '')
		FROM code_signing_operations
		WHERE tenant_id = $1 AND operation_id = ANY($2::text[])
		ORDER BY operation_id FOR UPDATE`, tenantID, operationIDs)
	if err != nil {
		return err
	}
	operations := make(map[string]operation, len(operationIDs))
	for rows.Next() {
		var item operation
		if err := rows.Scan(&item.operationID, &item.idempotencyKey, &item.mode,
			&item.requestHash, &item.sealedCommand, &item.createdAt, &item.sourceEventID,
			&item.approvalRequestID, &item.approvalIntentDigest, &item.semanticDigest); err != nil {
			rows.Close()
			return err
		}
		operations[item.operationID] = item
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, operationID := range operationIDs {
		item, ok := operations[operationID]
		if !ok {
			return fmt.Errorf("%w: selected code-signing operation disappeared", ErrIdempotencyConflict)
		}
		mapped := item.idempotencyKey
		keyDigest, alreadyMapped := LegacyCodeSigningStorageKeyDigest(item.idempotencyKey, operationID)
		if !alreadyMapped {
			if codesigningref.IsLegacyStorageKey(item.idempotencyKey) ||
				LegacyCodeSigningOperationID(tenantID, item.idempotencyKey) != operationID {
				return fmt.Errorf("%w: selected code-signing operation is not a legacy raw-key row", ErrIdempotencyConflict)
			}
			keyDigest = CodeSigningIdempotencyKeyDigest(item.idempotencyKey)
			mapped = LegacyCodeSigningStorageKey(operationID, item.idempotencyKey)
		}
		semanticDigest := item.semanticDigest
		switch {
		case item.sourceEventID == "":
			if item.approvalRequestID != "" || item.approvalIntentDigest != "" || item.semanticDigest != "" {
				return fmt.Errorf("%w: unapproved legacy code-signing operation carries approval identity", ErrIdempotencyConflict)
			}
		case item.approvalRequestID == "" || item.approvalIntentDigest == "":
			return fmt.Errorf("%w: approved legacy code-signing operation lacks approval identity", ErrIdempotencyConflict)
		default:
			var err error
			semanticDigest, err = codesigningref.LegacyApprovedCommandSemanticDigest(
				codesigningref.LegacyApprovedCommandSemanticBasis{
					EventID: item.sourceEventID, TenantID: tenantID, EventTime: item.createdAt,
					OperationID: operationID, KeyDigest: keyDigest, Mode: item.mode,
					RequestHash: item.requestHash, SealedCommand: item.sealedCommand,
					ApprovalRequestID:    item.approvalRequestID,
					ApprovalIntentDigest: item.approvalIntentDigest,
				})
			if err != nil {
				return err
			}
		}
		if !alreadyMapped && LegacyCodeSigningOperationID(tenantID, item.idempotencyKey) != operationID {
			return fmt.Errorf("%w: selected code-signing operation is not a legacy raw-key row", ErrIdempotencyConflict)
		}
		tag, err := tx.Exec(ctx, `UPDATE code_signing_operations
			SET idempotency_key = $3, command_semantic_sha256 = NULLIF($4, '')
			WHERE tenant_id = $1 AND operation_id = $2 AND idempotency_key = $5`,
			tenantID, operationID, mapped, semanticDigest, item.idempotencyKey)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("%w: selected code-signing operation changed during privacy erasure", ErrIdempotencyConflict)
		}
	}
	return nil
}

// SelectPrivacyRetention counts terminal/stale personal-data rows for one tenant.
// It returns only class cutoffs and aggregate counts, so the subsequent event can
// prove enforcement without storing the personal values being removed.
func (s *Store) SelectPrivacyRetention(ctx context.Context, tenantID, runID string, policy privacy.RetentionPolicy, now time.Time) (PrivacyRetentionRun, error) {
	if tenantID == "" {
		return PrivacyRetentionRun{}, fmt.Errorf("store: privacy retention requires a tenant id (AN-1)")
	}
	if runID == "" {
		return PrivacyRetentionRun{}, fmt.Errorf("store: privacy retention requires a run id")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	policy = policy.WithDefaults()
	run := PrivacyRetentionRun{
		TenantID: tenantID,
		RunID:    runID,
		Cutoffs: PrivacyRetentionCutoffs{
			OwnerInactiveBefore:       now.Add(-policy.OwnerInactiveAfter),
			IdentityTerminalBefore:    now.Add(-policy.IdentityTerminalAfter),
			CertificateTerminalBefore: now.Add(-policy.CertificateTerminalAfter),
			SSHStaleBefore:            now.Add(-policy.SSHStaleAfter),
			AccessTerminalBefore:      now.Add(-policy.AccessTerminalAfter),
			ApprovalActorBefore:       now.Add(-policy.ApprovalActorAfter),
			ProfileActorBefore:        now.Add(-policy.ProfileActorAfter),
			AttestationEvidenceBefore: now.Add(-policy.AttestationEvidenceAfter),
			AgentStaleBefore:          now.Add(-policy.AgentStaleAfter),
		},
		Counts: map[string]int{},
	}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		counts, err := countPrivacyRetentionRows(ctx, tx, tenantID, run.Cutoffs)
		if err != nil {
			return err
		}
		run.Counts = counts
		return nil
	})
	if err != nil {
		return PrivacyRetentionRun{}, err
	}
	return run, nil
}

// ApplyPrivacySubjectErasedTx projects a privacy.subject.erased event. The event
// is the source of truth; this method only derives the tenant read model from its
// subject_ref and stable selectors.
func (s *Store) ApplyPrivacySubjectErasedTx(ctx context.Context, tx pgx.Tx, e PrivacySubjectErasure) error {
	if e.ErasedAt.IsZero() {
		e.ErasedAt = time.Now().UTC()
	}
	if e.Counts == nil {
		e.Counts = countsForPrivacySelectors(e.Selectors)
	}
	selectors, err := json.Marshal(e.Selectors)
	if err != nil {
		return err
	}
	counts, err := json.Marshal(e.Counts)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO privacy_subject_erasures
		        (tenant_id, subject_ref, requested_by_ref, reason, selectors, counts, erased_at)
		 VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7)
		 ON CONFLICT (tenant_id, subject_ref) DO UPDATE
		    SET requested_by_ref = EXCLUDED.requested_by_ref,
		        reason = EXCLUDED.reason,
		        selectors = EXCLUDED.selectors,
		        counts = EXCLUDED.counts,
		        erased_at = EXCLUDED.erased_at
		  WHERE EXCLUDED.erased_at >= privacy_subject_erasures.erased_at`,
		e.TenantID, e.SubjectRef, e.RequestedByRef, e.Reason, selectors, counts, e.ErasedAt); err != nil {
		return err
	}
	placeholder := privacy.Placeholder(e.SubjectRef)
	if err := pseudonymizeLegacyCodeSigningOperationKeysTx(
		ctx, tx, e.TenantID, e.Selectors.CodeSigningOperationIDs,
	); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE tenant_members
		    SET subject = $3,
		        display_name = '',
		        email = '',
		        status = 'offboarded',
		        updated_at = $4,
		        offboarded_at = COALESCE(offboarded_at, $4),
		        offboarded_by = 'privacy-erasure',
		        offboard_reason = CASE WHEN offboard_reason = '' THEN $5 ELSE offboard_reason END
		  WHERE tenant_id = $1 AND subject_ref = $2 AND subject <> $3`,
		e.TenantID, e.SubjectRef, placeholder, e.ErasedAt, e.Reason); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE api_tokens
		    SET subject = $3,
		        revoked_at = COALESCE(revoked_at, $4),
		        revoked_by = CASE WHEN revoked_by = '' THEN 'privacy-erasure' ELSE revoked_by END,
		        revocation_reason = CASE WHEN revocation_reason = '' THEN $5 ELSE revocation_reason END
		  WHERE tenant_id = $1 AND subject_ref = $2`,
		e.TenantID, e.SubjectRef, placeholder, e.ErasedAt, e.Reason); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE owners
		    SET name = 'erased:' || left(id::text, 12), email = '',
		        application_id = '', service = '', business_unit = '',
		        escalation_chain = '[]'::jsonb,
		        ownership_verified_by = CASE
		          WHEN ownership_verified_by = '' THEN ''
		          ELSE $3
		        END
		  WHERE tenant_id = $1 AND id::text = ANY($2::text[])`,
		e.TenantID, e.Selectors.OwnerIDs, placeholder); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE identities
		    SET name = 'erased:' || left(id::text, 12), attributes = '{}'::jsonb
		  WHERE tenant_id = $1 AND id::text = ANY($2::text[])`,
		e.TenantID, e.Selectors.IdentityIDs); err != nil {
		return err
	}
	certificateFingerprints, err := resolvePrivacyCertificateFingerprints(
		ctx, tx, e.TenantID, e.Selectors,
	)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE certificates
			    SET subject = 'erased:' || left(fingerprint, 12),
			        sans = '{}'::text[],
			        deployment_location = '',
			        source = '', broker_issuance = NULL
			  WHERE tenant_id = $1 AND fingerprint = ANY($2::text[])`,
		e.TenantID, certificateFingerprints); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE ssh_keys
		    SET comment = '', location = ''
		  WHERE tenant_id = $1 AND id::text = ANY($2::text[])`,
		e.TenantID, e.Selectors.SSHKeyIDs); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE attestations
		    SET evidence = '{}'::jsonb
		  WHERE tenant_id = $1 AND id::text = ANY($2::text[])`,
		e.TenantID, e.Selectors.AttestationIDs); err != nil {
		return err
	}
	if err := eraseApprovalRequestActors(ctx, tx, e.TenantID, e.SubjectRef, placeholder, e.Selectors.ApprovalRequests); err != nil {
		return err
	}
	if err := eraseApprovalActors(ctx, tx, e.TenantID, e.SubjectRef, placeholder, e.Selectors.Approvals); err != nil {
		return err
	}
	// A command has not crossed its point of no return until event_time is durable.
	// Delete every earlier state, including a bound approval: keeping it would let
	// restart publish an event for the erased actor. The selected approval request
	// is independently pseudonymized and superseded above.
	if _, err := tx.Exec(ctx,
		`DELETE FROM application_secret_mutation_fences
		  WHERE tenant_id = $1
		    AND (requester_ref = $2 OR actor_subject_ref = $2)
		    AND event_time IS NULL`, e.TenantID, e.SubjectRef); err != nil {
		return err
	}
	// A bound/finalized command is already the durable point of no return. Keep
	// its recoverable audit envelope, but replace only the raw actor subject with
	// the same tenant-bound placeholder used by event-history erasure. Roles are
	// authorization metadata, not PII, and remain byte-for-byte exact.
	if _, err := tx.Exec(ctx,
		`UPDATE application_secret_mutation_fences
		    SET actor = jsonb_set(actor, '{subject}', to_jsonb($3::text), false),
		        actor_subject_ref = NULL
		  WHERE tenant_id = $1 AND actor_subject_ref = $2`,
		e.TenantID, e.SubjectRef, placeholder); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE certificate_profiles
		    SET created_by = $3
		  WHERE tenant_id = $1 AND id::text = ANY($2::text[])`,
		e.TenantID, e.Selectors.ProfileIDs, placeholder); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE agents
			    SET name = $3
			  WHERE tenant_id = $1 AND id::text = ANY($2::text[])`,
		e.TenantID, e.Selectors.AgentIDs, placeholder); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE agents
		    SET offboarded_by = $3
		  WHERE tenant_id = $1 AND id::text = ANY($2::text[])`,
		e.TenantID, e.Selectors.AgentOffboardActorIDs, placeholder); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE agents
		    SET offboard_reason = ''
		  WHERE tenant_id = $1 AND id::text = ANY($2::text[])`,
		e.TenantID, e.Selectors.AgentOffboardReasonIDs); err != nil {
		return err
	}
	if err := erasePrivacyReadModelRows(ctx, tx, e.TenantID, e.SubjectRef, placeholder, e.Selectors.ReadModels); err != nil {
		return err
	}
	return nil
}

// ApplyPrivacySubjectErasureOperationTx projects a v2 erasure as both the
// append-only durable receiver and the latest per-subject aggregate. Reapplying
// the exact event rebuilds/anonymizes the aggregate idempotently; a collision
// fails closed and cannot overwrite the authoritative response. The operation
// row and aggregate share this transaction.
func (s *Store) ApplyPrivacySubjectErasureOperationTx(
	ctx context.Context,
	tx pgx.Tx,
	op PrivacySubjectErasureOperation,
) error {
	if op.TenantID == "" || op.OperationID == "" || op.RequestBinding == "" ||
		op.EventID == "" || op.EventSequence == 0 || op.EventSequence > math.MaxInt64 ||
		op.SubjectRef == "" || op.ErasedAt.IsZero() {
		return errors.New("store: privacy subject erasure operation is incomplete")
	}
	// PostgreSQL timestamptz stores microseconds. Normalize before the first
	// write and every replay comparison so a Linux nanosecond clock cannot turn
	// the exact same immutable event into a false idempotency conflict.
	op.ErasedAt = op.ErasedAt.UTC().Truncate(time.Microsecond)
	selectors, err := json.Marshal(op.Selectors)
	if err != nil {
		return err
	}
	counts := op.Counts
	if counts == nil {
		counts = countsForPrivacySelectors(op.Selectors)
	}
	countsJSON, err := json.Marshal(counts)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		"privacy-subject-erasure-operation\x1f"+op.TenantID+"\x1f"+op.EventID); err != nil {
		return fmt.Errorf("store: lock privacy erasure operation: %w", err)
	}
	tag, err := tx.Exec(ctx,
		`INSERT INTO privacy_subject_erasure_operations
		        (tenant_id, operation_id, request_binding, event_id, event_sequence,
		         subject_ref, requested_by_ref, reason, selectors, counts, erased_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10::jsonb, $11)
		 ON CONFLICT DO NOTHING`,
		op.TenantID, op.OperationID, op.RequestBinding, op.EventID, int64(op.EventSequence),
		op.SubjectRef, op.RequestedByRef, op.Reason, selectors, countsJSON, op.ErasedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 1 {
		op.Counts = counts
		if err := s.ApplyPrivacySubjectErasedTx(ctx, tx, op.PrivacySubjectErasure); err != nil {
			return err
		}
		return s.completePrivacySubjectErasurePreparationTx(ctx, tx, op)
	}

	existing, err := scanPrivacySubjectErasureOperation(tx.QueryRow(ctx,
		`SELECT tenant_id::text, operation_id, request_binding, event_id, event_sequence,
		        subject_ref, requested_by_ref, reason, selectors, counts, erased_at
		   FROM privacy_subject_erasure_operations
		  WHERE tenant_id = $1 AND operation_id = $2`,
		op.TenantID, op.OperationID))
	if errors.Is(err, pgx.ErrNoRows) {
		existing, err = scanPrivacySubjectErasureOperation(tx.QueryRow(ctx,
			`SELECT tenant_id::text, operation_id, request_binding, event_id, event_sequence,
			        subject_ref, requested_by_ref, reason, selectors, counts, erased_at
			   FROM privacy_subject_erasure_operations
			  WHERE tenant_id = $1 AND event_id = $2`,
			op.TenantID, op.EventID))
	}
	if err != nil {
		return err
	}
	equal, err := privacySubjectErasureOperationsEqual(existing, op)
	if err != nil {
		return err
	}
	if !equal {
		return fmt.Errorf("%w: privacy erasure operation belongs to another command", ErrIdempotencyConflict)
	}
	// Rebuild preserves this independent operation table while truncating the
	// subject aggregate. Reapplying the exact event must therefore still rebuild
	// that aggregate; replay order ensures a later subject operation wins again.
	op.Counts = counts
	if err := s.ApplyPrivacySubjectErasedTx(ctx, tx, op.PrivacySubjectErasure); err != nil {
		return err
	}
	return s.completePrivacySubjectErasurePreparationTx(ctx, tx, op)
}

func (s *Store) completePrivacySubjectErasurePreparationTx(
	ctx context.Context,
	tx pgx.Tx,
	op PrivacySubjectErasureOperation,
) error {
	// Missing is valid during cold replay and DR: the preparation is independent
	// crash state, not an event-sourced read model. If it is present, delete only
	// the exact operation/binding/event/subject tuple after every erasure write in
	// this same transaction has succeeded.
	_, err := tx.Exec(ctx, `DELETE FROM privacy_subject_erasure_preparations
		WHERE tenant_id = $1 AND operation_id = $2 AND request_binding = $3
		  AND event_id = $4 AND subject_ref = $5`,
		op.TenantID, op.OperationID, op.RequestBinding, op.EventID, op.SubjectRef)
	return err
}

// GetPrivacySubjectErasureOperationByEventID resolves the raw-key-derived event
// anchor under RLS. It remains available after the live event or generic
// idempotency response cache has been retained away.
func (s *Store) GetPrivacySubjectErasureOperationByEventID(
	ctx context.Context,
	tenantID, eventID string,
) (PrivacySubjectErasureOperation, error) {
	if tenantID == "" || eventID == "" {
		return PrivacySubjectErasureOperation{}, errors.New("store: privacy erasure operation lookup requires tenant and event id")
	}
	var op PrivacySubjectErasureOperation
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		op, err = scanPrivacySubjectErasureOperation(tx.QueryRow(ctx,
			`SELECT tenant_id::text, operation_id, request_binding, event_id, event_sequence,
			        subject_ref, requested_by_ref, reason, selectors, counts, erased_at
			   FROM privacy_subject_erasure_operations
			  WHERE tenant_id = $1 AND event_id = $2`,
			tenantID, eventID))
		return err
	})
	return op, err
}

// ApplyPrivacyRetentionEnforcedTx projects a privacy.retention.enforced event. It
// pseudonymizes terminal/stale operational PII while preserving row identifiers
// and security evidence needed for audit, incident, and lifecycle reconstruction.
func (s *Store) ApplyPrivacyRetentionEnforcedTx(ctx context.Context, tx pgx.Tx, r PrivacyRetentionRun) error {
	if r.EnforcedAt.IsZero() {
		r.EnforcedAt = time.Now().UTC()
	}
	if r.Counts == nil {
		r.Counts = map[string]int{}
	}
	cutoffs, err := json.Marshal(r.Cutoffs)
	if err != nil {
		return err
	}
	counts, err := json.Marshal(r.Counts)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO privacy_retention_runs
		        (tenant_id, run_id, requested_by_ref, cutoffs, counts, enforced_at)
		 VALUES ($1, $2, $3, $4::jsonb, $5::jsonb, $6)
		 ON CONFLICT (tenant_id, run_id) DO UPDATE
		    SET requested_by_ref = EXCLUDED.requested_by_ref,
		        cutoffs = EXCLUDED.cutoffs,
		        counts = EXCLUDED.counts,
		        enforced_at = EXCLUDED.enforced_at`,
		r.TenantID, r.RunID, r.RequestedByRef, cutoffs, counts, r.EnforcedAt); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE owners
		    SET name = 'retained:' || left(id::text, 12),
		        email = '', application_id = '', service = '', business_unit = '',
		        escalation_chain = '[]'::jsonb, ownership_verified_by = ''
		  WHERE tenant_id = $1
		    AND created_at < $2
		    AND (email <> '' OR name NOT LIKE 'retained:%'
		      OR coalesce(application_id, '') <> '' OR coalesce(service, '') <> ''
		      OR coalesce(business_unit, '') <> '' OR jsonb_array_length(escalation_chain) > 0
		      OR coalesce(ownership_verified_by, '') <> '')
		    AND NOT EXISTS (
		          SELECT 1 FROM identities
		           WHERE tenant_id = $1 AND owner_id = owners.id
		        )`,
		r.TenantID, r.Cutoffs.OwnerInactiveBefore); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE identities
		    SET name = 'retained:' || left(id::text, 12),
		        attributes = '{}'::jsonb
		  WHERE tenant_id = $1
		    AND (name NOT LIKE 'retained:%' OR attributes <> '{}'::jsonb)
		    AND (
		          (status IN ('revoked', 'retired') AND created_at < $2)
		       OR (not_after IS NOT NULL AND not_after < $2)
		    )`,
		r.TenantID, r.Cutoffs.IdentityTerminalBefore); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE certificates
		    SET subject = 'retained:' || left(fingerprint, 12),
		        sans = '{}'::text[],
		        deployment_location = '',
		        source = '', broker_issuance = NULL
		  WHERE tenant_id = $1
		    AND (subject NOT LIKE 'retained:%' OR cardinality(sans) > 0 OR deployment_location <> '' OR source <> '' OR broker_issuance IS NOT NULL)
		    AND (
		          (status IN ('revoked', 'superseded')
		           AND COALESCE(revoked_at, renewed_at, not_after, created_at) < $2)
		       OR (not_after IS NOT NULL AND not_after < $2)
		    )`,
		r.TenantID, r.Cutoffs.CertificateTerminalBefore); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE ssh_keys
		    SET comment = '',
		        location = ''
		  WHERE tenant_id = $1
		    AND orphaned = true
		    AND created_at < $2
		    AND (comment <> '' OR location <> '')`,
		r.TenantID, r.Cutoffs.SSHStaleBefore); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE attestations
		    SET evidence = '{}'::jsonb
		  WHERE tenant_id = $1
		    AND created_at < $2
		    AND evidence <> '{}'::jsonb`,
		r.TenantID, r.Cutoffs.AttestationEvidenceBefore); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE issuance_approval_requests
		    SET requester = 'retained:' || left(md5($1::text || ':' || requester), 12)
		  WHERE tenant_id = $1
		    AND created_at < $2
		    AND requester <> ''
		    AND requester NOT LIKE 'retained:%'`,
		r.TenantID, r.Cutoffs.ApprovalActorBefore); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE issuance_approvals
		    SET approver = 'retained:' || left(md5($1::text || ':' || approver), 12)
		  WHERE tenant_id = $1
		    AND approved_at < $2
		    AND approver <> ''
		    AND approver NOT LIKE 'retained:%'`,
		r.TenantID, r.Cutoffs.ApprovalActorBefore); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE operation_approval_requests AS r
		    SET requester = CASE
		          WHEN requester LIKE 'retained:%' OR requester LIKE 'erased:%' THEN requester
		          ELSE 'retained:' || left(md5($1::text || ':' || requester), 12)
		        END,
		        reason = '',
		        evidence_refs = '[]'::jsonb
		  WHERE r.tenant_id = $1
		    AND (
		          (status IN ('denied', 'expired', 'superseded', 'consumed') AND updated_at < $2)
		       OR (status IN ('pending', 'approved') AND expires_at < $2)
		    )
		    AND (
		          (requester NOT LIKE 'retained:%' AND requester NOT LIKE 'erased:%')
		       OR reason <> ''
		       OR evidence_refs <> '[]'::jsonb
		    )
		    AND NOT EXISTS (
		          SELECT 1 FROM approved_target_event_fences f
		           WHERE f.tenant_id = r.tenant_id AND f.approval_request_id = r.id
		    )`,
		r.TenantID, r.Cutoffs.ApprovalActorBefore); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE operation_approval_decisions
		    SET approver = CASE
		          WHEN approver LIKE 'retained:%' OR approver LIKE 'erased:%' THEN approver
		          ELSE 'retained:' || left(md5($1::text || ':' || approver), 12)
		        END,
		        reason = ''
		  WHERE tenant_id = $1
		    AND decided_at < $2
		    AND (
		          (approver NOT LIKE 'retained:%' AND approver NOT LIKE 'erased:%')
		       OR reason <> ''
		    )`,
		r.TenantID, r.Cutoffs.ApprovalActorBefore); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE certificate_profiles
		    SET created_by = 'retained:' || left(id::text, 12)
		  WHERE tenant_id = $1
		    AND created_at < $2
		    AND created_by <> ''
		    AND created_by NOT LIKE 'retained:%'`,
		r.TenantID, r.Cutoffs.ProfileActorBefore); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE api_tokens
		    SET subject = 'erased:' || left(subject_ref, 12)
		  WHERE tenant_id = $1
		    AND subject_ref <> ''
		    AND subject NOT LIKE 'erased:%'
		    AND (
		          (revoked_at IS NOT NULL AND revoked_at < $2)
		       OR (expires_at IS NOT NULL AND expires_at < $2)
		    )`,
		r.TenantID, r.Cutoffs.AccessTerminalBefore); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE tenant_members
		    SET subject = 'erased:' || left(subject_ref, 12),
		        display_name = '',
		        email = ''
		  WHERE tenant_id = $1
		    AND subject_ref <> ''
		    AND status = 'offboarded'
		    AND offboarded_at IS NOT NULL
		    AND offboarded_at < $2
		    AND (subject NOT LIKE 'erased:%' OR display_name <> '' OR email <> '')`,
		r.TenantID, r.Cutoffs.AccessTerminalBefore); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE agents
			    SET name = CASE
			          WHEN name LIKE 'retained:%' THEN name
			          ELSE 'retained:' || left(id::text, 12)
			        END,
			        offboarded_by = CASE
			          WHEN offboarded_by IS NULL OR offboarded_by = '' OR offboarded_by LIKE 'retained:%' THEN offboarded_by
			          ELSE 'retained:' || left(md5($1::text || ':' || offboarded_by), 12)
			        END,
			        offboard_reason = CASE WHEN offboard_reason IS NULL THEN NULL ELSE '' END
			  WHERE tenant_id = $1
			    AND (
			          name NOT LIKE 'retained:%'
			       OR (COALESCE(offboarded_by, '') <> '' AND offboarded_by NOT LIKE 'retained:%')
			       OR COALESCE(offboard_reason, '') <> ''
			    )
		    AND (
		          (last_seen_at IS NOT NULL AND last_seen_at < $2)
		       OR (last_seen_at IS NULL AND created_at < $2)
		       OR (offboarded_at IS NOT NULL AND offboarded_at < $2)
		    )`,
		r.TenantID, r.Cutoffs.AgentStaleBefore); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE ownership_readiness_exceptions
		    SET reason = '', revocation_reason = '',
		        granted_by = CASE
		          WHEN granted_by LIKE 'retained:%' OR granted_by LIKE 'erased:%' THEN granted_by
		          ELSE 'retained:' || left(md5($1::text || ':' || granted_by), 12)
		        END,
		        revoked_by = CASE
		          WHEN revoked_by IS NULL OR revoked_by = '' OR revoked_by LIKE 'retained:%' OR revoked_by LIKE 'erased:%' THEN revoked_by
		          ELSE 'retained:' || left(md5($1::text || ':' || revoked_by), 12)
		        END
		  WHERE tenant_id = $1 AND expires_at < $2
		    AND (reason <> '' OR coalesce(revocation_reason, '') <> ''
		      OR (granted_by NOT LIKE 'retained:%' AND granted_by NOT LIKE 'erased:%')
		      OR (coalesce(revoked_by, '') <> '' AND revoked_by NOT LIKE 'retained:%' AND revoked_by NOT LIKE 'erased:%'))`,
		r.TenantID, r.Cutoffs.AttestationEvidenceBefore); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE pam_sessions
			    SET subject = CASE
			          WHEN subject LIKE 'retained:%' OR subject LIKE 'erased:%' THEN subject
			          ELSE 'retained:' || left(md5($1::text || ':' || subject), 12)
			        END,
			        requested_by = CASE
			          WHEN requested_by LIKE 'retained:%' OR requested_by LIKE 'erased:%' THEN requested_by
			          ELSE 'retained:' || left(md5($1::text || ':' || requested_by), 12)
			        END,
				        reason = '',
			        audit = '{}'::jsonb
			  WHERE tenant_id = $1
			    AND COALESCE(ended_at, expires_at) < $2
			    AND (
			          subject NOT LIKE 'retained:%'
			       OR requested_by NOT LIKE 'retained:%'
			       OR reason <> ''
			       OR audit <> '{}'::jsonb
			    )`,
		r.TenantID, r.Cutoffs.AccessTerminalBefore); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE discovery_findings
			    SET triage_actor = CASE
			          WHEN triage_actor = '' OR triage_actor LIKE 'retained:%' OR triage_actor LIKE 'erased:%' THEN triage_actor
			          ELSE 'retained:' || left(md5($1::text || ':' || triage_actor), 12)
			        END,
			        triage_reason = ''
			  WHERE tenant_id = $1
			    AND triaged_at IS NOT NULL
			    AND triaged_at < $2
			    AND ((triage_actor <> '' AND triage_actor NOT LIKE 'retained:%' AND triage_actor NOT LIKE 'erased:%') OR triage_reason <> '')`,
		r.TenantID, r.Cutoffs.AttestationEvidenceBefore); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE notification_threshold_deliveries
			    SET subject = CASE
			          WHEN subject LIKE 'retained:%' OR subject LIKE 'erased:%' THEN subject
			          ELSE 'retained:' || left(md5($1::text || ':' || subject), 12)
			        END,
			        channel = CASE
			          WHEN channel IN ('email', 'slack', 'teams', 'sms', 'webhook', 'pagerduty', 'opsgenie', 'siem') THEN channel
			          WHEN channel LIKE 'retained:%' OR channel LIKE 'erased:%' THEN channel
			          ELSE 'retained:' || left(md5($1::text || ':' || channel), 12)
			        END
			  WHERE tenant_id = $1
			    AND last_sent_at < $2
			    AND (
			          subject NOT LIKE 'retained:%'
			       OR (
			            channel NOT IN ('email', 'slack', 'teams', 'sms', 'webhook', 'pagerduty', 'opsgenie', 'siem')
			        AND channel NOT LIKE 'retained:%'
			          )
			    )`,
		r.TenantID, r.Cutoffs.AttestationEvidenceBefore); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE incident_executions
			    SET created_by = CASE
			          WHEN created_by = '' OR created_by LIKE 'retained:%' OR created_by LIKE 'erased:%' THEN created_by
			          ELSE 'retained:' || left(md5($1::text || ':' || created_by), 12)
			        END,
			        reason = '',
			        evidence_bundle = '',
			        failed_targets = '{}'::text[],
			        rollback_refs = '{}'::text[]
			  WHERE tenant_id = $1
			    AND updated_at < $2
			    AND ((created_by <> '' AND created_by NOT LIKE 'retained:%' AND created_by NOT LIKE 'erased:%')
			      OR reason <> '' OR evidence_bundle <> '' OR cardinality(failed_targets) > 0 OR cardinality(rollback_refs) > 0)`,
		r.TenantID, r.Cutoffs.AttestationEvidenceBefore); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE nhi_access_review_campaigns
			    SET reviewer_subject = CASE
			          WHEN reviewer_subject LIKE 'retained:%' OR reviewer_subject LIKE 'erased:%' THEN reviewer_subject
			          ELSE 'retained:' || left(md5($1::text || ':' || reviewer_subject), 12)
			        END,
			        requested_by = CASE
			          WHEN requested_by LIKE 'retained:%' OR requested_by LIKE 'erased:%' THEN requested_by
			          ELSE 'retained:' || left(md5($1::text || ':' || requested_by), 12)
			        END
			  WHERE tenant_id = $1
			    AND status = 'completed'
			    AND COALESCE(completed_at, updated_at, created_at) < $2
			    AND (reviewer_subject NOT LIKE 'retained:%' OR requested_by NOT LIKE 'retained:%')`,
		r.TenantID, r.Cutoffs.ApprovalActorBefore); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE nhi_access_review_items
			    SET decision_by = CASE
			          WHEN decision_by = '' OR decision_by LIKE 'retained:%' OR decision_by LIKE 'erased:%' THEN decision_by
			          ELSE 'retained:' || left(md5($1::text || ':' || decision_by), 12)
			        END,
			        decision_reason = '',
			        decision_evidence_refs = '{}'::text[]
			  WHERE tenant_id = $1
			    AND status <> 'pending'
			    AND COALESCE(decided_at, updated_at, created_at) < $2
			    AND ((decision_by <> '' AND decision_by NOT LIKE 'retained:%' AND decision_by NOT LIKE 'erased:%')
			      OR decision_reason <> '' OR cardinality(decision_evidence_refs) > 0)`,
		r.TenantID, r.Cutoffs.ApprovalActorBefore); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE access_change_requests
			    SET requester_subject = CASE
			          WHEN requester_subject LIKE 'retained:%' OR requester_subject LIKE 'erased:%' THEN requester_subject
			          ELSE 'retained:' || left(md5($1::text || ':' || requester_subject), 12)
			        END,
			        reason = 'privacy-redacted',
			        evidence_refs = '{}'::text[]
			  WHERE tenant_id = $1
			    AND status <> 'pending'
			    AND COALESCE(completed_at, updated_at, created_at) < $2
			    AND (requester_subject NOT LIKE 'retained:%' OR reason <> 'privacy-redacted' OR cardinality(evidence_refs) > 0)`,
		r.TenantID, r.Cutoffs.ApprovalActorBefore); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE access_change_request_decisions
			    SET approver_subject = CASE
			          WHEN approver_subject LIKE 'retained:%' OR approver_subject LIKE 'erased:%' THEN approver_subject
			          ELSE 'retained:' || left(md5($1::text || ':' || approver_subject), 12)
			        END,
				        reason = '',
			        decision_evidence_refs = '{}'::text[]
			  WHERE tenant_id = $1
			    AND decided_at < $2
			    AND (approver_subject NOT LIKE 'retained:%' OR reason <> '' OR cardinality(decision_evidence_refs) > 0)`,
		r.TenantID, r.Cutoffs.ApprovalActorBefore); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE discovery_runs
			    SET requested_by = CASE
			          WHEN requested_by = '' OR requested_by LIKE 'retained:%' OR requested_by LIKE 'erased:%' THEN requested_by
			          ELSE 'retained:' || left(md5($1::text || ':' || requested_by), 12)
			        END
			  WHERE tenant_id = $1
			    AND (completed_at IS NOT NULL OR status IN ('succeeded', 'partial', 'failed', 'completed'))
			    AND COALESCE(completed_at, started_at, created_at) < $2
			    AND requested_by <> ''
			    AND requested_by NOT LIKE 'retained:%'`,
		r.TenantID, r.Cutoffs.AttestationEvidenceBefore); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE notification_routing_policies
			    SET scope_ref = CASE
			          WHEN scope_kind <> 'owner' OR scope_ref = '' OR scope_ref LIKE 'owner/retained:%' OR scope_ref LIKE 'owner/erased:%' THEN scope_ref
			          ELSE 'owner/retained:' || left(md5($1::text || ':' || scope_ref), 12)
			        END,
			        owner_ref = CASE
			          WHEN owner_ref = '' OR owner_ref LIKE 'retained:%' OR owner_ref LIKE 'erased:%' THEN owner_ref
			          ELSE 'retained:' || left(md5($1::text || ':' || owner_ref), 12)
			        END,
			        owner_email = ''
			  WHERE tenant_id = $1
			    AND updated_at < $2
			    AND ((scope_kind = 'owner' AND scope_ref <> ''
			          AND scope_ref NOT LIKE 'owner/retained:%' AND scope_ref NOT LIKE 'owner/erased:%')
			      OR (owner_ref <> '' AND owner_ref NOT LIKE 'retained:%' AND owner_ref NOT LIKE 'erased:%')
			      OR owner_email <> '')`,
		r.TenantID, r.Cutoffs.AttestationEvidenceBefore); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE remediation_playbook_runs
			    SET created_by = CASE
			          WHEN created_by = '' OR created_by LIKE 'retained:%' OR created_by LIKE 'erased:%' THEN created_by
			          ELSE 'retained:' || left(md5($1::text || ':' || created_by), 12)
			        END,
			        reason = '',
			        evidence_refs = '{}'::text[],
			        rollback_refs = '{}'::text[],
			        initial_http_status = 0,
			        initial_response = ''::bytea
			  WHERE tenant_id = $1
			    AND updated_at < $2
			    AND ((created_by <> '' AND created_by NOT LIKE 'retained:%' AND created_by NOT LIKE 'erased:%')
			      OR reason <> '' OR cardinality(evidence_refs) > 0 OR cardinality(rollback_refs) > 0)`,
		r.TenantID, r.Cutoffs.AttestationEvidenceBefore); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE compliance_report_schedules
			    SET recipient_ref = CASE
			          WHEN recipient_ref = '' OR recipient_ref LIKE 'retained:%' OR recipient_ref LIKE 'erased:%' THEN recipient_ref
			          ELSE 'retained:' || left(md5($1::text || ':' || recipient_ref), 12)
			        END
			  WHERE tenant_id = $1
			    AND updated_at < $2
			    AND recipient_ref <> ''
			    AND recipient_ref NOT LIKE 'retained:%'`,
		r.TenantID, r.Cutoffs.AttestationEvidenceBefore); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE incident_fleet_reissuance_runs
			    SET created_by = CASE
			          WHEN created_by = '' OR created_by LIKE 'retained:%' OR created_by LIKE 'erased:%' THEN created_by
			          ELSE 'retained:' || left(md5($1::text || ':' || created_by), 12)
			        END,
			        reason = '',
			        evidence_bundle = '',
			        failed_targets = '{}'::text[],
			        rollback_refs = '{}'::text[]
			  WHERE tenant_id = $1
			    AND updated_at < $2
			    AND ((created_by <> '' AND created_by NOT LIKE 'retained:%' AND created_by NOT LIKE 'erased:%')
			      OR reason <> '' OR evidence_bundle <> '' OR cardinality(failed_targets) > 0 OR cardinality(rollback_refs) > 0)`,
		r.TenantID, r.Cutoffs.AttestationEvidenceBefore); err != nil {
		return err
	}
	if err := retainDiscoverySourcePrivacyRows(ctx, tx, r.TenantID, r.Cutoffs.AttestationEvidenceBefore); err != nil {
		return err
	}
	if err := retainDiscoveryFindingMetadataPrivacyRows(ctx, tx, r.TenantID, r.Cutoffs.AttestationEvidenceBefore); err != nil {
		return err
	}
	return nil
}

// ApplyPrivacyArchiveErasureAttestedTx projects a privacy.archive_erasure.attested
// event. The event is the source of truth; this method only records queryable
// evidence for the tenant privacy surface.
func (s *Store) ApplyPrivacyArchiveErasureAttestedTx(ctx context.Context, tx pgx.Tx, a PrivacyArchiveErasureAttestation) error {
	if a.AttestedAt.IsZero() {
		a.AttestedAt = time.Now().UTC()
	}
	refs := a.EvidenceRefs
	if refs == nil {
		refs = []string{}
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO privacy_archive_erasure_attestations
		        (tenant_id, attestation_id, subject_ref, requested_by_ref, artifact_type,
		         artifact_uri, action, reason, evidence_refs, held_until, attested_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		 ON CONFLICT (tenant_id, attestation_id) DO UPDATE
		    SET subject_ref = EXCLUDED.subject_ref,
		        requested_by_ref = EXCLUDED.requested_by_ref,
		        artifact_type = EXCLUDED.artifact_type,
		        artifact_uri = EXCLUDED.artifact_uri,
		        action = EXCLUDED.action,
		        reason = EXCLUDED.reason,
		        evidence_refs = EXCLUDED.evidence_refs,
		        held_until = EXCLUDED.held_until,
		        attested_at = EXCLUDED.attested_at`,
		a.TenantID, a.AttestationID, a.SubjectRef, a.RequestedByRef, a.ArtifactType,
		a.ArtifactURI, a.Action, a.Reason, refs, a.HeldUntil, a.AttestedAt)
	return err
}

// ListPrivacySubjectErasuresPage returns erasure evidence in newest-first order.
func (s *Store) ListPrivacySubjectErasuresPage(ctx context.Context, tenantID, afterRef string, limit int) ([]PrivacySubjectErasure, error) {
	var out []PrivacySubjectErasure
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT tenant_id::text, subject_ref, requested_by_ref, reason, selectors, counts, erased_at
			   FROM privacy_subject_erasures
			  WHERE tenant_id = $1 AND ($2 = '' OR subject_ref > $2)
			  ORDER BY subject_ref LIMIT $3`,
			tenantID, afterRef, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanPrivacySubjectErasure(rows)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

// ListPrivacyRetentionRunsPage returns projected retention evidence.
func (s *Store) ListPrivacyRetentionRunsPage(ctx context.Context, tenantID, afterRunID string, limit int) ([]PrivacyRetentionRun, error) {
	var out []PrivacyRetentionRun
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT tenant_id::text, run_id::text, requested_by_ref, cutoffs, counts, enforced_at
			   FROM privacy_retention_runs
			  WHERE tenant_id = $1 AND ($2 = '' OR run_id::text > $2)
			  ORDER BY run_id LIMIT $3`,
			tenantID, afterRunID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanPrivacyRetentionRun(rows)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

// ListPrivacyArchiveErasureAttestationsPage returns projected archive/backup
// erasure evidence. subjectRef is optional and already non-PII.
func (s *Store) ListPrivacyArchiveErasureAttestationsPage(ctx context.Context, tenantID, subjectRef, afterID string, limit int) ([]PrivacyArchiveErasureAttestation, error) {
	var out []PrivacyArchiveErasureAttestation
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT tenant_id::text, attestation_id::text, subject_ref, requested_by_ref,
			        artifact_type, artifact_uri, action, reason, evidence_refs,
			        held_until, attested_at
			   FROM privacy_archive_erasure_attestations
			  WHERE tenant_id = $1
			    AND ($2 = '' OR subject_ref = $2)
			    AND ($3 = '' OR attestation_id::text > $3)
			  ORDER BY attestation_id LIMIT $4`,
			tenantID, subjectRef, afterID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanPrivacyArchiveErasureAttestation(rows)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

// ListPrivacyErasureRefs returns the tenant's erased subject refs for audit
// redaction. The values are non-PII hashes and the query is tenant-scoped.
func (s *Store) ListPrivacyErasureRefs(ctx context.Context, tenantID string) (map[string]struct{}, error) {
	refs := map[string]struct{}{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT subject_ref FROM privacy_subject_erasures WHERE tenant_id = $1`,
			tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var ref string
			if err := rows.Scan(&ref); err != nil {
				return err
			}
			refs[ref] = struct{}{}
		}
		return rows.Err()
	})
	return refs, err
}

func scanPrivacySubjectErasure(row pgx.Row) (PrivacySubjectErasure, error) {
	var (
		r             PrivacySubjectErasure
		selectorsJSON []byte
		countsJSON    []byte
	)
	if err := row.Scan(&r.TenantID, &r.SubjectRef, &r.RequestedByRef, &r.Reason, &selectorsJSON, &countsJSON, &r.ErasedAt); err != nil {
		return PrivacySubjectErasure{}, err
	}
	r.ErasedAt = r.ErasedAt.UTC()
	if len(selectorsJSON) > 0 {
		if err := json.Unmarshal(selectorsJSON, &r.Selectors); err != nil {
			return PrivacySubjectErasure{}, err
		}
	}
	if len(countsJSON) > 0 {
		if err := json.Unmarshal(countsJSON, &r.Counts); err != nil {
			return PrivacySubjectErasure{}, err
		}
	}
	return r, nil
}

func scanPrivacySubjectErasureOperation(row pgx.Row) (PrivacySubjectErasureOperation, error) {
	var (
		op            PrivacySubjectErasureOperation
		eventSequence int64
		selectorsJSON []byte
		countsJSON    []byte
	)
	if err := row.Scan(
		&op.TenantID, &op.OperationID, &op.RequestBinding, &op.EventID, &eventSequence,
		&op.SubjectRef, &op.RequestedByRef, &op.Reason, &selectorsJSON, &countsJSON,
		&op.ErasedAt,
	); err != nil {
		return PrivacySubjectErasureOperation{}, err
	}
	if eventSequence <= 0 {
		return PrivacySubjectErasureOperation{}, errors.New("store: privacy erasure operation has invalid event sequence")
	}
	op.EventSequence = uint64(eventSequence)
	op.ErasedAt = op.ErasedAt.UTC()
	if err := json.Unmarshal(selectorsJSON, &op.Selectors); err != nil {
		return PrivacySubjectErasureOperation{}, err
	}
	if err := json.Unmarshal(countsJSON, &op.Counts); err != nil {
		return PrivacySubjectErasureOperation{}, err
	}
	return op, nil
}

func privacySubjectErasureOperationsEqual(
	a, b PrivacySubjectErasureOperation,
) (bool, error) {
	aSelectors, err := json.Marshal(a.Selectors)
	if err != nil {
		return false, err
	}
	bSelectors, err := json.Marshal(b.Selectors)
	if err != nil {
		return false, err
	}
	aCounts, err := json.Marshal(a.Counts)
	if err != nil {
		return false, err
	}
	bCounts := b.Counts
	if bCounts == nil {
		bCounts = countsForPrivacySelectors(b.Selectors)
	}
	bCountsJSON, err := json.Marshal(bCounts)
	if err != nil {
		return false, err
	}
	return a.TenantID == b.TenantID &&
		a.OperationID == b.OperationID &&
		a.RequestBinding == b.RequestBinding &&
		a.EventID == b.EventID &&
		a.EventSequence == b.EventSequence &&
		a.SubjectRef == b.SubjectRef &&
		a.RequestedByRef == b.RequestedByRef &&
		a.Reason == b.Reason &&
		a.ErasedAt.Equal(b.ErasedAt) &&
		bytes.Equal(aSelectors, bSelectors) &&
		bytes.Equal(aCounts, bCountsJSON), nil
}

func scanPrivacyRetentionRun(row pgx.Row) (PrivacyRetentionRun, error) {
	var (
		r           PrivacyRetentionRun
		cutoffsJSON []byte
		countsJSON  []byte
	)
	if err := row.Scan(&r.TenantID, &r.RunID, &r.RequestedByRef, &cutoffsJSON, &countsJSON, &r.EnforcedAt); err != nil {
		return PrivacyRetentionRun{}, err
	}
	if len(cutoffsJSON) > 0 {
		if err := json.Unmarshal(cutoffsJSON, &r.Cutoffs); err != nil {
			return PrivacyRetentionRun{}, err
		}
	}
	if len(countsJSON) > 0 {
		if err := json.Unmarshal(countsJSON, &r.Counts); err != nil {
			return PrivacyRetentionRun{}, err
		}
	}
	return r, nil
}

func scanPrivacyArchiveErasureAttestation(row pgx.Row) (PrivacyArchiveErasureAttestation, error) {
	var r PrivacyArchiveErasureAttestation
	if err := row.Scan(&r.TenantID, &r.AttestationID, &r.SubjectRef, &r.RequestedByRef,
		&r.ArtifactType, &r.ArtifactURI, &r.Action, &r.Reason, &r.EvidenceRefs,
		&r.HeldUntil, &r.AttestedAt); err != nil {
		return PrivacyArchiveErasureAttestation{}, err
	}
	if r.EvidenceRefs == nil {
		r.EvidenceRefs = []string{}
	}
	return r, nil
}

type privacyReadModelQuery struct {
	table string
	sql   string
	args  []any
}

func discoveryPrivacyJSONStringMatch(column, valueArg string) string {
	return fmt.Sprintf(`EXISTS (
				            SELECT 1 FROM jsonb_path_query(%s, '$.**') AS v(value)
				             WHERE jsonb_typeof(v.value) = 'string' AND v.value #>> '{}' = %s
				          )`, column, valueArg)
}

func discoveryPrivacyJSONHasRetainablePII(column string) string {
	scalarKeys := []string{"principal", "owner", "display_name", "ip", "user_agent", "source_event_ref"}
	arrayKeys := []string{"evidence_refs"}
	conditions := make([]string, 0, len(scalarKeys)+len(arrayKeys))
	for _, key := range scalarKeys {
		conditions = append(conditions, fmt.Sprintf(`(node.value ? '%[1]s' AND COALESCE(node.value->>'%[1]s', '') <> '' AND node.value->>'%[1]s' NOT LIKE 'erased:%%' AND node.value->>'%[1]s' NOT LIKE 'retained:%%')`, key))
	}
	for _, key := range arrayKeys {
		conditions = append(conditions, fmt.Sprintf(`(node.value ? '%[1]s' AND jsonb_typeof(node.value->'%[1]s') = 'array' AND jsonb_array_length(node.value->'%[1]s') > 0)`, key))
	}
	return fmt.Sprintf(`EXISTS (
				            SELECT 1 FROM jsonb_path_query(%s, '$.**') AS node(value)
				             WHERE jsonb_typeof(node.value) = 'object'
				               AND (%s)
				          )`, column, strings.Join(conditions, " OR "))
}

func privacyReadModelExportQueries(tenantID, subject string) []privacyReadModelQuery {
	return []privacyReadModelQuery{
		{
			table: "operation_approval_requests",
			sql: `SELECT id::text, ''::text,
			             jsonb_build_object('intent_digest', intent_digest, 'resource_kind', resource_kind, 'resource_id', resource_id, 'resource_name', resource_name, 'action', action, 'requester', requester, 'from_state', from_state, 'to_state', to_state, 'target_version', target_version, 'reason', reason, 'evidence_refs', evidence_refs, 'required_approvals', required_approvals, 'status', status, 'created_at', created_at, 'expires_at', expires_at, 'updated_at', updated_at, 'consumed_at', consumed_at, 'consumed_event_id', consumed_event_id)::text,
			             created_at
			        FROM operation_approval_requests
			       WHERE tenant_id = $1
			         AND (requester = $2 OR position($2 in reason) > 0 OR position($2 in evidence_refs::text) > 0)
			       ORDER BY id`,
			args: []any{tenantID, subject},
		},
		{
			table: "operation_approval_decisions",
			sql: `SELECT event_id::text, request_id::text,
			             jsonb_build_object('intent_digest', intent_digest, 'approver', approver, 'decision', decision, 'reason', reason, 'event_id', event_id, 'decided_at', decided_at)::text,
			             decided_at
			        FROM operation_approval_decisions
			       WHERE tenant_id = $1
			         AND (approver = $2 OR position($2 in reason) > 0)
			       ORDER BY request_id, event_id`,
			args: []any{tenantID, subject},
		},
		{
			table: "pam_sessions",
			sql: `SELECT id::text, ''::text,
			             jsonb_build_object('target_type', target_type, 'target_id', target_id, 'role', role, 'status', status, 'subject', subject, 'requested_by', requested_by, 'reason', reason, 'audit', audit, 'started_at', started_at, 'expires_at', expires_at, 'ended_at', ended_at)::text,
			             started_at
			        FROM pam_sessions
			       WHERE tenant_id = $1
			         AND (subject = $2 OR requested_by = $2 OR position($2 in reason) > 0 OR position($2 in audit::text) > 0)
			       ORDER BY id`,
			args: []any{tenantID, subject},
		},
		{
			table: "discovery_sources",
			sql: `SELECT id::text, ''::text,
				             jsonb_build_object('kind', kind, 'name', name, 'config', config, 'created_at', created_at, 'updated_at', updated_at)::text,
				             created_at
				        FROM discovery_sources
				       WHERE tenant_id = $1
				         AND ` + discoveryPrivacyJSONStringMatch("config", "$2") + `
				       ORDER BY id`,
			args: []any{tenantID, subject},
		},
		{
			table: "discovery_findings",
			sql: `SELECT id::text, run_id::text,
				             jsonb_build_object('kind', kind, 'ref', ref, 'metadata', metadata, 'triage_status', triage_status, 'triage_actor', triage_actor, 'triage_reason', triage_reason, 'triaged_at', triaged_at)::text,
				             discovered_at
				        FROM discovery_findings
				       WHERE tenant_id = $1
				         AND (triage_actor = $2 OR position($2 in triage_reason) > 0 OR ` + discoveryPrivacyJSONStringMatch("metadata", "$2") + `)
				       ORDER BY id`,
			args: []any{tenantID, subject},
		},
		{
			table: "notification_threshold_deliveries",
			sql: `SELECT threshold_days::text || ':' || left(md5(subject || ':' || channel), 12), ''::text,
			             jsonb_build_object('subject', subject, 'threshold_days', threshold_days, 'channel', channel, 'first_sent_at', first_sent_at, 'last_sent_at', last_sent_at)::text,
			             first_sent_at
			        FROM notification_threshold_deliveries
			       WHERE tenant_id = $1
			         AND (subject = $2 OR position($2 in channel) > 0)
			       ORDER BY threshold_days, channel`,
			args: []any{tenantID, subject},
		},
		{
			table: "incident_executions",
			sql: `SELECT id::text, ''::text,
			             jsonb_build_object('status', status, 'phase', phase, 'reason', reason, 'created_by', created_by, 'failed_targets', failed_targets, 'rollback_refs', rollback_refs, 'evidence_bundle_format', evidence_bundle_format, 'evidence_bundle', evidence_bundle)::text,
			             created_at
			        FROM incident_executions
			       WHERE tenant_id = $1
			         AND (created_by = $2 OR position($2 in reason) > 0 OR position($2 in evidence_bundle) > 0 OR $2 = ANY(failed_targets) OR $2 = ANY(rollback_refs))
			       ORDER BY id`,
			args: []any{tenantID, subject},
		},
		{
			table: "nhi_access_review_campaigns",
			sql: `SELECT id::text, ''::text,
			             jsonb_build_object('name', name, 'scope', scope, 'reviewer_subject', reviewer_subject, 'requested_by', requested_by, 'status', status, 'completed_at', completed_at)::text,
			             created_at
			        FROM nhi_access_review_campaigns
			       WHERE tenant_id = $1
			         AND (reviewer_subject = $2 OR requested_by = $2)
			       ORDER BY id`,
			args: []any{tenantID, subject},
		},
		{
			table: "nhi_access_review_items",
			sql: `SELECT item_id::text, campaign_id::text,
			             jsonb_build_object('nhi_id', nhi_id, 'nhi_kind', nhi_kind, 'display_name', display_name, 'resource', resource, 'entitlement', entitlement, 'status', status, 'decision_by', decision_by, 'decision_reason', decision_reason, 'decision_evidence_refs', decision_evidence_refs)::text,
			             created_at
			        FROM nhi_access_review_items
			       WHERE tenant_id = $1
			         AND (decision_by = $2 OR position($2 in decision_reason) > 0 OR $2 = ANY(decision_evidence_refs))
			       ORDER BY campaign_id, item_id`,
			args: []any{tenantID, subject},
		},
		{
			table: "access_change_requests",
			sql: `SELECT id::text, ''::text,
			             jsonb_build_object('requested_action', requested_action, 'requester_subject', requester_subject, 'nhi_id', nhi_id, 'nhi_kind', nhi_kind, 'display_name', display_name, 'resource', resource, 'entitlement', entitlement, 'change_ref', change_ref, 'reason', reason, 'evidence_refs', evidence_refs, 'status', status)::text,
			             created_at
			        FROM access_change_requests
			       WHERE tenant_id = $1
			         AND (requester_subject = $2 OR position($2 in reason) > 0 OR $2 = ANY(evidence_refs))
			       ORDER BY id`,
			args: []any{tenantID, subject},
		},
		{
			table: "access_change_request_decisions",
			sql: `SELECT request_id::text || ':' || left(md5(approver_subject), 12), request_id::text,
			             jsonb_build_object('approver_subject', approver_subject, 'decision', decision, 'reason', reason, 'decision_evidence_refs', decision_evidence_refs, 'decided_at', decided_at)::text,
			             decided_at
			        FROM access_change_request_decisions
			       WHERE tenant_id = $1
			         AND (approver_subject = $2 OR position($2 in reason) > 0 OR $2 = ANY(decision_evidence_refs))
			       ORDER BY request_id, approver_subject`,
			args: []any{tenantID, subject},
		},
		{
			table: "discovery_runs",
			sql: `SELECT id::text, source_id::text,
			             jsonb_build_object('status', status, 'dry_run', dry_run, 'requested_by', requested_by, 'targets', targets, 'discovered', discovered, 'failed', failed, 'rejected', rejected, 'error', error, 'started_at', started_at, 'completed_at', completed_at)::text,
			             created_at
			        FROM discovery_runs
			       WHERE tenant_id = $1 AND requested_by = $2
			       ORDER BY id`,
			args: []any{tenantID, subject},
		},
		{
			table: "notification_routing_policies",
			sql: `SELECT id::text, ''::text,
			             jsonb_build_object('name', name, 'scope_kind', scope_kind, 'scope_ref', scope_ref, 'owner_ref', owner_ref, 'owner_email', owner_email, 'digest_interval_seconds', digest_interval_seconds, 'digest_timezone', digest_timezone)::text,
			             created_at
			        FROM notification_routing_policies
			       WHERE tenant_id = $1
			         AND (scope_ref = $2 OR scope_ref = 'owner/' || $2 OR owner_ref = $2 OR owner_email = $2)
			       ORDER BY id`,
			args: []any{tenantID, subject},
		},
		{
			table: "remediation_playbook_runs",
			sql: `SELECT id::text, ''::text,
			             jsonb_build_object('playbook_id', playbook_id, 'status', status, 'phase', phase, 'action', action, 'reason', reason, 'evidence_refs', evidence_refs, 'rollback_refs', rollback_refs, 'created_by', created_by)::text,
			             created_at
			        FROM remediation_playbook_runs
			       WHERE tenant_id = $1
			         AND (created_by = $2 OR position($2 in reason) > 0 OR $2 = ANY(evidence_refs) OR $2 = ANY(rollback_refs))
			       ORDER BY id`,
			args: []any{tenantID, subject},
		},
		{
			table: "compliance_report_schedules",
			sql: `SELECT id::text, ''::text,
			             jsonb_build_object('framework', framework, 'name', name, 'report_type', report_type, 'delivery', delivery, 'recipient_ref', recipient_ref, 'next_run_at', next_run_at)::text,
			             created_at
			        FROM compliance_report_schedules
			       WHERE tenant_id = $1 AND recipient_ref = $2
			       ORDER BY id`,
			args: []any{tenantID, subject},
		},
		{
			table: "incident_fleet_reissuance_runs",
			sql: `SELECT id::text, ''::text,
			             jsonb_build_object('issuer_id', issuer_id, 'status', status, 'phase', phase, 'reason', reason, 'failed_targets', failed_targets, 'rollback_refs', rollback_refs, 'evidence_bundle_format', evidence_bundle_format, 'evidence_bundle', evidence_bundle, 'created_by', created_by)::text,
			             created_at
			        FROM incident_fleet_reissuance_runs
			       WHERE tenant_id = $1
			         AND (created_by = $2 OR position($2 in reason) > 0 OR position($2 in evidence_bundle) > 0 OR $2 = ANY(failed_targets) OR $2 = ANY(rollback_refs))
			       ORDER BY id`,
			args: []any{tenantID, subject},
		},
		{
			table: "ownership_readiness_exceptions",
			sql: `SELECT id::text, identity_id::text,
			             jsonb_build_object('identity_id', identity_id, 'reason', reason,
			               'granted_by', granted_by, 'granted_at', granted_at,
			               'expires_at', expires_at, 'revoked_by', revoked_by,
			               'revoked_at', revoked_at, 'revocation_reason', revocation_reason)::text,
			             granted_at
			        FROM ownership_readiness_exceptions
			       WHERE tenant_id = $1
			         AND (granted_by = $2 OR coalesce(revoked_by, '') = $2
			           OR position($2 in reason) > 0
			           OR position($2 in coalesce(revocation_reason, '')) > 0)
			       ORDER BY id`,
			args: []any{tenantID, subject},
		},
	}
}

func privacyReadModelSelectorQueries(tenantID, subject string) []privacyReadModelQuery {
	return []privacyReadModelQuery{
		{table: "operation_approval_requests", sql: `SELECT id::text, ''::text, 0 FROM operation_approval_requests WHERE tenant_id = $1 AND (requester = $2 OR position($2 in resource_kind) > 0 OR position($2 in resource_id) > 0 OR position($2 in resource_name) > 0 OR position($2 in action) > 0 OR position($2 in from_state) > 0 OR position($2 in to_state) > 0 OR position($2 in reason) > 0 OR position($2 in evidence_refs::text) > 0) ORDER BY id`, args: []any{tenantID, subject}},
		{
			table: "operation_approval_decisions",
			sql: `SELECT d.event_id::text, d.request_id::text, 0
			        FROM operation_approval_decisions d
			        JOIN operation_approval_requests r
			          ON r.tenant_id = d.tenant_id AND r.id = d.request_id
			       WHERE d.tenant_id = $1
			         AND (
			               d.approver = $2 OR position($2 in d.reason) > 0
			            OR r.requester = $2
			            OR position($2 in r.resource_kind) > 0
			            OR position($2 in r.resource_id) > 0
			            OR position($2 in r.resource_name) > 0
			            OR position($2 in r.action) > 0
			            OR position($2 in r.from_state) > 0
			            OR position($2 in r.to_state) > 0
			            OR position($2 in r.reason) > 0
			            OR position($2 in r.evidence_refs::text) > 0
			         )
			       ORDER BY d.request_id, d.event_id`,
			args: []any{tenantID, subject},
		},
		{table: "pam_sessions", sql: `SELECT id::text, ''::text, 0 FROM pam_sessions WHERE tenant_id = $1 AND (subject = $2 OR requested_by = $2 OR position($2 in reason) > 0 OR position($2 in audit::text) > 0) ORDER BY id`, args: []any{tenantID, subject}},
		{table: "discovery_sources", sql: `SELECT id::text, ''::text, 0 FROM discovery_sources WHERE tenant_id = $1 AND ` + discoveryPrivacyJSONStringMatch("config", "$2") + ` ORDER BY id`, args: []any{tenantID, subject}},
		{table: "discovery_findings", sql: `SELECT id::text, ''::text, 0 FROM discovery_findings WHERE tenant_id = $1 AND (triage_actor = $2 OR position($2 in triage_reason) > 0 OR ` + discoveryPrivacyJSONStringMatch("metadata", "$2") + `) ORDER BY id`, args: []any{tenantID, subject}},
		{table: "notification_threshold_deliveries", sql: `SELECT ''::text, ''::text, threshold_days FROM notification_threshold_deliveries WHERE tenant_id = $1 AND (subject = $2 OR channel = $2) GROUP BY threshold_days ORDER BY threshold_days`, args: []any{tenantID, subject}},
		{table: "incident_executions", sql: `SELECT id::text, ''::text, 0 FROM incident_executions WHERE tenant_id = $1 AND (created_by = $2 OR position($2 in reason) > 0 OR position($2 in evidence_bundle) > 0 OR $2 = ANY(failed_targets) OR $2 = ANY(rollback_refs)) ORDER BY id`, args: []any{tenantID, subject}},
		{table: "nhi_access_review_campaigns", sql: `SELECT id::text, ''::text, 0 FROM nhi_access_review_campaigns WHERE tenant_id = $1 AND (reviewer_subject = $2 OR requested_by = $2) ORDER BY id`, args: []any{tenantID, subject}},
		{table: "nhi_access_review_items", sql: `SELECT item_id::text, campaign_id::text, 0 FROM nhi_access_review_items WHERE tenant_id = $1 AND (decision_by = $2 OR position($2 in decision_reason) > 0 OR $2 = ANY(decision_evidence_refs)) ORDER BY campaign_id, item_id`, args: []any{tenantID, subject}},
		{table: "access_change_requests", sql: `SELECT id::text, ''::text, 0 FROM access_change_requests WHERE tenant_id = $1 AND (requester_subject = $2 OR position($2 in reason) > 0 OR $2 = ANY(evidence_refs)) ORDER BY id`, args: []any{tenantID, subject}},
		{table: "access_change_request_decisions", sql: `SELECT request_id::text, ''::text, 0 FROM access_change_request_decisions WHERE tenant_id = $1 AND (approver_subject = $2 OR position($2 in reason) > 0 OR $2 = ANY(decision_evidence_refs)) GROUP BY request_id ORDER BY request_id`, args: []any{tenantID, subject}},
		{table: "discovery_runs", sql: `SELECT id::text, ''::text, 0 FROM discovery_runs WHERE tenant_id = $1 AND requested_by = $2 ORDER BY id`, args: []any{tenantID, subject}},
		{table: "notification_routing_policies", sql: `SELECT id::text, ''::text, 0 FROM notification_routing_policies WHERE tenant_id = $1 AND (scope_ref = $2 OR scope_ref = 'owner/' || $2 OR owner_ref = $2 OR owner_email = $2) ORDER BY id`, args: []any{tenantID, subject}},
		{table: "remediation_playbook_runs", sql: `SELECT id::text, ''::text, 0 FROM remediation_playbook_runs WHERE tenant_id = $1 AND (created_by = $2 OR position($2 in reason) > 0 OR $2 = ANY(evidence_refs) OR $2 = ANY(rollback_refs)) ORDER BY id`, args: []any{tenantID, subject}},
		{table: "compliance_report_schedules", sql: `SELECT id::text, ''::text, 0 FROM compliance_report_schedules WHERE tenant_id = $1 AND recipient_ref = $2 ORDER BY id`, args: []any{tenantID, subject}},
		{table: "incident_fleet_reissuance_runs", sql: `SELECT id::text, ''::text, 0 FROM incident_fleet_reissuance_runs WHERE tenant_id = $1 AND (created_by = $2 OR position($2 in reason) > 0 OR position($2 in evidence_bundle) > 0 OR $2 = ANY(failed_targets) OR $2 = ANY(rollback_refs)) ORDER BY id`, args: []any{tenantID, subject}},
		{table: "ownership_readiness_exceptions", sql: `SELECT id::text, ''::text, 0 FROM ownership_readiness_exceptions WHERE tenant_id = $1 AND (granted_by = $2 OR coalesce(revoked_by, '') = $2 OR position($2 in reason) > 0 OR position($2 in coalesce(revocation_reason, '')) > 0) ORDER BY id`, args: []any{tenantID, subject}},
	}
}

func appendPrivacyReadModelRecords(ctx context.Context, tx pgx.Tx, out *[]PrivacyReadModelRecord, table, sql string, args ...any) error {
	rows, err := tx.Query(ctx, sql, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		r := PrivacyReadModelRecord{Table: table}
		if err := rows.Scan(&r.ID, &r.ParentID, &r.Data, &r.At); err != nil {
			return err
		}
		*out = append(*out, r)
	}
	return rows.Err()
}

func appendPrivacyReadModelSelectors(ctx context.Context, tx pgx.Tx, out *[]PrivacyReadModelSelector, table, sql string, args ...any) error {
	rows, err := tx.Query(ctx, sql, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		sel := PrivacyReadModelSelector{Table: table}
		if err := rows.Scan(&sel.ID, &sel.ParentID, &sel.ThresholdDays); err != nil {
			return err
		}
		*out = append(*out, sel)
	}
	return rows.Err()
}

func selectStrings(ctx context.Context, tx pgx.Tx, sql string, args ...any) ([]string, error) {
	rows, err := tx.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func selectPrivacyApprovalSelectors(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, sql string,
	args ...any,
) ([]PrivacyApprovalSelector, error) {
	rows, err := tx.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PrivacyApprovalSelector
	for rows.Next() {
		var resource, action string
		if err := rows.Scan(&resource, &action); err != nil {
			return nil, err
		}
		out = append(out, PrivacyApprovalSelector{
			BindingRef: privacyApprovalBindingRef(tenantID, resource, action),
		})
	}
	return out, rows.Err()
}

func privacyApprovalBindingRef(tenantID, resource, action string) string {
	return privacy.SubjectRef(tenantID, "issuance-approval\x00"+resource+"\x00"+action)
}

func privacyCertificateRef(tenantID, fingerprint string) string {
	return privacy.SubjectRef(tenantID, "certificate-fingerprint\x00"+fingerprint)
}

func resolvePrivacyCertificateFingerprints(
	ctx context.Context,
	tx pgx.Tx,
	tenantID string,
	selectors PrivacyErasureSelectors,
) ([]string, error) {
	fingerprints := append([]string(nil), selectors.CertificateFingerprints...)
	if len(selectors.CertificateRefs) == 0 {
		return fingerprints, nil
	}
	wanted := make(map[string]struct{}, len(selectors.CertificateRefs))
	for _, ref := range selectors.CertificateRefs {
		wanted[ref] = struct{}{}
	}
	rows, err := tx.Query(ctx, `SELECT fingerprint FROM certificates
		WHERE tenant_id = $1 ORDER BY fingerprint`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	seen := make(map[string]struct{}, len(wanted))
	for rows.Next() {
		var fingerprint string
		if err := rows.Scan(&fingerprint); err != nil {
			return nil, err
		}
		ref := privacyCertificateRef(tenantID, fingerprint)
		if _, ok := wanted[ref]; !ok {
			continue
		}
		if _, duplicate := seen[ref]; duplicate {
			return nil, fmt.Errorf("%w: privacy certificate reference collision", ErrIdempotencyConflict)
		}
		seen[ref] = struct{}{}
		fingerprints = append(fingerprints, fingerprint)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return fingerprints, nil
}

func eraseApprovalRequestActors(ctx context.Context, tx pgx.Tx, tenantID, subjectRef, placeholder string, selectors []PrivacyApprovalSelector) error {
	keys, err := resolvePrivacyApprovalSelectorKeys(ctx, tx, tenantID,
		"issuance_approval_requests", selectors)
	if err != nil {
		return err
	}
	for _, sel := range keys {
		var requester string
		err := tx.QueryRow(ctx,
			`SELECT requester
			   FROM issuance_approval_requests
			  WHERE tenant_id = $1 AND resource = $2 AND action = $3`,
			tenantID, sel.Resource, sel.Action).Scan(&requester)
		if err != nil {
			if err == pgx.ErrNoRows {
				continue
			}
			return err
		}
		if privacy.SubjectRef(tenantID, requester) != subjectRef {
			continue
		}
		if _, err := tx.Exec(ctx,
			`UPDATE issuance_approval_requests
			    SET requester = $4
			  WHERE tenant_id = $1 AND resource = $2 AND action = $3`,
			tenantID, sel.Resource, sel.Action, placeholder); err != nil {
			return err
		}
	}
	return nil
}

func eraseApprovalActors(ctx context.Context, tx pgx.Tx, tenantID, subjectRef, placeholder string, selectors []PrivacyApprovalSelector) error {
	keys, err := resolvePrivacyApprovalSelectorKeys(ctx, tx, tenantID,
		"issuance_approvals", selectors)
	if err != nil {
		return err
	}
	for _, sel := range keys {
		rows, err := tx.Query(ctx,
			`SELECT approver
			   FROM issuance_approvals
			  WHERE tenant_id = $1 AND resource = $2 AND action = $3`,
			tenantID, sel.Resource, sel.Action)
		if err != nil {
			return err
		}
		var approvers []string
		for rows.Next() {
			var approver string
			if err := rows.Scan(&approver); err != nil {
				rows.Close()
				return err
			}
			if privacy.SubjectRef(tenantID, approver) == subjectRef {
				approvers = append(approvers, approver)
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		for _, approver := range approvers {
			if _, err := tx.Exec(ctx,
				`UPDATE issuance_approvals
				    SET approver = $5
				  WHERE tenant_id = $1 AND resource = $2 AND action = $3 AND approver = $4`,
				tenantID, sel.Resource, sel.Action, approver, placeholder); err != nil {
				return err
			}
		}
	}
	return nil
}

func resolvePrivacyApprovalSelectorKeys(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, table string,
	selectors []PrivacyApprovalSelector,
) ([]PrivacyApprovalSelector, error) {
	if len(selectors) == 0 {
		return nil, nil
	}
	byRef := make(map[string]struct{}, len(selectors))
	keys := make([]PrivacyApprovalSelector, 0, len(selectors))
	for _, selector := range selectors {
		if selector.BindingRef != "" {
			byRef[selector.BindingRef] = struct{}{}
			continue
		}
		// v1/v2 compatibility: historical events carried the raw composite key.
		if selector.Resource != "" || selector.Action != "" {
			keys = append(keys, selector)
		}
	}
	if len(byRef) == 0 {
		return keys, nil
	}
	if table != "issuance_approval_requests" && table != "issuance_approvals" {
		return nil, errors.New("store: unsupported privacy approval selector table")
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT resource, action FROM `+table+`
		WHERE tenant_id = $1 ORDER BY resource, action`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	seen := make(map[string]struct{}, len(byRef))
	for rows.Next() {
		var resource, action string
		if err := rows.Scan(&resource, &action); err != nil {
			return nil, err
		}
		ref := privacyApprovalBindingRef(tenantID, resource, action)
		if _, wanted := byRef[ref]; !wanted {
			continue
		}
		if _, duplicate := seen[ref]; duplicate {
			return nil, fmt.Errorf("%w: privacy approval binding reference collision", ErrIdempotencyConflict)
		}
		seen[ref] = struct{}{}
		keys = append(keys, PrivacyApprovalSelector{Resource: resource, Action: action})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return keys, nil
}

func erasePrivacyReadModelRows(ctx context.Context, tx pgx.Tx, tenantID, subjectRef, placeholder string, selectors []PrivacyReadModelSelector) error {
	if len(selectors) == 0 {
		return nil
	}
	for _, fn := range []func(context.Context, pgx.Tx, string, string, string, []PrivacyReadModelSelector) error{
		eraseOperationApprovalDecisionPrivacyRows,
		eraseOperationApprovalRequestPrivacyRows,
		erasePAMSessionPrivacyRows,
		eraseDiscoverySourcePrivacyRows,
		eraseDiscoveryFindingPrivacyRows,
		eraseNotificationThresholdPrivacyRows,
		eraseIncidentExecutionPrivacyRows,
		eraseAccessReviewCampaignPrivacyRows,
		eraseAccessReviewItemPrivacyRows,
		eraseAccessChangeRequestPrivacyRows,
		eraseAccessChangeDecisionPrivacyRows,
		eraseDiscoveryRunPrivacyRows,
		eraseNotificationRoutingPolicyPrivacyRows,
		eraseRemediationRunPrivacyRows,
		eraseComplianceReportSchedulePrivacyRows,
		eraseIncidentFleetReissuancePrivacyRows,
		eraseOwnershipReadinessExceptionPrivacyRows,
	} {
		if err := fn(ctx, tx, tenantID, subjectRef, placeholder, selectors); err != nil {
			return err
		}
	}
	return nil
}

func operationApprovalRequesterIDsMatchingSubjectRef(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, subjectRef string,
	ids []string,
) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT id::text, requester
		FROM operation_approval_requests
		WHERE tenant_id = $1 AND id::text = ANY($2::text[])
		ORDER BY id
		FOR UPDATE`, tenantID, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	matches := make([]string, 0, len(ids))
	seen := 0
	for rows.Next() {
		var id, requester string
		if err := rows.Scan(&id, &requester); err != nil {
			return nil, err
		}
		seen++
		if subjectValueMatches(tenantID, subjectRef, requester) {
			matches = append(matches, id)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if seen != len(ids) {
		return nil, fmt.Errorf("%w: selected operation approval request is missing", ErrIdempotencyConflict)
	}
	return matches, nil
}

func operationApprovalDecisionIDsMatchingSubjectRef(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, subjectRef string,
	ids []string,
) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT event_id::text, approver
		FROM operation_approval_decisions
		WHERE tenant_id = $1 AND event_id::text = ANY($2::text[])
		ORDER BY event_id
		FOR UPDATE`, tenantID, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	matches := make([]string, 0, len(ids))
	seen := 0
	for rows.Next() {
		var id, approver string
		if err := rows.Scan(&id, &approver); err != nil {
			return nil, err
		}
		seen++
		if subjectValueMatches(tenantID, subjectRef, approver) {
			matches = append(matches, id)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if seen != len(ids) {
		return nil, fmt.Errorf("%w: selected operation approval decision is missing", ErrIdempotencyConflict)
	}
	return matches, nil
}

func eraseOperationApprovalRequestPrivacyRows(ctx context.Context, tx pgx.Tx, tenantID, subjectRef, placeholder string, selectors []PrivacyReadModelSelector) error {
	ids := readModelIDs(selectors, "operation_approval_requests")
	if len(ids) == 0 {
		return nil
	}
	directRequesterIDs, err := operationApprovalRequesterIDsMatchingSubjectRef(
		ctx, tx, tenantID, subjectRef, ids,
	)
	if err != nil {
		return err
	}
	// Requester, reason, and evidence are part of the immutable intent digest. A
	// privacy projection may pseudonymize those fields, but it must first revoke
	// any still-live authority. Otherwise the altered row could remain approved
	// even though it no longer describes the command reviewers saw.
	tag, err := tx.Exec(ctx,
		`UPDATE operation_approval_requests
		    SET resource_kind = $3, resource_id = $3, resource_name = $3,
		        action = $3,
		        requester = CASE WHEN id::text = ANY($4::text[]) THEN $3 ELSE requester END,
		        from_state = $3, to_state = $3,
		        reason = '', evidence_refs = '[]'::jsonb,
		        status = CASE WHEN status IN ('pending', 'approved') THEN 'superseded' ELSE status END
		  WHERE tenant_id = $1 AND id::text = ANY($2::text[])`,
		tenantID, ids, placeholder, directRequesterIDs)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != int64(len(ids)) {
		return fmt.Errorf("%w: selected operation approval request is missing", ErrIdempotencyConflict)
	}
	return nil
}

func eraseOperationApprovalDecisionPrivacyRows(ctx context.Context, tx pgx.Tx, tenantID, subjectRef, placeholder string, selectors []PrivacyReadModelSelector) error {
	ids := readModelIDs(selectors, "operation_approval_decisions")
	if len(ids) == 0 {
		return nil
	}
	directApproverIDs, err := operationApprovalDecisionIDsMatchingSubjectRef(
		ctx, tx, tenantID, subjectRef, ids,
	)
	if err != nil {
		return err
	}
	// An approver identity is part of the quorum proof. Supersede every live
	// parent before pseudonymizing a selected decision so erasure cannot turn a
	// modified quorum into reusable authority.
	if _, err := tx.Exec(ctx,
		`UPDATE operation_approval_requests r
		    SET status = 'superseded'
		  WHERE r.tenant_id = $1 AND r.status IN ('pending', 'approved')
		    AND EXISTS (
		          SELECT 1 FROM operation_approval_decisions d
		           WHERE d.tenant_id = r.tenant_id AND d.request_id = r.id
		             AND d.event_id::text = ANY($2::text[])
		        )`, tenantID, ids); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE operation_approval_decisions
		SET approver = CASE WHEN event_id::text = ANY($4::text[]) THEN $3 ELSE approver END,
		    reason = ''
		WHERE tenant_id = $1 AND event_id::text = ANY($2::text[])`,
		tenantID, ids, placeholder, directApproverIDs)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != int64(len(ids)) {
		return fmt.Errorf("%w: selected operation approval decision is missing", ErrIdempotencyConflict)
	}
	return nil
}

func erasePAMSessionPrivacyRows(ctx context.Context, tx pgx.Tx, tenantID, subjectRef, placeholder string, selectors []PrivacyReadModelSelector) error {
	ids := readModelIDs(selectors, "pam_sessions")
	if len(ids) == 0 {
		return nil
	}
	type row struct{ id, subject, requestedBy string }
	var rowsToUpdate []row
	rows, err := tx.Query(ctx, `SELECT id::text, subject, requested_by FROM pam_sessions WHERE tenant_id = $1 AND id::text = ANY($2)`, tenantID, ids)
	if err != nil {
		return err
	}
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.subject, &r.requestedBy); err != nil {
			rows.Close()
			return err
		}
		rowsToUpdate = append(rowsToUpdate, r)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, r := range rowsToUpdate {
		if _, err := tx.Exec(ctx,
			`UPDATE pam_sessions
			    SET subject = $3,
			        requested_by = $4,
			        reason = '',
			        audit = '{}'::jsonb
			  WHERE tenant_id = $1 AND id::text = $2`,
			tenantID, r.id, redactSubjectValue(tenantID, subjectRef, placeholder, r.subject), redactSubjectValue(tenantID, subjectRef, placeholder, r.requestedBy)); err != nil {
			return err
		}
	}
	return nil
}

func eraseDiscoverySourcePrivacyRows(ctx context.Context, tx pgx.Tx, tenantID, subjectRef, placeholder string, selectors []PrivacyReadModelSelector) error {
	ids := readModelIDs(selectors, "discovery_sources")
	if len(ids) == 0 {
		return nil
	}
	type row struct{ id, config string }
	var rowsToUpdate []row
	rows, err := tx.Query(ctx, `SELECT id::text, config::text FROM discovery_sources WHERE tenant_id = $1 AND id::text = ANY($2)`, tenantID, ids)
	if err != nil {
		return err
	}
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.config); err != nil {
			rows.Close()
			return err
		}
		rowsToUpdate = append(rowsToUpdate, r)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	redactor := privacy.Redactor{TenantID: tenantID, Refs: map[string]struct{}{subjectRef: {}}}
	for _, r := range rowsToUpdate {
		config := redactor.RedactJSON([]byte(r.config))
		if string(config) == r.config {
			continue
		}
		if _, err := tx.Exec(ctx,
			`UPDATE discovery_sources
			    SET config = $3::jsonb
			  WHERE tenant_id = $1 AND id::text = $2`,
			tenantID, r.id, string(config)); err != nil {
			return err
		}
	}
	return nil
}

func eraseDiscoveryFindingPrivacyRows(ctx context.Context, tx pgx.Tx, tenantID, subjectRef, placeholder string, selectors []PrivacyReadModelSelector) error {
	ids := readModelIDs(selectors, "discovery_findings")
	if len(ids) == 0 {
		return nil
	}
	type row struct{ id, actor, metadata string }
	var rowsToUpdate []row
	rows, err := tx.Query(ctx, `SELECT id::text, triage_actor, metadata::text FROM discovery_findings WHERE tenant_id = $1 AND id::text = ANY($2)`, tenantID, ids)
	if err != nil {
		return err
	}
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.actor, &r.metadata); err != nil {
			rows.Close()
			return err
		}
		rowsToUpdate = append(rowsToUpdate, r)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	redactor := privacy.Redactor{TenantID: tenantID, Refs: map[string]struct{}{subjectRef: {}}}
	for _, r := range rowsToUpdate {
		metadata := redactor.RedactJSON([]byte(r.metadata))
		if _, err := tx.Exec(ctx,
			`UPDATE discovery_findings
			    SET triage_actor = $3,
			        triage_reason = '',
			        metadata = $4::jsonb
			  WHERE tenant_id = $1 AND id::text = $2`,
			tenantID, r.id, redactSubjectValue(tenantID, subjectRef, placeholder, r.actor), string(metadata)); err != nil {
			return err
		}
	}
	return nil
}

func retainDiscoverySourcePrivacyRows(ctx context.Context, tx pgx.Tx, tenantID string, cutoff time.Time) error {
	type row struct{ id, config string }
	var rowsToUpdate []row
	rows, err := tx.Query(ctx,
		`SELECT id::text, config::text
		   FROM discovery_sources
		  WHERE tenant_id = $1
		    AND updated_at < $2
		    AND `+discoveryPrivacyJSONHasRetainablePII("config")+`
		  ORDER BY id`,
		tenantID, cutoff)
	if err != nil {
		return err
	}
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.config); err != nil {
			rows.Close()
			return err
		}
		rowsToUpdate = append(rowsToUpdate, r)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, r := range rowsToUpdate {
		config, changed, err := redactDiscoveryRetainedJSON([]byte(r.config))
		if err != nil {
			return err
		}
		if !changed {
			continue
		}
		if _, err := tx.Exec(ctx,
			`UPDATE discovery_sources
			    SET config = $3::jsonb
			  WHERE tenant_id = $1 AND id::text = $2`,
			tenantID, r.id, string(config)); err != nil {
			return err
		}
	}
	return nil
}

func retainDiscoveryFindingMetadataPrivacyRows(ctx context.Context, tx pgx.Tx, tenantID string, cutoff time.Time) error {
	type row struct{ id, metadata string }
	var rowsToUpdate []row
	rows, err := tx.Query(ctx,
		`SELECT id::text, metadata::text
		   FROM discovery_findings
		  WHERE tenant_id = $1
		    AND discovered_at < $2
		    AND `+discoveryPrivacyJSONHasRetainablePII("metadata")+`
		  ORDER BY id`,
		tenantID, cutoff)
	if err != nil {
		return err
	}
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.metadata); err != nil {
			rows.Close()
			return err
		}
		rowsToUpdate = append(rowsToUpdate, r)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, r := range rowsToUpdate {
		metadata, changed, err := redactDiscoveryRetainedJSON([]byte(r.metadata))
		if err != nil {
			return err
		}
		if !changed {
			continue
		}
		if _, err := tx.Exec(ctx,
			`UPDATE discovery_findings
			    SET metadata = $3::jsonb
			  WHERE tenant_id = $1 AND id::text = $2`,
			tenantID, r.id, string(metadata)); err != nil {
			return err
		}
	}
	return nil
}

func redactDiscoveryRetainedJSON(raw []byte) ([]byte, bool, error) {
	if len(raw) == 0 {
		return raw, false, nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, false, err
	}
	if !redactDiscoveryRetainedValue(&v, "") {
		return raw, false, nil
	}
	out, err := json.Marshal(v)
	if err != nil {
		return nil, false, err
	}
	return out, true, nil
}

func redactDiscoveryRetainedValue(v *any, key string) bool {
	if discoveryPrivacyArrayKey(key) {
		if values, ok := (*v).([]any); ok && len(values) > 0 {
			*v = []any{}
			return true
		}
	}
	if discoveryPrivacyScalarKey(key) {
		if value, ok := (*v).(string); ok {
			redacted := retainedDiscoveryPrivacyScalar(key, value)
			if redacted != value {
				*v = redacted
				return true
			}
		}
	}
	switch x := (*v).(type) {
	case []any:
		var changed bool
		for i := range x {
			if redactDiscoveryRetainedValue(&x[i], "") {
				changed = true
			}
		}
		return changed
	case map[string]any:
		var changed bool
		for k, val := range x {
			if redactDiscoveryRetainedValue(&val, k) {
				x[k] = val
				changed = true
			}
		}
		return changed
	}
	return false
}

func retainedDiscoveryPrivacyScalar(key, value string) string {
	if value == "" || privacy.IsPlaceholder(value) || strings.HasPrefix(value, "retained:") {
		return value
	}
	switch normalizeDiscoveryPrivacyKey(key) {
	case "principal", "owner", "display_name":
		return "retained:discovery"
	default:
		return ""
	}
}

func discoveryPrivacyScalarKey(key string) bool {
	switch normalizeDiscoveryPrivacyKey(key) {
	case "principal", "owner", "display_name", "ip", "user_agent", "source_event_ref":
		return true
	default:
		return false
	}
}

func discoveryPrivacyArrayKey(key string) bool {
	return normalizeDiscoveryPrivacyKey(key) == "evidence_refs"
}

func normalizeDiscoveryPrivacyKey(key string) string {
	key = strings.ToLower(strings.TrimSpace(key))
	key = strings.ReplaceAll(key, "-", "_")
	return key
}

func eraseNotificationThresholdPrivacyRows(ctx context.Context, tx pgx.Tx, tenantID, subjectRef, placeholder string, selectors []PrivacyReadModelSelector) error {
	for _, threshold := range readModelThresholds(selectors, "notification_threshold_deliveries") {
		type row struct {
			subject string
			channel string
		}
		var rowsToUpdate []row
		rows, err := tx.Query(ctx,
			`SELECT subject, channel
			   FROM notification_threshold_deliveries
			  WHERE tenant_id = $1 AND threshold_days = $2`,
			tenantID, threshold)
		if err != nil {
			return err
		}
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.subject, &r.channel); err != nil {
				rows.Close()
				return err
			}
			if subjectValueMatches(tenantID, subjectRef, r.subject) || subjectValueMatches(tenantID, subjectRef, r.channel) {
				rowsToUpdate = append(rowsToUpdate, r)
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		for _, r := range rowsToUpdate {
			if _, err := tx.Exec(ctx,
				`UPDATE notification_threshold_deliveries
				    SET subject = $5,
				        channel = $6
				  WHERE tenant_id = $1 AND subject = $2 AND threshold_days = $3 AND channel = $4`,
				tenantID, r.subject, threshold, r.channel,
				redactSubjectValue(tenantID, subjectRef, placeholder, r.subject),
				redactSubjectValue(tenantID, subjectRef, placeholder, r.channel)); err != nil {
				return err
			}
		}
	}
	return nil
}

func eraseIncidentExecutionPrivacyRows(ctx context.Context, tx pgx.Tx, tenantID, subjectRef, placeholder string, selectors []PrivacyReadModelSelector) error {
	return eraseIncidentEvidenceRows(ctx, tx, tenantID, subjectRef, placeholder, "incident_executions", readModelIDs(selectors, "incident_executions"))
}

func eraseAccessReviewCampaignPrivacyRows(ctx context.Context, tx pgx.Tx, tenantID, subjectRef, placeholder string, selectors []PrivacyReadModelSelector) error {
	ids := readModelIDs(selectors, "nhi_access_review_campaigns")
	if len(ids) == 0 {
		return nil
	}
	type row struct{ id, reviewer, requestedBy string }
	var rowsToUpdate []row
	rows, err := tx.Query(ctx, `SELECT id::text, reviewer_subject, requested_by FROM nhi_access_review_campaigns WHERE tenant_id = $1 AND id::text = ANY($2)`, tenantID, ids)
	if err != nil {
		return err
	}
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.reviewer, &r.requestedBy); err != nil {
			rows.Close()
			return err
		}
		rowsToUpdate = append(rowsToUpdate, r)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, r := range rowsToUpdate {
		if _, err := tx.Exec(ctx,
			`UPDATE nhi_access_review_campaigns
			    SET reviewer_subject = $3,
			        requested_by = $4
			  WHERE tenant_id = $1 AND id::text = $2`,
			tenantID, r.id,
			redactSubjectValue(tenantID, subjectRef, placeholder, r.reviewer),
			redactSubjectValue(tenantID, subjectRef, placeholder, r.requestedBy)); err != nil {
			return err
		}
	}
	return nil
}

func eraseAccessReviewItemPrivacyRows(ctx context.Context, tx pgx.Tx, tenantID, subjectRef, placeholder string, selectors []PrivacyReadModelSelector) error {
	items := readModelChildSelectors(selectors, "nhi_access_review_items")
	for _, sel := range items {
		var decisionBy string
		var evidenceRefs []string
		err := tx.QueryRow(ctx,
			`SELECT decision_by, decision_evidence_refs
			   FROM nhi_access_review_items
			  WHERE tenant_id = $1 AND campaign_id::text = $2 AND item_id::text = $3`,
			tenantID, sel.ParentID, sel.ID).Scan(&decisionBy, &evidenceRefs)
		if err != nil {
			if err == pgx.ErrNoRows {
				continue
			}
			return err
		}
		if _, err := tx.Exec(ctx,
			`UPDATE nhi_access_review_items
			    SET decision_by = $4,
			        decision_reason = '',
			        decision_evidence_refs = $5
			  WHERE tenant_id = $1 AND campaign_id::text = $2 AND item_id::text = $3`,
			tenantID, sel.ParentID, sel.ID,
			redactSubjectValue(tenantID, subjectRef, placeholder, decisionBy),
			redactSubjectValues(tenantID, subjectRef, placeholder, evidenceRefs)); err != nil {
			return err
		}
	}
	return nil
}

func eraseAccessChangeRequestPrivacyRows(ctx context.Context, tx pgx.Tx, tenantID, subjectRef, placeholder string, selectors []PrivacyReadModelSelector) error {
	ids := readModelIDs(selectors, "access_change_requests")
	if len(ids) == 0 {
		return nil
	}
	type row struct {
		id           string
		requester    string
		evidenceRefs []string
	}
	var rowsToUpdate []row
	rows, err := tx.Query(ctx, `SELECT id::text, requester_subject, evidence_refs FROM access_change_requests WHERE tenant_id = $1 AND id::text = ANY($2)`, tenantID, ids)
	if err != nil {
		return err
	}
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.requester, &r.evidenceRefs); err != nil {
			rows.Close()
			return err
		}
		rowsToUpdate = append(rowsToUpdate, r)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, r := range rowsToUpdate {
		if _, err := tx.Exec(ctx,
			`UPDATE access_change_requests
			    SET requester_subject = $3,
			        reason = 'privacy-redacted',
			        evidence_refs = $4
			  WHERE tenant_id = $1 AND id::text = $2`,
			tenantID, r.id,
			redactSubjectValue(tenantID, subjectRef, placeholder, r.requester),
			redactSubjectValues(tenantID, subjectRef, placeholder, r.evidenceRefs)); err != nil {
			return err
		}
	}
	return nil
}

func eraseAccessChangeDecisionPrivacyRows(ctx context.Context, tx pgx.Tx, tenantID, subjectRef, placeholder string, selectors []PrivacyReadModelSelector) error {
	requestIDs := readModelIDs(selectors, "access_change_request_decisions")
	if len(requestIDs) == 0 {
		return nil
	}
	type row struct {
		requestID    string
		approver     string
		evidenceRefs []string
	}
	var rowsToUpdate []row
	rows, err := tx.Query(ctx,
		`SELECT request_id::text, approver_subject, decision_evidence_refs
		   FROM access_change_request_decisions
		  WHERE tenant_id = $1 AND request_id::text = ANY($2)`,
		tenantID, requestIDs)
	if err != nil {
		return err
	}
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.requestID, &r.approver, &r.evidenceRefs); err != nil {
			rows.Close()
			return err
		}
		rowsToUpdate = append(rowsToUpdate, r)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, r := range rowsToUpdate {
		if _, err := tx.Exec(ctx,
			`UPDATE access_change_request_decisions
			    SET approver_subject = $4,
			        reason = '',
			        decision_evidence_refs = $5
			  WHERE tenant_id = $1 AND request_id::text = $2 AND approver_subject = $3`,
			tenantID, r.requestID, r.approver,
			redactSubjectValue(tenantID, subjectRef, placeholder, r.approver),
			redactSubjectValues(tenantID, subjectRef, placeholder, r.evidenceRefs)); err != nil {
			return err
		}
	}
	return nil
}

func eraseDiscoveryRunPrivacyRows(ctx context.Context, tx pgx.Tx, tenantID, subjectRef, placeholder string, selectors []PrivacyReadModelSelector) error {
	ids := readModelIDs(selectors, "discovery_runs")
	if len(ids) == 0 {
		return nil
	}
	if _, err := tx.Exec(ctx,
		`UPDATE discovery_runs
		    SET requested_by = $3
		  WHERE tenant_id = $1 AND id::text = ANY($2)`,
		tenantID, ids, placeholder); err != nil {
		return err
	}
	return nil
}

func eraseNotificationRoutingPolicyPrivacyRows(ctx context.Context, tx pgx.Tx, tenantID, subjectRef, placeholder string, selectors []PrivacyReadModelSelector) error {
	ids := readModelIDs(selectors, "notification_routing_policies")
	if len(ids) == 0 {
		return nil
	}
	type row struct{ id, scopeKind, scopeRef, ownerRef, ownerEmail string }
	var rowsToUpdate []row
	rows, err := tx.Query(ctx, `SELECT id::text, scope_kind, scope_ref, owner_ref, owner_email FROM notification_routing_policies WHERE tenant_id = $1 AND id::text = ANY($2)`, tenantID, ids)
	if err != nil {
		return err
	}
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.scopeKind, &r.scopeRef, &r.ownerRef, &r.ownerEmail); err != nil {
			rows.Close()
			return err
		}
		rowsToUpdate = append(rowsToUpdate, r)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, r := range rowsToUpdate {
		scopeRef := r.scopeRef
		if r.scopeKind == "owner" && (subjectValueMatches(tenantID, subjectRef, scopeRef) || subjectValueMatches(tenantID, "owner/"+subjectRef, scopeRef)) {
			scopeRef = "owner/" + strings.TrimPrefix(placeholder, "owner/")
		}
		ownerEmail := r.ownerEmail
		if subjectValueMatches(tenantID, subjectRef, ownerEmail) {
			ownerEmail = ""
		}
		if _, err := tx.Exec(ctx,
			`UPDATE notification_routing_policies
			    SET scope_ref = $3,
			        owner_ref = $4,
			        owner_email = $5
			  WHERE tenant_id = $1 AND id::text = $2`,
			tenantID, r.id,
			scopeRef,
			redactSubjectValue(tenantID, subjectRef, placeholder, r.ownerRef),
			ownerEmail); err != nil {
			return err
		}
	}
	return nil
}

func eraseRemediationRunPrivacyRows(ctx context.Context, tx pgx.Tx, tenantID, subjectRef, placeholder string, selectors []PrivacyReadModelSelector) error {
	ids := readModelIDs(selectors, "remediation_playbook_runs")
	if len(ids) == 0 {
		return nil
	}
	type row struct {
		id           string
		createdBy    string
		evidenceRefs []string
		rollbackRefs []string
	}
	var rowsToUpdate []row
	rows, err := tx.Query(ctx,
		`SELECT id::text, created_by, evidence_refs, rollback_refs
		   FROM remediation_playbook_runs
		  WHERE tenant_id = $1 AND id::text = ANY($2)`,
		tenantID, ids)
	if err != nil {
		return err
	}
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.createdBy, &r.evidenceRefs, &r.rollbackRefs); err != nil {
			rows.Close()
			return err
		}
		rowsToUpdate = append(rowsToUpdate, r)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, r := range rowsToUpdate {
		if _, err := tx.Exec(ctx,
			`UPDATE remediation_playbook_runs
			    SET created_by = $3,
			        reason = '',
			        evidence_refs = $4,
			        rollback_refs = $5,
			        initial_http_status = 0,
			        initial_response = ''::bytea
			  WHERE tenant_id = $1 AND id::text = $2`,
			tenantID, r.id,
			redactSubjectValue(tenantID, subjectRef, placeholder, r.createdBy),
			redactSubjectValues(tenantID, subjectRef, placeholder, r.evidenceRefs),
			redactSubjectValues(tenantID, subjectRef, placeholder, r.rollbackRefs)); err != nil {
			return err
		}
	}
	return nil
}

func eraseComplianceReportSchedulePrivacyRows(ctx context.Context, tx pgx.Tx, tenantID, subjectRef, placeholder string, selectors []PrivacyReadModelSelector) error {
	ids := readModelIDs(selectors, "compliance_report_schedules")
	if len(ids) == 0 {
		return nil
	}
	if _, err := tx.Exec(ctx,
		`UPDATE compliance_report_schedules
		    SET recipient_ref = $3
		  WHERE tenant_id = $1 AND id::text = ANY($2)`,
		tenantID, ids, placeholder); err != nil {
		return err
	}
	return nil
}

func eraseIncidentFleetReissuancePrivacyRows(ctx context.Context, tx pgx.Tx, tenantID, subjectRef, placeholder string, selectors []PrivacyReadModelSelector) error {
	return eraseIncidentEvidenceRows(ctx, tx, tenantID, subjectRef, placeholder, "incident_fleet_reissuance_runs", readModelIDs(selectors, "incident_fleet_reissuance_runs"))
}

func eraseOwnershipReadinessExceptionPrivacyRows(ctx context.Context, tx pgx.Tx, tenantID, subjectRef, placeholder string, selectors []PrivacyReadModelSelector) error {
	ids := readModelIDs(selectors, "ownership_readiness_exceptions")
	if len(ids) == 0 {
		return nil
	}
	type row struct{ id, grantedBy, revokedBy string }
	var selected []row
	rows, err := tx.Query(ctx, `SELECT id::text, granted_by, coalesce(revoked_by, '')
		FROM ownership_readiness_exceptions
		WHERE tenant_id = $1 AND id::text = ANY($2::text[])`, tenantID, ids)
	if err != nil {
		return err
	}
	for rows.Next() {
		var item row
		if err := rows.Scan(&item.id, &item.grantedBy, &item.revokedBy); err != nil {
			rows.Close()
			return err
		}
		selected = append(selected, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, item := range selected {
		if _, err := tx.Exec(ctx, `UPDATE ownership_readiness_exceptions
			SET reason = '', revocation_reason = '',
			    granted_by = $3, revoked_by = $4
			WHERE tenant_id = $1 AND id::text = $2`, tenantID, item.id,
			redactSubjectValue(tenantID, subjectRef, placeholder, item.grantedBy),
			redactSubjectValue(tenantID, subjectRef, placeholder, item.revokedBy)); err != nil {
			return err
		}
	}
	return nil
}

func eraseIncidentEvidenceRows(ctx context.Context, tx pgx.Tx, tenantID, subjectRef, placeholder, table string, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	type row struct {
		id            string
		createdBy     string
		failedTargets []string
		rollbackRefs  []string
	}
	var rowsToUpdate []row
	rows, err := tx.Query(ctx,
		fmt.Sprintf(`SELECT id::text, created_by, failed_targets, rollback_refs FROM %s WHERE tenant_id = $1 AND id::text = ANY($2)`, table),
		tenantID, ids)
	if err != nil {
		return err
	}
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.createdBy, &r.failedTargets, &r.rollbackRefs); err != nil {
			rows.Close()
			return err
		}
		rowsToUpdate = append(rowsToUpdate, r)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, r := range rowsToUpdate {
		if _, err := tx.Exec(ctx,
			fmt.Sprintf(`UPDATE %s
			    SET created_by = $3,
			        reason = '',
			        evidence_bundle = '',
			        failed_targets = $4,
			        rollback_refs = $5
			  WHERE tenant_id = $1 AND id::text = $2`, table),
			tenantID, r.id,
			redactSubjectValue(tenantID, subjectRef, placeholder, r.createdBy),
			redactSubjectValues(tenantID, subjectRef, placeholder, r.failedTargets),
			redactSubjectValues(tenantID, subjectRef, placeholder, r.rollbackRefs)); err != nil {
			return err
		}
	}
	return nil
}

func readModelIDs(selectors []PrivacyReadModelSelector, table string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, sel := range selectors {
		if sel.Table != table || sel.ID == "" {
			continue
		}
		if _, ok := seen[sel.ID]; ok {
			continue
		}
		seen[sel.ID] = struct{}{}
		out = append(out, sel.ID)
	}
	return out
}

func readModelChildSelectors(selectors []PrivacyReadModelSelector, table string) []PrivacyReadModelSelector {
	seen := map[string]struct{}{}
	var out []PrivacyReadModelSelector
	for _, sel := range selectors {
		if sel.Table != table || sel.ID == "" || sel.ParentID == "" {
			continue
		}
		key := sel.ParentID + "/" + sel.ID
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, sel)
	}
	return out
}

func readModelThresholds(selectors []PrivacyReadModelSelector, table string) []int {
	seen := map[int]struct{}{}
	var out []int
	for _, sel := range selectors {
		if sel.Table != table || sel.ThresholdDays == 0 {
			continue
		}
		if _, ok := seen[sel.ThresholdDays]; ok {
			continue
		}
		seen[sel.ThresholdDays] = struct{}{}
		out = append(out, sel.ThresholdDays)
	}
	return out
}

func subjectValueMatches(tenantID, subjectRef, value string) bool {
	return value != "" && !privacy.IsPlaceholder(value) && privacy.SubjectRef(tenantID, value) == subjectRef
}

func redactSubjectValue(tenantID, subjectRef, placeholder, value string) string {
	if subjectValueMatches(tenantID, subjectRef, value) {
		return placeholder
	}
	return value
}

func redactSubjectValues(tenantID, subjectRef, placeholder string, values []string) []string {
	if len(values) == 0 {
		return values
	}
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = redactSubjectValue(tenantID, subjectRef, placeholder, v)
	}
	return out
}

func countPrivacyRetentionRows(ctx context.Context, tx pgx.Tx, tenantID string, c PrivacyRetentionCutoffs) (map[string]int, error) {
	queries := map[string]struct {
		sql  string
		args []any
	}{
		"owners": {
			sql: `SELECT count(*) FROM owners
			       WHERE tenant_id = $1
			         AND created_at < $2
			         AND (email <> '' OR name NOT LIKE 'retained:%'
			           OR coalesce(application_id, '') <> '' OR coalesce(service, '') <> ''
			           OR coalesce(business_unit, '') <> '' OR jsonb_array_length(escalation_chain) > 0
			           OR coalesce(ownership_verified_by, '') <> '')
			         AND NOT EXISTS (
			               SELECT 1 FROM identities
			                WHERE tenant_id = $1 AND owner_id = owners.id
			             )`,
			args: []any{tenantID, c.OwnerInactiveBefore},
		},
		"identities": {
			sql: `SELECT count(*) FROM identities
			       WHERE tenant_id = $1
			         AND (name NOT LIKE 'retained:%' OR attributes <> '{}'::jsonb)
			         AND (
			               (status IN ('revoked', 'retired') AND created_at < $2)
			            OR (not_after IS NOT NULL AND not_after < $2)
			         )`,
			args: []any{tenantID, c.IdentityTerminalBefore},
		},
		"certificates": {
			sql: `SELECT count(*) FROM certificates
			       WHERE tenant_id = $1
			         AND (subject NOT LIKE 'retained:%' OR cardinality(sans) > 0 OR deployment_location <> '' OR source <> '' OR broker_issuance IS NOT NULL)
			         AND (
			               (status IN ('revoked', 'superseded')
			                AND COALESCE(revoked_at, renewed_at, not_after, created_at) < $2)
			            OR (not_after IS NOT NULL AND not_after < $2)
			         )`,
			args: []any{tenantID, c.CertificateTerminalBefore},
		},
		"ssh_keys": {
			sql: `SELECT count(*) FROM ssh_keys
			       WHERE tenant_id = $1
			         AND orphaned = true
			         AND created_at < $2
			         AND (comment <> '' OR location <> '')`,
			args: []any{tenantID, c.SSHStaleBefore},
		},
		"attestations": {
			sql: `SELECT count(*) FROM attestations
			       WHERE tenant_id = $1
			         AND created_at < $2
			         AND evidence <> '{}'::jsonb`,
			args: []any{tenantID, c.AttestationEvidenceBefore},
		},
		"approval_requests": {
			sql: `SELECT count(*) FROM issuance_approval_requests
			       WHERE tenant_id = $1
			         AND created_at < $2
			         AND requester <> ''
			         AND requester NOT LIKE 'retained:%'`,
			args: []any{tenantID, c.ApprovalActorBefore},
		},
		"approvals": {
			sql: `SELECT count(*) FROM issuance_approvals
			       WHERE tenant_id = $1
			         AND approved_at < $2
			         AND approver <> ''
			         AND approver NOT LIKE 'retained:%'`,
			args: []any{tenantID, c.ApprovalActorBefore},
		},
		"operation_approval_requests": {
			sql: `SELECT count(*) FROM operation_approval_requests r
			       WHERE r.tenant_id = $1
			         AND (
			               (status IN ('denied', 'expired', 'superseded', 'consumed') AND updated_at < $2)
			            OR (status IN ('pending', 'approved') AND expires_at < $2)
			         )
			         AND (
			               (requester NOT LIKE 'retained:%' AND requester NOT LIKE 'erased:%')
			            OR reason <> ''
			            OR evidence_refs <> '[]'::jsonb
			         )
			         AND NOT EXISTS (
			               SELECT 1 FROM approved_target_event_fences f
			                WHERE f.tenant_id = r.tenant_id AND f.approval_request_id = r.id
			         )`,
			args: []any{tenantID, c.ApprovalActorBefore},
		},
		"operation_approval_decisions": {
			sql: `SELECT count(*) FROM operation_approval_decisions
			       WHERE tenant_id = $1
			         AND decided_at < $2
			         AND (
			               (approver NOT LIKE 'retained:%' AND approver NOT LIKE 'erased:%')
			            OR reason <> ''
			         )`,
			args: []any{tenantID, c.ApprovalActorBefore},
		},
		"profiles": {
			sql: `SELECT count(*) FROM certificate_profiles
			       WHERE tenant_id = $1
			         AND created_at < $2
			         AND created_by <> ''
			         AND created_by NOT LIKE 'retained:%'`,
			args: []any{tenantID, c.ProfileActorBefore},
		},
		"api_tokens": {
			sql: `SELECT count(*) FROM api_tokens
			       WHERE tenant_id = $1
			         AND subject_ref <> ''
			         AND subject NOT LIKE 'erased:%'
			         AND (
			               (revoked_at IS NOT NULL AND revoked_at < $2)
			            OR (expires_at IS NOT NULL AND expires_at < $2)
			         )`,
			args: []any{tenantID, c.AccessTerminalBefore},
		},
		"tenant_members": {
			sql: `SELECT count(*) FROM tenant_members
			       WHERE tenant_id = $1
			         AND subject_ref <> ''
			         AND status = 'offboarded'
			         AND offboarded_at IS NOT NULL
			         AND offboarded_at < $2
			         AND (subject NOT LIKE 'erased:%' OR display_name <> '' OR email <> '')`,
			args: []any{tenantID, c.AccessTerminalBefore},
		},
		"agents": {
			sql: `SELECT count(*) FROM agents
				       WHERE tenant_id = $1
				         AND (
				               name NOT LIKE 'retained:%'
				            OR (COALESCE(offboarded_by, '') <> '' AND offboarded_by NOT LIKE 'retained:%')
				            OR COALESCE(offboard_reason, '') <> ''
				         )
			         AND (
			               (last_seen_at IS NOT NULL AND last_seen_at < $2)
			            OR (last_seen_at IS NULL AND created_at < $2)
			            OR (offboarded_at IS NOT NULL AND offboarded_at < $2)
				         )`,
			args: []any{tenantID, c.AgentStaleBefore},
		},
		"pam_sessions": {
			sql: `SELECT count(*) FROM pam_sessions
				       WHERE tenant_id = $1
				         AND COALESCE(ended_at, expires_at) < $2
				         AND (
				               subject NOT LIKE 'retained:%'
				            OR requested_by NOT LIKE 'retained:%'
				            OR reason <> ''
				            OR audit <> '{}'::jsonb
				)`,
			args: []any{tenantID, c.AccessTerminalBefore},
		},
		"discovery_sources": {
			sql: `SELECT count(*) FROM discovery_sources
					       WHERE tenant_id = $1
					         AND updated_at < $2
					         AND ` + discoveryPrivacyJSONHasRetainablePII("config"),
			args: []any{tenantID, c.AttestationEvidenceBefore},
		},
		"discovery_findings": {
			sql: `SELECT count(*) FROM discovery_findings
					       WHERE tenant_id = $1
					         AND (
					               (triaged_at IS NOT NULL AND triaged_at < $2
					                 AND ((triage_actor <> '' AND triage_actor NOT LIKE 'retained:%' AND triage_actor NOT LIKE 'erased:%') OR triage_reason <> ''))
					            OR (discovered_at < $2 AND ` + discoveryPrivacyJSONHasRetainablePII("metadata") + `)
					         )`,
			args: []any{tenantID, c.AttestationEvidenceBefore},
		},
		"notification_threshold_deliveries": {
			sql: `SELECT count(*) FROM notification_threshold_deliveries
				       WHERE tenant_id = $1
				         AND last_sent_at < $2
				         AND (
				               subject NOT LIKE 'retained:%'
				            OR (
				                 channel NOT IN ('email', 'slack', 'teams', 'sms', 'webhook', 'pagerduty', 'opsgenie', 'siem')
				             AND channel NOT LIKE 'retained:%'
				               )
				         )`,
			args: []any{tenantID, c.AttestationEvidenceBefore},
		},
		"incident_executions": {
			sql: `SELECT count(*) FROM incident_executions
					       WHERE tenant_id = $1
					         AND updated_at < $2
					         AND ((created_by <> '' AND created_by NOT LIKE 'retained:%' AND created_by NOT LIKE 'erased:%')
					           OR reason <> '' OR evidence_bundle <> '' OR cardinality(failed_targets) > 0 OR cardinality(rollback_refs) > 0)`,
			args: []any{tenantID, c.AttestationEvidenceBefore},
		},
		"nhi_access_review_campaigns": {
			sql: `SELECT count(*) FROM nhi_access_review_campaigns
				       WHERE tenant_id = $1
				         AND status = 'completed'
				         AND COALESCE(completed_at, updated_at, created_at) < $2
				         AND (reviewer_subject NOT LIKE 'retained:%' OR requested_by NOT LIKE 'retained:%')`,
			args: []any{tenantID, c.ApprovalActorBefore},
		},
		"nhi_access_review_items": {
			sql: `SELECT count(*) FROM nhi_access_review_items
					       WHERE tenant_id = $1
					         AND status <> 'pending'
					         AND COALESCE(decided_at, updated_at, created_at) < $2
					         AND ((decision_by <> '' AND decision_by NOT LIKE 'retained:%' AND decision_by NOT LIKE 'erased:%')
					           OR decision_reason <> '' OR cardinality(decision_evidence_refs) > 0)`,
			args: []any{tenantID, c.ApprovalActorBefore},
		},
		"access_change_requests": {
			sql: `SELECT count(*) FROM access_change_requests
				       WHERE tenant_id = $1
				         AND status <> 'pending'
				         AND COALESCE(completed_at, updated_at, created_at) < $2
				        AND (requester_subject NOT LIKE 'retained:%' OR reason <> 'privacy-redacted' OR cardinality(evidence_refs) > 0)`,
			args: []any{tenantID, c.ApprovalActorBefore},
		},
		"access_change_request_decisions": {
			sql: `SELECT count(*) FROM access_change_request_decisions
				       WHERE tenant_id = $1
				         AND decided_at < $2
				         AND (approver_subject NOT LIKE 'retained:%' OR reason <> '' OR cardinality(decision_evidence_refs) > 0)`,
			args: []any{tenantID, c.ApprovalActorBefore},
		},
		"discovery_runs": {
			sql: `SELECT count(*) FROM discovery_runs
				       WHERE tenant_id = $1
				         AND (completed_at IS NOT NULL OR status IN ('succeeded', 'partial', 'failed', 'completed'))
				         AND COALESCE(completed_at, started_at, created_at) < $2
				         AND requested_by <> ''
				         AND requested_by NOT LIKE 'retained:%'`,
			args: []any{tenantID, c.AttestationEvidenceBefore},
		},
		"notification_routing_policies": {
			sql: `SELECT count(*) FROM notification_routing_policies
					       WHERE tenant_id = $1
					         AND updated_at < $2
					         AND ((scope_kind = 'owner' AND scope_ref <> ''
					               AND scope_ref NOT LIKE 'owner/retained:%' AND scope_ref NOT LIKE 'owner/erased:%')
					           OR (owner_ref <> '' AND owner_ref NOT LIKE 'retained:%' AND owner_ref NOT LIKE 'erased:%')
					           OR owner_email <> '')`,
			args: []any{tenantID, c.AttestationEvidenceBefore},
		},
		"remediation_playbook_runs": {
			sql: `SELECT count(*) FROM remediation_playbook_runs
					       WHERE tenant_id = $1
					         AND updated_at < $2
					         AND ((created_by <> '' AND created_by NOT LIKE 'retained:%' AND created_by NOT LIKE 'erased:%')
					           OR reason <> '' OR cardinality(evidence_refs) > 0 OR cardinality(rollback_refs) > 0)`,
			args: []any{tenantID, c.AttestationEvidenceBefore},
		},
		"compliance_report_schedules": {
			sql: `SELECT count(*) FROM compliance_report_schedules
				       WHERE tenant_id = $1
				         AND updated_at < $2
				         AND recipient_ref <> ''
				         AND recipient_ref NOT LIKE 'retained:%'`,
			args: []any{tenantID, c.AttestationEvidenceBefore},
		},
		"incident_fleet_reissuance_runs": {
			sql: `SELECT count(*) FROM incident_fleet_reissuance_runs
					       WHERE tenant_id = $1
					         AND updated_at < $2
					         AND ((created_by <> '' AND created_by NOT LIKE 'retained:%' AND created_by NOT LIKE 'erased:%')
					           OR reason <> '' OR evidence_bundle <> '' OR cardinality(failed_targets) > 0 OR cardinality(rollback_refs) > 0)`,
			args: []any{tenantID, c.AttestationEvidenceBefore},
		},
		"ownership_readiness_exceptions": {
			sql: `SELECT count(*) FROM ownership_readiness_exceptions
			       WHERE tenant_id = $1 AND expires_at < $2
			         AND (reason <> '' OR coalesce(revocation_reason, '') <> ''
			           OR (granted_by NOT LIKE 'retained:%' AND granted_by NOT LIKE 'erased:%')
			           OR (coalesce(revoked_by, '') <> '' AND revoked_by NOT LIKE 'retained:%' AND revoked_by NOT LIKE 'erased:%'))`,
			args: []any{tenantID, c.AttestationEvidenceBefore},
		},
	}
	out := make(map[string]int, len(queries))
	for k, q := range queries {
		n, err := selectCount(ctx, tx, q.sql, q.args...)
		if err != nil {
			return nil, err
		}
		out[k] = n
	}
	return out, nil
}

func selectCount(ctx context.Context, tx pgx.Tx, sql string, args ...any) (int, error) {
	var out int
	if err := tx.QueryRow(ctx, sql, args...).Scan(&out); err != nil {
		return 0, err
	}
	return out, nil
}

func countsForPrivacySelectors(sel PrivacyErasureSelectors) map[string]int {
	out := map[string]int{
		"owners":                  len(sel.OwnerIDs),
		"identities":              len(sel.IdentityIDs),
		"certificates":            len(sel.CertificateFingerprints) + len(sel.CertificateRefs),
		"ssh_keys":                len(sel.SSHKeyIDs),
		"attestations":            len(sel.AttestationIDs),
		"approval_requests":       len(sel.ApprovalRequests),
		"approvals":               len(sel.Approvals),
		"profiles":                len(sel.ProfileIDs),
		"agents":                  len(sel.AgentIDs),
		"agent_offboard_actors":   len(sel.AgentOffboardActorIDs),
		"agent_offboard_reasons":  len(sel.AgentOffboardReasonIDs),
		"api_tokens":              0, // filled by subject_ref update at projection time; rows are not enumerated in the event.
		"tenant_members":          0,
		"code_signing_operations": len(sel.CodeSigningOperationIDs),
		"read_models":             len(sel.ReadModels),
	}
	for _, rm := range sel.ReadModels {
		out[rm.Table]++
	}
	return out
}
