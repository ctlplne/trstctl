// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/store"
)

type privacySubjectErasureRequest struct {
	Subject string `json:"subject"`
	Reason  string `json:"reason"`
}

// privacySubjectExportRequest names the data subject to export (PRIVACY-004
// data-subject access/portability). It is a read: it collects, but does not modify,
// the subject's records across the privacy catalog.
type privacySubjectExportRequest struct {
	Subject string `json:"subject"`
}

type privacyArchiveErasureAttestationRequest struct {
	Subject      string     `json:"subject"`
	ArtifactType string     `json:"artifact_type"`
	ArtifactURI  string     `json:"artifact_uri"`
	Action       string     `json:"action"`
	Reason       string     `json:"reason"`
	EvidenceRefs []string   `json:"evidence_refs"`
	HeldUntil    *time.Time `json:"held_until,omitempty"`
}

type privacySubjectErasureResponse struct {
	SubjectRef     string                        `json:"subject_ref"`
	RequestedByRef string                        `json:"requested_by_ref,omitempty"`
	Reason         string                        `json:"reason,omitempty"`
	Selectors      store.PrivacyErasureSelectors `json:"selectors"`
	Counts         map[string]int                `json:"counts"`
	ErasedAt       time.Time                     `json:"erased_at"`
}

type privacySubjectErasurePreviewResponse struct {
	Capability             string                       `json:"capability"`
	Operation              string                       `json:"operation"`
	Ready                  bool                         `json:"ready"`
	EffectFree             bool                         `json:"effect_free"`
	RequestFingerprint     string                       `json:"request_fingerprint"`
	RequiredPermission     string                       `json:"required_permission"`
	NormalizedRequest      privacySubjectErasureRequest `json:"normalized_request"`
	SubjectRef             string                       `json:"subject_ref"`
	Counts                 map[string]int               `json:"counts"`
	TotalRecords           int                          `json:"total_records"`
	ArchiveAttestations    int                          `json:"archive_attestations"`
	ActiveLegalHolds       int                          `json:"active_legal_holds"`
	Prerequisites          []string                     `json:"prerequisites"`
	Blockers               []string                     `json:"blockers"`
	Warnings               []string                     `json:"warnings"`
	PreviewWrites          []string                     `json:"preview_writes"`
	PreviewExternalEffects []string                     `json:"preview_external_effects"`
	ExecuteWrites          []string                     `json:"execute_writes"`
	ExecuteExternalEffects []string                     `json:"execute_external_effects"`
	RecoverySteps          []string                     `json:"recovery_steps"`
	VerificationSteps      []string                     `json:"verification_steps"`
	SecretDataHandling     string                       `json:"secret_data_handling"`
}

type privacyRetentionPreviewResponse struct {
	Capability             string                          `json:"capability"`
	Operation              string                          `json:"operation"`
	Ready                  bool                            `json:"ready"`
	EffectFree             bool                            `json:"effect_free"`
	RequestFingerprint     string                          `json:"request_fingerprint"`
	RequiredPermission     string                          `json:"required_permission"`
	ReviewedAt             time.Time                       `json:"reviewed_at"`
	Cutoffs                privacyRetentionCutoffsResponse `json:"cutoffs"`
	Counts                 map[string]int                  `json:"counts"`
	TotalRecords           int                             `json:"total_records"`
	Prerequisites          []string                        `json:"prerequisites"`
	Blockers               []string                        `json:"blockers"`
	Warnings               []string                        `json:"warnings"`
	PreviewWrites          []string                        `json:"preview_writes"`
	PreviewExternalEffects []string                        `json:"preview_external_effects"`
	ExecuteWrites          []string                        `json:"execute_writes"`
	ExecuteExternalEffects []string                        `json:"execute_external_effects"`
	RecoverySteps          []string                        `json:"recovery_steps"`
	VerificationSteps      []string                        `json:"verification_steps"`
	SecretDataHandling     string                          `json:"secret_data_handling"`
}

type privacySubjectErasureListResponse struct {
	Items      []privacySubjectErasureResponse `json:"items"`
	NextCursor string                          `json:"next_cursor,omitempty"`
}

type privacyCatalogResponse struct {
	Items []privacy.CatalogEntry `json:"items"`
}

type privacyRetentionCutoffsResponse struct {
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

type privacyRetentionRunResponse struct {
	RunID          string                          `json:"run_id"`
	RequestedByRef string                          `json:"requested_by_ref,omitempty"`
	Cutoffs        privacyRetentionCutoffsResponse `json:"cutoffs"`
	Counts         map[string]int                  `json:"counts"`
	EnforcedAt     time.Time                       `json:"enforced_at"`
}

type privacyRetentionRunListResponse struct {
	Items      []privacyRetentionRunResponse `json:"items"`
	NextCursor string                        `json:"next_cursor,omitempty"`
}

type privacyArchiveErasureAttestationResponse struct {
	AttestationID  string     `json:"attestation_id"`
	SubjectRef     string     `json:"subject_ref"`
	RequestedByRef string     `json:"requested_by_ref,omitempty"`
	ArtifactType   string     `json:"artifact_type"`
	ArtifactURI    string     `json:"artifact_uri,omitempty"`
	Action         string     `json:"action"`
	Reason         string     `json:"reason,omitempty"`
	EvidenceRefs   []string   `json:"evidence_refs"`
	HeldUntil      *time.Time `json:"held_until,omitempty"`
	AttestedAt     time.Time  `json:"attested_at"`
}

type privacyArchiveErasureAttestationListResponse struct {
	Items      []privacyArchiveErasureAttestationResponse `json:"items"`
	NextCursor string                                     `json:"next_cursor,omitempty"`
}

func toPrivacySubjectErasureResponse(e store.PrivacySubjectErasure) privacySubjectErasureResponse {
	counts := e.Counts
	if counts == nil {
		counts = map[string]int{}
	}
	return privacySubjectErasureResponse{
		SubjectRef:     e.SubjectRef,
		RequestedByRef: e.RequestedByRef,
		Reason:         e.Reason,
		Selectors:      e.Selectors,
		Counts:         counts,
		ErasedAt:       e.ErasedAt,
	}
}

func toPrivacyRetentionRunResponse(r store.PrivacyRetentionRun) privacyRetentionRunResponse {
	counts := r.Counts
	if counts == nil {
		counts = map[string]int{}
	}
	return privacyRetentionRunResponse{
		RunID:          r.RunID,
		RequestedByRef: r.RequestedByRef,
		Cutoffs: privacyRetentionCutoffsResponse{
			OwnerInactiveBefore:       r.Cutoffs.OwnerInactiveBefore,
			IdentityTerminalBefore:    r.Cutoffs.IdentityTerminalBefore,
			CertificateTerminalBefore: r.Cutoffs.CertificateTerminalBefore,
			SSHStaleBefore:            r.Cutoffs.SSHStaleBefore,
			AccessTerminalBefore:      r.Cutoffs.AccessTerminalBefore,
			ApprovalActorBefore:       r.Cutoffs.ApprovalActorBefore,
			ProfileActorBefore:        r.Cutoffs.ProfileActorBefore,
			AttestationEvidenceBefore: r.Cutoffs.AttestationEvidenceBefore,
			AgentStaleBefore:          r.Cutoffs.AgentStaleBefore,
		},
		Counts:     counts,
		EnforcedAt: r.EnforcedAt,
	}
}

func privacyCountTotal(counts map[string]int) int {
	total := 0
	for _, count := range counts {
		total += count
	}
	return total
}

// privacySubjectExportCountTotal counts each matched record once. Subject
// exports expose both an aggregate read_models count and per-table read-model
// breakdowns; summing every map value would count those rows twice.
func privacySubjectExportCountTotal(counts map[string]int) int {
	total := 0
	for _, class := range []string{
		"owners", "identities", "certificates", "ssh_keys", "attestations",
		"tenant_members", "api_tokens", "approvals", "read_models",
	} {
		total += counts[class]
	}
	return total
}

func normalizePrivacySubjectErasureRequest(req privacySubjectErasureRequest) (privacySubjectErasureRequest, error) {
	req.Subject = strings.TrimSpace(req.Subject)
	req.Reason = strings.TrimSpace(req.Reason)
	if req.Subject == "" {
		return privacySubjectErasureRequest{}, errStatus(http.StatusBadRequest, "subject is required")
	}
	return req, nil
}

// previewPrivacySubjectErasure is a structured read. It shows the exact records
// currently matched by the same tenant-scoped selector used by erasure, plus
// archive disposition evidence. It emits no event and changes no row.
func (a *API) previewPrivacySubjectErasure(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	var req privacySubjectErasureRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	normalized, err := normalizePrivacySubjectErasureRequest(req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	export, err := a.store.SelectPrivacySubjectExport(r.Context(), tenantID, normalized.Subject)
	if err != nil {
		a.writeError(w, err)
		return
	}
	attestations, err := a.listAllPrivacyArchiveAttestations(r.Context(), tenantID, export.SubjectRef)
	if err != nil {
		a.writeError(w, err)
		return
	}
	now := time.Now().UTC()
	activeLegalHolds := 0
	for _, attestation := range attestations {
		if attestation.Action == "legal_hold" && (attestation.HeldUntil == nil || attestation.HeldUntil.After(now)) {
			activeLegalHolds++
		}
	}
	fingerprintBody, err := json.Marshal(struct {
		Domain           string                                   `json:"domain"`
		TenantID         string                                   `json:"tenant_id"`
		Request          privacySubjectErasureRequest             `json:"request"`
		SubjectRef       string                                   `json:"subject_ref"`
		Counts           map[string]int                           `json:"counts"`
		Attestations     []store.PrivacyArchiveErasureAttestation `json:"attestations"`
		ActiveLegalHolds int                                      `json:"active_legal_holds"`
	}{
		Domain: "trstctl.api.privacy-subject-erasure-preview.v1", TenantID: tenantID,
		Request: normalized, SubjectRef: export.SubjectRef, Counts: export.Counts, Attestations: attestations,
		ActiveLegalHolds: activeLegalHolds,
	})
	if err != nil {
		a.writeError(w, err)
		return
	}
	warnings := []string{"Completed direct-data erasure is irreversible. Export any evidence you are allowed to retain before execution."}
	if len(attestations) == 0 {
		warnings = append(warnings, "No backup or signed-audit-archive disposition is recorded for this subject. Direct operational erasure can proceed, but archive removal must be evidenced separately.")
	}
	if activeLegalHolds > 0 {
		warnings = append(warnings, "An active archive legal hold preserves the held artifact. This direct operational erasure does not remove or override that hold.")
	}
	a.writeJSON(w, http.StatusOK, privacySubjectErasurePreviewResponse{
		Capability: "F79", Operation: "erase_subject", Ready: true, EffectFree: true,
		RequestFingerprint: crypto.SHA256Hex(fingerprintBody), RequiredPermission: string(authz.PrivacyWrite),
		NormalizedRequest: normalized, SubjectRef: export.SubjectRef, Counts: export.Counts,
		TotalRecords: privacySubjectExportCountTotal(export.Counts), ArchiveAttestations: len(attestations), ActiveLegalHolds: activeLegalHolds,
		Prerequisites: []string{
			"Confirm the data-subject identifier and the tenant boundary shown in this review.",
			"Export any records that policy or law requires before irreversible direct-data erasure.",
			"Record backup or signed-audit-archive disposition separately when archived copies exist.",
		},
		Blockers: []string{}, Warnings: warnings, PreviewWrites: []string{}, PreviewExternalEffects: []string{},
		ExecuteWrites: []string{
			"Prepare a tenant-scoped crash-recovery record and rewrite affected direct operational data to a non-PII placeholder.",
			"Append one immutable privacy.subject.erased event and project subject-erasure evidence.",
			"Revoke subject-bound API tokens and preserve sanitized audit continuity.",
		},
		ExecuteExternalEffects: []string{},
		RecoverySteps: []string{
			"If the request is interrupted, retry the exact request with the same Idempotency-Key; the original result is returned instead of erasing twice.",
			"At startup, trstctl completes any prepared rewrite before normal service resumes.",
			"There is no rollback after completion. Use the pre-erasure export and archive disposition evidence for retained records.",
		},
		VerificationSteps: []string{
			"List subject-erasure evidence and match subject_ref, reason, counts, and erased_at.",
			"Export the same subject again and confirm direct operational record counts are zero or only policy-preserved evidence remains.",
			"Search the audit feed for the raw subject and confirm it no longer appears while the pseudonymized erasure event verifies.",
		},
		SecretDataHandling: "The authorized review may echo the submitted data-subject identifier. It never reads or returns token hashes, secret values, private keys, or credential material; the fingerprint is tenant-bound.",
	})
}

func (a *API) listAllPrivacyArchiveAttestations(ctx context.Context, tenantID, subjectRef string) ([]store.PrivacyArchiveErasureAttestation, error) {
	const pageSize = 500
	after := ""
	var out []store.PrivacyArchiveErasureAttestation
	for {
		page, err := a.store.ListPrivacyArchiveErasureAttestationsPage(ctx, tenantID, subjectRef, after, pageSize)
		if err != nil {
			return nil, err
		}
		out = append(out, page...)
		if len(page) < pageSize {
			return out, nil
		}
		after = page[len(page)-1].AttestationID
	}
}

// previewPrivacyRetention resolves the effective tenant policy and performs the
// same read-only count selection as enforcement. It does not reserve a run ID,
// append an event, or pseudonymize a row.
func (a *API) previewPrivacyRetention(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	policy, err := privacy.ResolveRetentionPolicy(r.Context(), a.privacyRetentionSource, tenantID, a.privacyRetentionPolicy)
	if err != nil {
		a.writeError(w, err)
		return
	}
	reviewedAt := time.Now().UTC()
	selected, err := a.store.SelectPrivacyRetention(r.Context(), tenantID, "00000000-0000-0000-0000-000000000000", policy, reviewedAt)
	if err != nil {
		a.writeError(w, err)
		return
	}
	view := toPrivacyRetentionRunResponse(selected)
	fingerprintBody, err := json.Marshal(struct {
		Domain     string                          `json:"domain"`
		TenantID   string                          `json:"tenant_id"`
		ReviewedAt time.Time                       `json:"reviewed_at"`
		Cutoffs    privacyRetentionCutoffsResponse `json:"cutoffs"`
		Counts     map[string]int                  `json:"counts"`
	}{
		Domain: "trstctl.api.privacy-retention-preview.v1", TenantID: tenantID,
		ReviewedAt: reviewedAt, Cutoffs: view.Cutoffs, Counts: view.Counts,
	})
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, privacyRetentionPreviewResponse{
		Capability: "F79", Operation: "enforce_retention", Ready: true, EffectFree: true,
		RequestFingerprint: crypto.SHA256Hex(fingerprintBody), RequiredPermission: string(authz.PrivacyWrite),
		ReviewedAt: reviewedAt, Cutoffs: view.Cutoffs, Counts: view.Counts, TotalRecords: privacyCountTotal(view.Counts),
		Prerequisites: []string{
			"Review the effective tenant retention cutoffs and affected record classes.",
			"Confirm required legal holds and archive policies are recorded before pseudonymizing eligible operational rows.",
		},
		Blockers: []string{}, Warnings: []string{"Counts describe the reviewed instant. Re-review if time passes or tenant data changes before execution."},
		PreviewWrites: []string{}, PreviewExternalEffects: []string{},
		ExecuteWrites: []string{
			"Append one tenant-scoped privacy.retention.enforced event containing cutoffs and aggregate counts, never raw personal values.",
			"Project deterministic pseudonyms into eligible non-audit operational rows while retaining verifiable security evidence.",
		},
		ExecuteExternalEffects: []string{},
		RecoverySteps: []string{
			"Retry an interrupted request with the same Idempotency-Key; duplicate mutation is prevented.",
			"Run a fresh review after any policy correction, then execute a new run. Completed pseudonymization has no rollback.",
		},
		VerificationSteps: []string{
			"List retention runs and match the enforced cutoffs and aggregate counts.",
			"Run a new effect-free review; eligible counts should fall to zero unless newer rows crossed a cutoff.",
			"Verify the immutable privacy.retention.enforced audit event contains no raw data-subject value.",
		},
		SecretDataHandling: "Preview returns tenant-scoped aggregate counts and policy cutoffs only. It never returns raw matched values, token hashes, secrets, private keys, or credential material.",
	})
}

func toPrivacyArchiveErasureAttestationResponse(a store.PrivacyArchiveErasureAttestation) privacyArchiveErasureAttestationResponse {
	refs := a.EvidenceRefs
	if refs == nil {
		refs = []string{}
	}
	return privacyArchiveErasureAttestationResponse{
		AttestationID:  a.AttestationID,
		SubjectRef:     a.SubjectRef,
		RequestedByRef: a.RequestedByRef,
		ArtifactType:   a.ArtifactType,
		ArtifactURI:    a.ArtifactURI,
		Action:         a.Action,
		Reason:         a.Reason,
		EvidenceRefs:   refs,
		HeldUntil:      a.HeldUntil,
		AttestedAt:     a.AttestedAt,
	}
}

//trstctl:mutation
func (a *API) erasePrivacySubject(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	var req privacySubjectErasureRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	req, err := normalizePrivacySubjectErasureRequest(req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	binding, err := privacySubjectErasureRequestBinding(r, req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateDurableBound(w, r, idempotencyKey, binding, func(ctx context.Context, tenantID string) (int, any, error) {
		erasure, err := a.orch.ErasePrivacySubjectBound(
			ctx, tenantID, req.Subject, req.Reason, idempotencyKey, binding,
		)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, toPrivacySubjectErasureResponse(erasure), nil
	})
}

// privacySubjectErasureRequestBinding prevents one raw Idempotency-Key from
// replaying a successful erasure for another caller, route, subject, or reason.
// Only the non-secret digest is persisted; the canonical bytes are wiped.
func privacySubjectErasureRequestBinding(r *http.Request, command privacySubjectErasureRequest) (string, error) {
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		return "", err
	}
	escapedPath := ""
	if r.URL != nil {
		escapedPath = r.URL.EscapedPath()
	}
	material, err := json.Marshal(struct {
		Domain      string                       `json:"domain"`
		Principal   string                       `json:"principal"`
		Method      string                       `json:"method"`
		EscapedPath string                       `json:"escaped_path"`
		Command     privacySubjectErasureRequest `json:"command"`
	}{
		Domain:      "trstctl.privacy-subject-erasure-command.v1",
		Principal:   principal,
		Method:      r.Method,
		EscapedPath: escapedPath,
		Command:     command,
	})
	if err != nil {
		return "", err
	}
	defer secret.Wipe(material)
	return crypto.SHA256Hex(material), nil
}

//trstctl:mutation
func (a *API) enforcePrivacyRetention(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		policy, err := privacy.ResolveRetentionPolicy(ctx, a.privacyRetentionSource, tenantID, a.privacyRetentionPolicy)
		if err != nil {
			return 0, nil, err
		}
		run, err := a.orch.EnforcePrivacyRetention(ctx, tenantID, policy, time.Now().UTC())
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, toPrivacyRetentionRunResponse(run), nil
	})
}

//trstctl:mutation
func (a *API) attestPrivacyArchiveErasure(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req privacyArchiveErasureAttestationRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		req.Subject = strings.TrimSpace(req.Subject)
		req.ArtifactType = strings.TrimSpace(req.ArtifactType)
		req.Action = strings.TrimSpace(req.Action)
		if req.Subject == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "subject is required")
		}
		if req.ArtifactType != "backup" && req.ArtifactType != "signed_audit_archive" {
			return 0, nil, errStatus(http.StatusBadRequest, "artifact_type must be backup or signed_audit_archive")
		}
		if req.Action != "deleted" && req.Action != "legal_hold" && req.Action != "cryptographic_shred" {
			return 0, nil, errStatus(http.StatusBadRequest, "action must be deleted, legal_hold, or cryptographic_shred")
		}
		att, err := a.orch.AttestPrivacyArchiveErasure(ctx, tenantID, req.Subject, store.PrivacyArchiveErasureAttestation{
			ArtifactType: req.ArtifactType,
			ArtifactURI:  req.ArtifactURI,
			Action:       req.Action,
			Reason:       req.Reason,
			EvidenceRefs: req.EvidenceRefs,
			HeldUntil:    req.HeldUntil,
		})
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, toPrivacyArchiveErasureAttestationResponse(att), nil
	})
}

func (a *API) listPrivacySubjectErasures(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	limit, err := pageLimit(r)
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, err.Error()))
		return
	}
	after := ""
	if c := r.URL.Query().Get("cursor"); c != "" {
		after, err = decodeStringCursor(c)
		if err != nil {
			a.writeError(w, errStatus(http.StatusBadRequest, "invalid cursor"))
			return
		}
	}
	erasures, err := a.store.ListPrivacySubjectErasuresPage(r.Context(), tenantID, after, limit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]privacySubjectErasureResponse, 0, len(erasures))
	for _, erasure := range erasures {
		items = append(items, toPrivacySubjectErasureResponse(erasure))
	}
	next := ""
	if len(erasures) == limit {
		next = encodeStringCursor(erasures[len(erasures)-1].SubjectRef)
	}
	a.writeJSON(w, http.StatusOK, privacySubjectErasureListResponse{Items: items, NextCursor: next})
}

func (a *API) listPrivacyRetentionRuns(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	limit, err := pageLimit(r)
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, err.Error()))
		return
	}
	after := ""
	if c := r.URL.Query().Get("cursor"); c != "" {
		after, err = decodeStringCursor(c)
		if err != nil {
			a.writeError(w, errStatus(http.StatusBadRequest, "invalid cursor"))
			return
		}
	}
	runs, err := a.store.ListPrivacyRetentionRunsPage(r.Context(), tenantID, after, limit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]privacyRetentionRunResponse, 0, len(runs))
	for _, run := range runs {
		items = append(items, toPrivacyRetentionRunResponse(run))
	}
	next := ""
	if len(runs) == limit {
		next = encodeStringCursor(runs[len(runs)-1].RunID)
	}
	a.writeJSON(w, http.StatusOK, privacyRetentionRunListResponse{Items: items, NextCursor: next})
}

func (a *API) listPrivacyArchiveErasureAttestations(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	limit, err := pageLimit(r)
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, err.Error()))
		return
	}
	after := ""
	if c := r.URL.Query().Get("cursor"); c != "" {
		after, err = decodeStringCursor(c)
		if err != nil {
			a.writeError(w, errStatus(http.StatusBadRequest, "invalid cursor"))
			return
		}
	}
	subjectRef := strings.TrimSpace(r.URL.Query().Get("subject_ref"))
	atts, err := a.store.ListPrivacyArchiveErasureAttestationsPage(r.Context(), tenantID, subjectRef, after, limit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]privacyArchiveErasureAttestationResponse, 0, len(atts))
	for _, att := range atts {
		items = append(items, toPrivacyArchiveErasureAttestationResponse(att))
	}
	next := ""
	if len(atts) == limit {
		next = encodeStringCursor(atts[len(atts)-1].AttestationID)
	}
	a.writeJSON(w, http.StatusOK, privacyArchiveErasureAttestationListResponse{Items: items, NextCursor: next})
}

// exportPrivacySubject answers a data-subject access/portability request
// (PRIVACY-004): it collects every record tied to the named subject across the
// privacy catalog (owners, identities, certificates, SSH keys, attestations, tenant
// members, API tokens, dual-control approvals) for the caller's tenant only (AN-1,
// under RLS). It is a READ — no state changes, so it carries no Idempotency-Key — and
// it returns no secret material (API-token hashes are never included). It is the
// inverse of the existing subject erasure: erase removes the subject's data, export
// discloses it.
func (a *API) exportPrivacySubject(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	var req privacySubjectExportRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	req.Subject = strings.TrimSpace(req.Subject)
	if req.Subject == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "subject is required"))
		return
	}
	export, err := a.store.SelectPrivacySubjectExport(r.Context(), tenantID, req.Subject)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, export)
}

func (a *API) getPrivacyCatalog(w http.ResponseWriter, r *http.Request) {
	a.writeJSON(w, http.StatusOK, privacyCatalogResponse{Items: privacy.Catalog()})
}

func encodeStringCursor(value string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(value))
}

func decodeStringCursor(cursor string) (string, error) {
	b, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return "", err
	}
	if len(b) == 0 {
		return "", errors.New("empty cursor")
	}
	return string(b), nil
}
