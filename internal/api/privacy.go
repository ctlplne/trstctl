// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

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
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req privacySubjectErasureRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		req.Subject = strings.TrimSpace(req.Subject)
		req.Reason = strings.TrimSpace(req.Reason)
		if req.Subject == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "subject is required")
		}
		erasure, err := a.orch.ErasePrivacySubject(ctx, tenantID, req.Subject, req.Reason)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, toPrivacySubjectErasureResponse(erasure), nil
	})
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
