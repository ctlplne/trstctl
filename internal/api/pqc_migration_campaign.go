// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

const (
	pqcCampaignClosureFormat = "trstctl.pqc-migration-campaign-closure.v1"
	campaignExecutionNote    = "Campaign tracking and evidence work without a license. Automated fleet execution is unavailable in this edition; record work performed manually or by another tool."
)

// PQCCampaignClosureSigner is the crypto-free API-side view of the persistent
// audit signing key. The implementation remains inside internal/crypto.
type PQCCampaignClosureSigner interface {
	SignArtifact(string, []byte) (string, error)
	PublicJWKS() ([]byte, error)
}

type pqcCampaignResponse struct {
	ID                          string                       `json:"id"`
	TenantID                    string                       `json:"tenant_id"`
	Name                        string                       `json:"name"`
	Owner                       string                       `json:"owner"`
	Deadline                    time.Time                    `json:"deadline"`
	Wave                        string                       `json:"wave"`
	ReadinessCriteria           []string                     `json:"readiness_criteria"`
	ReadinessStatus             string                       `json:"readiness_status"`
	ReadinessEvidenceRefs       []string                     `json:"readiness_evidence_refs"`
	Status                      string                       `json:"status"`
	FindingCount                int                          `json:"finding_count"`
	PendingCount                int                          `json:"pending_count"`
	RemediatedCount             int                          `json:"remediated_count"`
	ExceptedCount               int                          `json:"excepted_count"`
	AutomatedExecutionAvailable bool                         `json:"automated_execution_available"`
	AutomatedExecutionNote      string                       `json:"automated_execution_note"`
	CreatedAt                   time.Time                    `json:"created_at"`
	UpdatedAt                   time.Time                    `json:"updated_at"`
	ClosedAt                    *time.Time                   `json:"closed_at,omitempty"`
	Findings                    []pqcCampaignFindingResponse `json:"findings,omitempty"`
	Closure                     *pqcCampaignClosureResponse  `json:"closure,omitempty"`
}

type pqcCampaignFindingResponse struct {
	FindingID         string     `json:"finding_id"`
	FindingDigest     string     `json:"finding_digest"`
	ReadinessDigest   string     `json:"readiness_digest,omitempty"`
	Kind              string     `json:"kind"`
	Location          string     `json:"location"`
	Algorithm         string     `json:"algorithm,omitempty"`
	KeyBits           int        `json:"key_bits,omitempty"`
	Protocol          string     `json:"protocol,omitempty"`
	Cipher            string     `json:"cipher,omitempty"`
	Disposition       string     `json:"disposition"`
	RemediationMethod string     `json:"remediation_method,omitempty"`
	DispositionReason string     `json:"disposition_reason,omitempty"`
	EvidenceRefs      []string   `json:"evidence_refs"`
	EvidenceDigests   []string   `json:"evidence_digests"`
	DispositionedAt   *time.Time `json:"dispositioned_at,omitempty"`
}

type pqcCampaignClosureResponse struct {
	Format        string          `json:"format"`
	SignedClosure string          `json:"signed_closure"`
	PublicJWKS    json.RawMessage `json:"public_jwks"`
}

type pqcCampaignReadinessRequest struct {
	Status       string   `json:"status"`
	EvidenceRefs []string `json:"evidence_refs"`
}

type pqcCampaignCloseRequest struct {
	ClosedBy string `json:"closed_by,omitempty"`
}

type pqcCampaignClosurePayload struct {
	Format                string                       `json:"format"`
	CampaignID            string                       `json:"campaign_id"`
	TenantID              string                       `json:"tenant_id"`
	Name                  string                       `json:"name"`
	Owner                 string                       `json:"owner"`
	Deadline              time.Time                    `json:"deadline"`
	Wave                  string                       `json:"wave"`
	ReadinessStatus       string                       `json:"readiness_status"`
	ReadinessEvidenceRefs []string                     `json:"readiness_evidence_refs"`
	CreatedAt             time.Time                    `json:"created_at"`
	ClosedAt              time.Time                    `json:"closed_at"`
	ClosedBy              string                       `json:"closed_by"`
	Findings              []pqcCampaignFindingResponse `json:"findings"`
}

//trstctl:mutation
func (a *API) startPQCMigrationCampaign(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		if a.orch == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "PQC migration campaigns are not configured")
		}
		var req orchestrator.PQCMigrationCampaignStartRequest
		if err := decodePQCCampaignRequest(r, &req); err != nil {
			return 0, nil, err
		}
		campaign, err := a.orch.StartPQCMigrationCampaign(ctx, tenantID, req)
		if err != nil {
			return 0, nil, errStatus(http.StatusBadRequest, err.Error())
		}
		return http.StatusCreated, toPQCCampaignResponse(campaign, true), nil
	})
}

func (a *API) listPQCMigrationCampaigns(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	limit, after, err := a.pageParams(r)
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, err.Error()))
		return
	}
	rows, err := a.store.ListPQCMigrationCampaignsPage(r.Context(), tenantID, after, limit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]pqcCampaignResponse, 0, len(rows))
	for _, campaign := range rows {
		items = append(items, toPQCCampaignResponse(campaign, false))
	}
	next := ""
	if len(rows) == limit {
		next = encodeCursor(rows[len(rows)-1].ID)
	}
	a.writeJSON(w, http.StatusOK, listResponse{Items: items, NextCursor: next})
}

func (a *API) getPQCMigrationCampaign(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	campaign, err := a.store.GetPQCMigrationCampaign(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, toPQCCampaignResponse(campaign, true))
}

//trstctl:mutation
func (a *API) updatePQCMigrationCampaign(w http.ResponseWriter, r *http.Request) {
	campaignID := r.PathValue("id")
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		if a.orch == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "PQC migration campaigns are not configured")
		}
		var req orchestrator.PQCMigrationCampaignUpdateRequest
		if err := decodePQCCampaignRequest(r, &req); err != nil {
			return 0, nil, err
		}
		campaign, err := a.orch.UpdatePQCMigrationCampaign(ctx, tenantID, campaignID, req)
		if err != nil {
			return 0, nil, mapPQCCampaignError(err)
		}
		return http.StatusOK, toPQCCampaignResponse(campaign, true), nil
	})
}

//trstctl:mutation
func (a *API) setPQCMigrationCampaignReadiness(w http.ResponseWriter, r *http.Request) {
	campaignID := r.PathValue("id")
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		if a.orch == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "PQC migration campaigns are not configured")
		}
		var req pqcCampaignReadinessRequest
		if err := decodePQCCampaignRequest(r, &req); err != nil {
			return 0, nil, err
		}
		campaign, err := a.orch.UpdatePQCMigrationCampaign(ctx, tenantID, campaignID, orchestrator.PQCMigrationCampaignUpdateRequest{
			ReadinessStatus: req.Status, ReadinessEvidenceRefs: req.EvidenceRefs,
		})
		if err != nil {
			return 0, nil, mapPQCCampaignError(err)
		}
		return http.StatusOK, toPQCCampaignResponse(campaign, true), nil
	})
}

//trstctl:mutation
func (a *API) dispositionPQCMigrationFinding(w http.ResponseWriter, r *http.Request) {
	campaignID, findingID := r.PathValue("id"), r.PathValue("finding_id")
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		if a.orch == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "PQC migration campaigns are not configured")
		}
		var req orchestrator.PQCMigrationFindingDispositionRequest
		if err := decodePQCCampaignRequest(r, &req); err != nil {
			return 0, nil, err
		}
		campaign, err := a.orch.DispositionPQCMigrationFinding(ctx, tenantID, campaignID, findingID, req)
		if err != nil {
			return 0, nil, mapPQCCampaignError(err)
		}
		return http.StatusOK, toPQCCampaignResponse(campaign, true), nil
	})
}

//trstctl:mutation
func (a *API) closePQCMigrationCampaign(w http.ResponseWriter, r *http.Request) {
	campaignID := r.PathValue("id")
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		if a.orch == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "PQC migration campaigns are not configured")
		}
		if a.pqcCampaignSigner == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "PQC campaign closure signing is not configured")
		}
		var req pqcCampaignCloseRequest
		if err := decodePQCCampaignRequest(r, &req); err != nil {
			return 0, nil, err
		}
		closedBy := strings.TrimSpace(req.ClosedBy)
		if closedBy == "" {
			if actor, ok := events.ActorFromContext(ctx); ok {
				closedBy = strings.TrimSpace(actor.Subject)
			}
		}
		if closedBy == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "closed_by is required")
		}
		campaign, err := a.orch.ClosePQCMigrationCampaign(ctx, tenantID, campaignID, func(campaign store.PQCMigrationCampaign) (projections.PQCMigrationCampaignClosed, error) {
			closedAt := time.Now().UTC()
			closurePayload := pqcCampaignClosurePayload{
				Format: pqcCampaignClosureFormat, CampaignID: campaign.ID, TenantID: campaign.TenantID,
				Name: campaign.Name, Owner: campaign.OwnerRef, Deadline: campaign.Deadline,
				Wave: campaign.Wave, ReadinessStatus: campaign.ReadinessStatus,
				ReadinessEvidenceRefs: append([]string(nil), campaign.ReadinessEvidenceRefs...),
				CreatedAt:             campaign.CreatedAt, ClosedAt: closedAt, ClosedBy: closedBy,
				Findings: toPQCCampaignFindings(campaign.Findings),
			}
			payload, err := json.Marshal(closurePayload)
			if err != nil {
				return projections.PQCMigrationCampaignClosed{}, err
			}
			signed, err := a.pqcCampaignSigner.SignArtifact(jose.ArtifactPQCCampaignClosure, payload)
			if err != nil {
				return projections.PQCMigrationCampaignClosed{}, errStatus(http.StatusServiceUnavailable, "sign PQC campaign closure: "+err.Error())
			}
			jwks, err := a.pqcCampaignSigner.PublicJWKS()
			if err != nil {
				return projections.PQCMigrationCampaignClosed{}, errStatus(http.StatusServiceUnavailable, "publish PQC campaign verifier: "+err.Error())
			}
			return projections.PQCMigrationCampaignClosed{
				CampaignID: campaign.ID, SignedJWS: signed, PublicJWKS: jwks,
				ClosedBy: closedBy, ClosedAt: closedAt,
			}, nil
		})
		if err != nil {
			return 0, nil, mapPQCCampaignError(err)
		}
		return http.StatusOK, toPQCCampaignResponse(campaign, true), nil
	})
}

func (a *API) getPQCMigrationCampaignEvidence(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	campaign, err := a.store.GetPQCMigrationCampaign(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	if campaign.Status != "closed" || campaign.ClosureJWS == "" || len(campaign.ClosureJWKS) == 0 {
		a.writeError(w, errStatus(http.StatusConflict, "PQC migration campaign has no signed closure evidence"))
		return
	}
	a.writeJSON(w, http.StatusOK, pqcCampaignClosureResponse{
		Format: pqcCampaignClosureFormat, SignedClosure: campaign.ClosureJWS,
		PublicJWKS: campaign.ClosureJWKS,
	})
}

func decodePQCCampaignRequest(r *http.Request, dst any) error {
	var raw json.RawMessage
	if err := decodeJSON(r, &raw); err != nil {
		return errWithStatus(http.StatusBadRequest, err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return errStatus(http.StatusBadRequest, "request body must be a JSON object")
	}
	if containsInlineSecret(obj) {
		return errStatus(http.StatusBadRequest, "PQC migration campaigns accept evidence references and digests, not inline credential or token values")
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return errStatus(http.StatusBadRequest, "invalid PQC migration campaign request")
	}
	return nil
}

func mapPQCCampaignError(err error) error {
	var ae *apiError
	switch {
	case errors.As(err, &ae):
		return ae
	case store.IsNotFound(err):
		return errStatus(http.StatusNotFound, "PQC migration campaign or finding not found")
	case errors.Is(err, store.ErrPQCCampaignClosed), errors.Is(err, store.ErrPQCCampaignExists), errors.Is(err, store.ErrPQCCampaignNotReady), errors.Is(err, store.ErrPQCCampaignTopologyStale):
		return errStatus(http.StatusConflict, err.Error())
	default:
		return errStatus(http.StatusBadRequest, err.Error())
	}
}

func toPQCCampaignResponse(campaign store.PQCMigrationCampaign, includeFindings bool) pqcCampaignResponse {
	resp := pqcCampaignResponse{
		ID: campaign.ID, TenantID: campaign.TenantID, Name: campaign.Name,
		Owner: campaign.OwnerRef, Deadline: campaign.Deadline, Wave: campaign.Wave,
		ReadinessCriteria:     nonNilAPIStrings(campaign.ReadinessCriteria),
		ReadinessStatus:       campaign.ReadinessStatus,
		ReadinessEvidenceRefs: nonNilAPIStrings(campaign.ReadinessEvidenceRefs),
		Status:                campaign.Status, FindingCount: campaign.FindingCount,
		PendingCount: campaign.PendingCount, RemediatedCount: campaign.RemediatedCount,
		ExceptedCount: campaign.ExceptedCount, AutomatedExecutionAvailable: false,
		AutomatedExecutionNote: campaignExecutionNote, CreatedAt: campaign.CreatedAt,
		UpdatedAt: campaign.UpdatedAt, ClosedAt: campaign.ClosedAt,
	}
	if includeFindings {
		resp.Findings = toPQCCampaignFindings(campaign.Findings)
	}
	if campaign.ClosureJWS != "" && len(campaign.ClosureJWKS) > 0 {
		resp.Closure = &pqcCampaignClosureResponse{
			Format: pqcCampaignClosureFormat, SignedClosure: campaign.ClosureJWS,
			PublicJWKS: campaign.ClosureJWKS,
		}
	}
	return resp
}

func toPQCCampaignFindings(findings []store.PQCMigrationCampaignFinding) []pqcCampaignFindingResponse {
	out := make([]pqcCampaignFindingResponse, 0, len(findings))
	for _, finding := range findings {
		out = append(out, pqcCampaignFindingResponse{
			FindingID: finding.FindingID, FindingDigest: finding.FindingDigest, ReadinessDigest: finding.ReadinessDigest,
			Kind: finding.Kind, Location: finding.Location, Algorithm: finding.Algorithm,
			KeyBits: finding.KeyBits, Protocol: finding.Protocol, Cipher: finding.Cipher,
			Disposition: finding.Disposition, RemediationMethod: finding.RemediationMethod,
			DispositionReason: finding.DispositionReason,
			EvidenceRefs:      nonNilAPIStrings(finding.EvidenceRefs),
			EvidenceDigests:   nonNilAPIStrings(finding.EvidenceDigests),
			DispositionedAt:   finding.DispositionedAt,
		})
	}
	return out
}

func nonNilAPIStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
