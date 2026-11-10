// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/graph"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// Generated access reviews (Q1). A campaign is built from what trstctl already
// records instead of a hand-typed list: the credentials that reach a resource
// in the access graph, or the credentials whose owner's attestation is stale.
// The graph source carries the graph's coverage statement, because an empty or
// short list is not proof that nobody else has access.

func (a *API) nhiReviewGenerateRoutes() []route {
	return []route{
		{method: "POST", path: "/api/v1/access/reviews/generate", opID: "generateNHIReviewCampaign",
			summary: "Start an NHI access review built from the access graph or from stale owner attestations",
			handler: a.generateNHIReviewCampaign, reqSchema: "NHIReviewGenerateRequest", resSchema: "NHIReviewGenerateResponse",
			successCode: "201", mutation: true, perm: authz.AccessWrite},
	}
}

type nhiReviewGenerateRequest struct {
	Name            string     `json:"name"`
	Source          string     `json:"source"`
	Target          string     `json:"target,omitempty"`
	OlderThanDays   int        `json:"older_than_days,omitempty"`
	ReviewerSubject string     `json:"reviewer_subject,omitempty"`
	DueAt           *time.Time `json:"due_at,omitempty"`
}

type nhiReviewGenerateResponse struct {
	Campaign nhiReviewCampaignResponse `json:"campaign"`
	// Coverage is the access graph's statement of what it sees, for a
	// campaign generated from it.
	Coverage *graph.AccessCoverage `json:"coverage,omitempty"`
}

//trstctl:mutation
func (a *API) generateNHIReviewCampaign(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.orch == nil || a.store == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "NHI access reviews are not configured")
		}
		var req nhiReviewGenerateRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		g, err := graph.Build(ctx, a.store, tenantID)
		if err != nil {
			return 0, nil, err
		}
		var start orchestrator.NHIReviewCampaignStartRequest
		var coverage *graph.AccessCoverage
		switch req.Source {
		case "graph_reachers":
			// The items carry the graph's holders and approvers to every
			// campaign reader, so building one needs graph authority too.
			principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
			if !principal.Can(authz.GraphRead, authz.Scope{TenantID: tenantID}) {
				return 0, nil, errStatus(http.StatusForbidden, "a review generated from the access graph also needs graph:read")
			}
			start, err = nhiReviewFromReachers(g, strings.TrimSpace(req.Target))
			c := graph.Coverage()
			coverage = &c
		case "stale_owner_attestation":
			start, err = a.nhiReviewFromStaleOwners(ctx, tenantID, g, req.OlderThanDays, time.Now().UTC())
		case "pam_accounts":
			// A276: brokered accounts, their templates' approvers, the
			// approvers of access without a template, and the emergency
			// responders.
			src, ok := a.pam.(PAMCertificationService)
			if a.pam == nil || !ok {
				return 0, nil, ErrPAMUnavailable
			}
			start, err = src.GeneratePAMCertification(ctx, tenantID)
		default:
			return 0, nil, errStatus(http.StatusBadRequest, "source must be graph_reachers, stale_owner_attestation or pam_accounts")
		}
		if err != nil {
			return 0, nil, err
		}
		start.Name, start.ReviewerSubject, start.DueAt = req.Name, req.ReviewerSubject, req.DueAt
		campaign, err := a.orch.StartNHIReviewCampaign(ctx, tenantID, start)
		if err != nil {
			return 0, nil, errStatusFrom(http.StatusBadRequest, err)
		}
		return http.StatusCreated, nhiReviewGenerateResponse{Campaign: toNHIReviewCampaignResponse(campaign, true), Coverage: coverage}, nil
	})
}

// nhiReviewFromReachers lists one item per credential that reaches target
// through an access grant, with its holders, approvers and grant as evidence.
func nhiReviewFromReachers(g *graph.Graph, target string) (orchestrator.NHIReviewCampaignStartRequest, error) {
	node, ok := g.Node(target)
	if target == "" || !ok {
		return orchestrator.NHIReviewCampaignStartRequest{}, errStatus(http.StatusNotFound, "target graph node not found")
	}
	answer := g.WhoCanReach(target)
	if len(answer.Access) == 0 {
		return orchestrator.NHIReviewCampaignStartRequest{}, errStatus(http.StatusUnprocessableEntity,
			"no credential reaches "+target+" in trstctl's records. "+answer.Coverage.Note)
	}
	if len(answer.Access) > orchestrator.MaxNHIReviewCampaignItems {
		return orchestrator.NHIReviewCampaignStartRequest{}, errStatus(http.StatusUnprocessableEntity, fmt.Sprintf(
			"%d credentials reach %s; a campaign holds at most %d, so review a narrower target", len(answer.Access), target, orchestrator.MaxNHIReviewCampaignItems))
	}
	items := make([]orchestrator.NHIReviewItemRequest, 0, len(answer.Access))
	for _, grant := range answer.Access {
		refs := []string{"graph:grant:" + grant.Grant.Source}
		owner := ""
		for _, holder := range grant.Holders {
			refs = append(refs, "graph:holder:"+holder.Node.ID)
			if owner == "" && holder.Edge.Type == graph.EdgeOwns {
				owner = holder.Node.ID
			}
		}
		for _, approver := range grant.Approvers {
			refs = append(refs, "graph:approver:"+approver.Node.ID)
		}
		if owner == "" && len(grant.Holders) > 0 {
			owner = grant.Holders[0].Node.ID
		}
		if len(refs) > 20 {
			refs = refs[:20]
		}
		attrs := grant.Credential.Attrs
		kind := firstNonEmpty(attrs["credential_kind"], "credential")
		risk := "medium"
		if kind == "pam_session" {
			risk = "high"
		}
		items = append(items, orchestrator.NHIReviewItemRequest{
			NHIID: grant.Credential.ID, NHIKind: kind, DisplayName: grant.Credential.Name, OwnerRef: owner,
			Resource: target, Entitlement: firstNonEmpty(attrs["role"], attrs["scopes"], grant.Grant.Source),
			Risk: risk, EvidenceRefs: refs,
		})
	}
	return orchestrator.NHIReviewCampaignStartRequest{Scope: "credentials reaching " + node.Name, Items: items}, nil
}

// nhiReviewFromStaleOwners lists the credentials of every complete owner whose
// attestation is older than olderThanDays (the tenant's attestation cadence
// when zero) or was never made. A keep decision renews that owner's
// attestation.
func (a *API) nhiReviewFromStaleOwners(ctx context.Context, tenantID string, g *graph.Graph, olderThanDays int, now time.Time) (orchestrator.NHIReviewCampaignStartRequest, error) {
	cadence := a.ownerAttestationCadence()
	if olderThanDays != 0 {
		if olderThanDays < 1 || olderThanDays > 3650 {
			return orchestrator.NHIReviewCampaignStartRequest{}, errStatus(http.StatusBadRequest, "older_than_days must be between 1 and 3650")
		}
		cadence = time.Duration(olderThanDays) * 24 * time.Hour
	}
	var items []orchestrator.NHIReviewItemRequest
	for after := store.ZeroUUID; ; {
		owners, err := a.store.ListOwnersPage(ctx, tenantID, after, 200)
		if err != nil {
			return orchestrator.NHIReviewCampaignStartRequest{}, err
		}
		for _, owner := range owners {
			// Q1-L5: an owner with no application or environment can never be
			// attested, so its credentials are listed here too: a keep is
			// refused until the reviewer completes the owner. Only a complete
			// owner with a current attestation is left out.
			if owner.OwnershipComplete() && owner.OwnershipCurrent(now, cadence) {
				continue
			}
			for _, credential := range g.Neighbors("wl:"+owner.ID, graph.EdgeOwns) {
				if len(items) == orchestrator.MaxNHIReviewCampaignItems {
					return orchestrator.NHIReviewCampaignStartRequest{}, errStatus(http.StatusUnprocessableEntity, fmt.Sprintf(
						"more than %d credentials have a stale owner attestation; review a shorter window first", orchestrator.MaxNHIReviewCampaignItems))
				}
				items = append(items, staleOwnerReviewItem(owner, credential))
			}
		}
		if len(owners) < 200 {
			break
		}
		after = owners[len(owners)-1].ID
	}
	if len(items) == 0 {
		return orchestrator.NHIReviewCampaignStartRequest{}, errStatus(http.StatusUnprocessableEntity, "no owned credential has a stale or incomplete owner attestation")
	}
	return orchestrator.NHIReviewCampaignStartRequest{Scope: "owners attested before " + now.Add(-cadence).Format(time.DateOnly) +
		", and owners with no application or environment", Items: items}, nil
}

func staleOwnerReviewItem(owner store.Owner, credential graph.Node) orchestrator.NHIReviewItemRequest {
	attested := "never attested"
	if owner.OwnershipVerifiedAt != nil {
		attested = "attested " + owner.OwnershipVerifiedAt.UTC().Format(time.DateOnly)
	}
	if !owner.OwnershipComplete() {
		attested = "incomplete: the owner has no application or environment, so it cannot be attested; complete the owner, then keep"
	}
	return orchestrator.NHIReviewItemRequest{
		NHIID: credential.ID, NHIKind: firstNonEmpty(credential.Attrs["credential_kind"], "credential"),
		DisplayName: credential.Name, OwnerRef: "wl:" + owner.ID,
		Resource: "owner " + firstNonEmpty(owner.Name, owner.ID), Entitlement: "ownership " + attested,
		EvidenceRefs: []string{"owner:" + owner.ID},
	}
}

// CertificationResult is a completed campaign's canonical result and the
// audit key's signature over it (A276): verify the signature with the audit
// verification keys, then compare the payload it carries with result.
type CertificationResult struct {
	Artifact  string          `json:"artifact"`
	Result    json.RawMessage `json:"result"`
	Signature string          `json:"signature"`
}

// PAMCertificationService builds certification campaigns from brokered
// accounts and signs completed campaigns' results; the served broker
// implements it.
type PAMCertificationService interface {
	GeneratePAMCertification(ctx context.Context, tenantID string) (orchestrator.NHIReviewCampaignStartRequest, error)
	CertificationResult(ctx context.Context, tenantID, campaignID string) (CertificationResult, error)
}

func (a *API) nhiReviewResultRoutes() []route {
	return []route{
		{method: "GET", path: "/api/v1/access/reviews/{id}/result", opID: "getNHIReviewResult",
			summary: "Get a completed access review's result, signed with the audit key",
			handler: a.getNHIReviewResult, pathParams: []param{pathUUID("id")}, resSchema: "CertificationResult", successCode: "200", perm: authz.AccessRead},
	}
}

func (a *API) getNHIReviewResult(w http.ResponseWriter, r *http.Request) {
	src, ok := a.pam.(PAMCertificationService)
	if a.pam == nil || !ok {
		a.writePAMError(w, ErrPAMUnavailable)
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	out, err := src.CertificationResult(r.Context(), tenantID, strings.TrimSpace(r.PathValue("id")))
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, out)
}
