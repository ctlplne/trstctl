// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/store"
)

// bindApprovalDestination adds the identity's destination — its deployment
// target and that target's configuration revision — and its issuing authority
// to an issuance binding (A244). They become evidence refs under the
// approval's intent digest, so a target edit, a rebinding or another issuer
// supersedes the approval when it is decided or used.
func (a *API) bindApprovalDestination(ctx context.Context, tenantID string, identity store.Identity, b *store.OperationApprovalIssuanceBinding) error {
	var attrs struct {
		Target string `json:"deployment_target_id"`
		Source string `json:"issuing_authority_source"`
		Issuer string `json:"issuing_authority_id"`
	}
	if len(identity.Attributes) > 0 {
		if err := json.Unmarshal(identity.Attributes, &attrs); err != nil {
			return err
		}
	}
	if target := strings.TrimSpace(attrs.Target); target != "" && a.store != nil {
		rec, err := a.store.GetDeploymentTarget(ctx, tenantID, target)
		if err != nil && !store.IsNotFound(err) {
			return err
		}
		if err == nil {
			b.DestinationTargetID, b.DestinationRevision = rec.ID, rec.RevisionID
		}
	}
	if source := strings.TrimSpace(attrs.Source); source != "" {
		b.IssuerSource, b.IssuerID = source, strings.TrimSpace(attrs.Issuer)
	}
	return nil
}

// changeImpactResponse is what a change to a deployment target or a profile
// reaches (A244): the identities that use it and the open approvals the
// change would supersede.
type changeImpactResponse struct {
	Kind       string                 `json:"kind"`
	Name       string                 `json:"name"`
	Identities []changeImpactIdentity `json:"identities"`
	Approvals  []changeImpactApproval `json:"approvals"`
}

type changeImpactIdentity struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	OwnerID string `json:"owner_id,omitempty"`
}

type changeImpactApproval struct {
	ID         string `json:"id"`
	IdentityID string `json:"identity_id"`
	Action     string `json:"action"`
	Status     string `json:"status"`
}

func changeImpactSchemas() map[string]*Schema {
	return map[string]*Schema{
		"ChangeImpact": object(map[string]*Schema{
			"kind": {Type: "string", Enum: []string{"deployment_target", "profile"}}, "name": str(),
			"identities": {Type: "array", Items: object(map[string]*Schema{
				"id": uuid(), "name": str(), "status": str(), "owner_id": str(),
			}, "id", "name", "status")},
			"approvals": {Type: "array", Items: object(map[string]*Schema{
				"id": uuid(), "identity_id": str(), "action": str(), "status": str(),
			}, "id", "identity_id", "action", "status")},
		}, "kind", "name", "identities", "approvals"),
	}
}

func (a *API) changeImpactRoutes() []route {
	return []route{
		{method: "GET", path: "/api/v1/connectors/targets/{id}/impact", opID: "getConnectorTargetChangeImpact",
			summary: "Show what a change to a deployment target reaches: the certificates that deploy to it and the open approvals a change supersedes",
			handler: a.getConnectorTargetChangeImpact, pathParams: []param{pathString("id", "deployment target ID")},
			resSchema: "ChangeImpact", successCode: "200", perm: authz.ConnectorsRead},
		{method: "GET", path: "/api/v1/profiles/impact/{name}", opID: "getProfileChangeImpact",
			summary: "Show what a change to a certificate profile reaches: the certificates that use it and the open approvals a change supersedes",
			handler: a.getProfileChangeImpact, pathParams: []param{pathString("name", "certificate profile name")},
			resSchema: "ChangeImpact", successCode: "200", perm: authz.ProfilesRead, scope: scopeProfilePath("name")},
	}
}

func (a *API) getConnectorTargetChangeImpact(w http.ResponseWriter, r *http.Request) {
	a.writeChangeImpact(w, r, "deployment_target", r.PathValue("id"), "deployment_target_id", store.DestinationApprovalEvidence(r.PathValue("id")))
}

func (a *API) getProfileChangeImpact(w http.ResponseWriter, r *http.Request) {
	a.writeChangeImpact(w, r, "profile", r.PathValue("name"), "profile_name", store.ProfileApprovalEvidence(r.PathValue("name")))
}

func (a *API) writeChangeImpact(w http.ResponseWriter, r *http.Request, kind, name, attribute, evidence string) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.store == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "the store is unavailable"))
		return
	}
	if kind == "deployment_target" {
		if _, err := a.store.GetDeploymentTarget(r.Context(), tenantID, name); err != nil {
			a.writeError(w, err)
			return
		}
	}
	identities, err := a.store.IdentitiesWithAttribute(r.Context(), tenantID, attribute, name)
	if err != nil {
		a.writeError(w, err)
		return
	}
	approvals, err := a.store.OpenApprovalsWithEvidence(r.Context(), tenantID, evidence)
	if err != nil {
		a.writeError(w, err)
		return
	}
	out := changeImpactResponse{Kind: kind, Name: name, Identities: []changeImpactIdentity{}, Approvals: []changeImpactApproval{}}
	for _, i := range identities {
		out.Identities = append(out.Identities, changeImpactIdentity{ID: i.ID, Name: i.Name, Status: i.Status, OwnerID: i.OwnerID})
	}
	for _, ap := range approvals {
		out.Approvals = append(out.Approvals, changeImpactApproval{ID: ap.ID, IdentityID: ap.IdentityID, Action: ap.Action, Status: ap.Status})
	}
	a.writeJSON(w, http.StatusOK, out)
}
