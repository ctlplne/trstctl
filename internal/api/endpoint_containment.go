// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
)

type endpointContainmentRequest struct {
	TargetRevision      string `json:"target_revision"`
	IdentityID          string `json:"identity_id"`
	ExpectedFingerprint string `json:"expected_fingerprint"`
	RequiredAgentID     string `json:"required_agent_id"`
	PreviewFingerprint  string `json:"preview_fingerprint"`
	Reason              string `json:"reason"`
}

type endpointContainmentPreview struct {
	Capability          string   `json:"capability"`
	Ready               bool     `json:"ready"`
	EffectFree          bool     `json:"effect_free"`
	TargetID            string   `json:"target_id"`
	TargetName          string   `json:"target_name"`
	TargetRevision      string   `json:"target_revision"`
	Connector           string   `json:"connector"`
	TargetEnabled       bool     `json:"target_enabled"`
	IdentityID          string   `json:"identity_id"`
	IdentityName        string   `json:"identity_name"`
	IdentityStatus      string   `json:"identity_status"`
	CertificateStatus   string   `json:"certificate_status"`
	ExpectedFingerprint string   `json:"expected_fingerprint"`
	RequiredAgentID     string   `json:"required_agent_id"`
	PreviewFingerprint  string   `json:"preview_fingerprint"`
	RequiredPermission  string   `json:"required_permission"`
	ExecutionEffects    []string `json:"execution_effects"`
	VerificationSteps   []string `json:"verification_steps"`
	Warnings            []string `json:"warnings"`
}

func (a *API) endpointContainmentPlan(ctx context.Context, tenantID, targetID string) (endpointContainmentPreview, error) {
	if err := a.validateContainmentExecutionReady(); err != nil {
		return endpointContainmentPreview{}, err
	}
	target, err := a.store.GetDeploymentTarget(ctx, tenantID, targetID)
	if err != nil {
		return endpointContainmentPreview{}, err
	}
	if !connector.CanRollbackOnHost(target.Type) {
		return endpointContainmentPreview{}, errStatus(http.StatusConflict,
			"this connector is not an enrolled host target with an executable containment path")
	}
	evidence, found, err := a.store.LastSuccessfulHostDeployEvidence(ctx, tenantID, target.ID)
	if err != nil {
		return endpointContainmentPreview{}, err
	}
	if !found || evidence.AgentID == "" || evidence.IdentityID == "" || evidence.Fingerprint == "" {
		return endpointContainmentPreview{}, errStatus(http.StatusConflict,
			"no exact completed host deployment identifies the target, leaf and enrolled agent; containment was not queued")
	}
	assigned, err := connector.TargetHostAgentID(target.Config)
	if err != nil || assigned != evidence.AgentID {
		return endpointContainmentPreview{}, errStatus(http.StatusConflict,
			"the target no longer assigns the host agent that reported its last deployment; review target ownership first")
	}
	owned, err := a.store.IdentityOwnsCertificateFingerprint(ctx, tenantID, evidence.IdentityID, evidence.Fingerprint)
	if err != nil {
		return endpointContainmentPreview{}, err
	}
	if !owned {
		return endpointContainmentPreview{}, errStatus(http.StatusConflict,
			"the last reported leaf is not bound to the reported identity; containment was not queued")
	}
	identity, err := a.store.GetIdentity(ctx, tenantID, evidence.IdentityID)
	if err != nil {
		return endpointContainmentPreview{}, err
	}
	if identity.Status == "retired" {
		return endpointContainmentPreview{}, errStatus(http.StatusConflict,
			"the reported identity is retired; review the live target before authorizing a host action")
	}
	cert, err := a.store.GetCertificateByFingerprint(ctx, tenantID, evidence.Fingerprint)
	if err != nil {
		return endpointContainmentPreview{}, err
	}
	plan := endpointContainmentPreview{
		Capability: "host_endpoint_containment", Ready: true, EffectFree: true,
		TargetID: target.ID, TargetName: target.Name, TargetRevision: target.RevisionID,
		Connector: target.Type, TargetEnabled: target.Enabled,
		IdentityID: identity.ID, IdentityName: identity.Name, IdentityStatus: identity.Status,
		CertificateStatus: cert.Status, ExpectedFingerprint: strings.ToLower(evidence.Fingerprint),
		RequiredAgentID: evidence.AgentID, RequiredPermission: string(authz.ConnectorsWrite),
		ExecutionEffects: []string{
			"Append a tenant-scoped containment request and queue an endpoint.contain job on this target's deploy/rollback lane.",
			"Only the exact enrolled host agent may claim it. That agent must first observe this fingerprint on its operator-pinned listener before running its operator-pinned stop action.",
		},
		VerificationSteps: []string{
			"Follow this job's connector receipt to a terminal containment status and inspect its signed before/after probes.",
			"Independently open a new connection to this listener and confirm the compromised fingerprint is absent or TLS is refused.",
			"Verify exact CA revocation and relying-party rejection separately; stopping a listener does not publish a CRL or OCSP result.",
		},
		Warnings: []string{
			"The last completed delivery identifies a candidate leaf, not the current listener state. The host agent performs a fresh exact-fingerprint probe immediately before any stop.",
			"This preview cannot inspect the host operator's private profile. The job fails if that profile lacks this target's exact listener and stop action.",
			"A different leaf observed before execution causes a no-stop result; it is not proof that the replacement is authorized or trusted.",
		},
	}
	if !target.Enabled {
		plan.Warnings = append(plan.Warnings,
			"The target is disabled in trstctl. That flag does not stop its service; exact-fingerprint emergency containment remains available.")
	}
	if cert.Status != "revoked" {
		plan.Warnings = append(plan.Warnings,
			"The certificate is not recorded revoked. If this is key compromise, publish revocation with its issuing CA and verify signed CRL or OCSP separately.")
	}
	body, err := json.Marshal(struct {
		Domain              string `json:"domain"`
		TargetID            string `json:"target_id"`
		TargetRevision      string `json:"target_revision"`
		IdentityID          string `json:"identity_id"`
		ExpectedFingerprint string `json:"expected_fingerprint"`
		RequiredAgentID     string `json:"required_agent_id"`
	}{"trstctl.endpoint-containment-preview.v1", plan.TargetID, plan.TargetRevision,
		plan.IdentityID, plan.ExpectedFingerprint, plan.RequiredAgentID})
	if err != nil {
		return endpointContainmentPreview{}, err
	}
	plan.PreviewFingerprint = crypto.SHA256Hex(body)
	return plan, nil
}

func (a *API) previewEndpointContainment(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	plan, err := a.endpointContainmentPlan(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, plan)
}

//trstctl:mutation
func (a *API) containEndpoint(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	targetID := r.PathValue("id")
	var request endpointContainmentRequest
	if err := decodeJSON(r, &request); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	if strings.TrimSpace(request.Reason) == "" || strings.TrimSpace(request.PreviewFingerprint) == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "containment needs a reason and the reviewed preview fingerprint"))
		return
	}
	principal, _ := r.Context().Value(principalCtxKey).(authz.Principal)
	bindingBody, err := json.Marshal(struct {
		Domain   string                     `json:"domain"`
		Actor    string                     `json:"actor"`
		TargetID string                     `json:"target_id"`
		Request  endpointContainmentRequest `json:"request"`
	}{"trstctl.endpoint-containment-command.v1", principal.Subject, targetID, request})
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateDurableBound(w, r, idempotencyKey, crypto.SHA256Hex(bindingBody),
		func(ctx context.Context, tenantID string) (int, any, error) {
			if a.orch == nil {
				return 0, nil, errors.New("endpoint containment orchestrator is unavailable")
			}
			plan, err := a.endpointContainmentPlan(ctx, tenantID, targetID)
			if err != nil {
				return 0, nil, err
			}
			if request.TargetRevision != plan.TargetRevision || request.IdentityID != plan.IdentityID ||
				!strings.EqualFold(request.ExpectedFingerprint, plan.ExpectedFingerprint) ||
				request.RequiredAgentID != plan.RequiredAgentID ||
				request.PreviewFingerprint != plan.PreviewFingerprint {
				return 0, nil, errStatus(http.StatusConflict,
					"the target, identity, agent or served leaf changed after review; preview containment again")
			}
			receipt, err := a.orch.RequestEndpointContainment(ctx, tenantID, orchestrator.EndpointContainmentRequest{
				TargetID: plan.TargetID, TargetRevision: plan.TargetRevision,
				IdentityID: plan.IdentityID, ExpectedFingerprint: plan.ExpectedFingerprint,
				RequiredAgentID: plan.RequiredAgentID, Connector: plan.Connector,
				Target: plan.TargetName, Reason: request.Reason,
				RequestedBy: principal.Subject, IdempotencyKey: idempotencyKey,
			})
			if err != nil {
				return 0, nil, err
			}
			return http.StatusAccepted, toConnectorDeliveryResponse(receipt), nil
		})
}
