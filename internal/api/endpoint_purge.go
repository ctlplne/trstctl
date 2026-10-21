// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
)

// Removing compromised material from a host (A49) reuses the containment
// review: the same exact target, identity, leaf and enrolled agent, the same
// preview fingerprint binding, and the same submission checks. What differs
// is the host action: not a stop, but the overwrite and removal of the files
// the target's own configuration names, plus the wipe of every rollback-ledger
// snapshot carrying that fingerprint.

func (a *API) endpointPurgePlan(ctx context.Context, tenantID, targetID string) (endpointContainmentPreview, error) {
	if err := a.validatePurgeExecutionReady(); err != nil {
		return endpointContainmentPreview{}, err
	}
	target, err := a.store.GetDeploymentTarget(ctx, tenantID, targetID)
	if err != nil {
		return endpointContainmentPreview{}, err
	}
	if !connector.CanRollbackOnHost(target.Type) {
		return endpointContainmentPreview{}, errStatus(http.StatusConflict,
			"this connector is not an enrolled host target with an executable material-removal path")
	}
	if !relay.HostPredecessorLayoutComplete(target.Type, target.Config) {
		return endpointContainmentPreview{}, errStatus(http.StatusConflict,
			"this target's configuration does not name an exact certificate and key file layout for its connector family (java-keystore, iis and envoy hold material the host agent cannot address as files); removal was not queued")
	}
	evidence, found, err := a.store.LastSuccessfulHostDeployEvidence(ctx, tenantID, target.ID)
	if err != nil {
		return endpointContainmentPreview{}, err
	}
	if !found || evidence.AgentID == "" || evidence.IdentityID == "" || evidence.Fingerprint == "" {
		return endpointContainmentPreview{}, errStatus(http.StatusConflict,
			"no exact completed host deployment identifies the target, leaf and enrolled agent; removal was not queued")
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
			"the last reported leaf is not bound to the reported identity; removal was not queued")
	}
	identity, err := a.store.GetIdentity(ctx, tenantID, evidence.IdentityID)
	if err != nil {
		return endpointContainmentPreview{}, err
	}
	cert, err := a.store.GetCertificateByFingerprint(ctx, tenantID, evidence.Fingerprint)
	if err != nil {
		return endpointContainmentPreview{}, err
	}
	plan := endpointContainmentPreview{
		Capability: "host_material_purge", Ready: true, EffectFree: true,
		TargetID: target.ID, TargetName: target.Name, TargetRevision: target.RevisionID,
		Connector: target.Type, TargetEnabled: target.Enabled,
		IdentityID: identity.ID, IdentityName: identity.Name, IdentityStatus: identity.Status,
		CertificateStatus: cert.Status, ExpectedFingerprint: strings.ToLower(evidence.Fingerprint),
		RequiredAgentID: evidence.AgentID, RequiredPermission: string(authz.ConnectorsWrite),
		ExecutionEffects: []string{
			"Append a tenant-scoped removal request and queue an endpoint.purge job on this target's deploy/rollback lane, pinned to the exact enrolled host agent.",
			"That agent reads the installed certificate at the target's configured paths and removes nothing unless its fingerprint is exactly this leaf. It then overwrites and removes the certificate and key files, wipes every rollback-ledger snapshot with this fingerprint, and runs the host profile's stop action for this target when one is bound.",
		},
		VerificationSteps: []string{
			"Follow this job's connector receipt to a terminal purge status; only purged means files were removed and the ledger wiped.",
			"Confirm the listener no longer serves the compromised fingerprint; a service that was not stopped may keep it in memory until it reloads.",
			"Verify exact CA revocation separately; removing material does not publish a CRL or OCSP result.",
		},
		Warnings: []string{
			"After a successful removal this target has no certificate on disk until a fresh issuance is deployed; a rollback cannot restore the purged material.",
			"A different leaf at the target's paths causes no removal and does not prove the compromised key is gone from this host.",
			"This preview cannot inspect the host operator's private profile; the job fails if the target's paths are outside the profile's allowed roots.",
		},
	}
	if cert.Status != "revoked" {
		plan.Warnings = append(plan.Warnings,
			"The certificate is not recorded revoked. If this is key compromise, publish revocation with its issuing CA first and verify signed CRL or OCSP separately.")
	}
	body, err := json.Marshal(struct {
		Domain              string `json:"domain"`
		TargetID            string `json:"target_id"`
		TargetRevision      string `json:"target_revision"`
		IdentityID          string `json:"identity_id"`
		ExpectedFingerprint string `json:"expected_fingerprint"`
		RequiredAgentID     string `json:"required_agent_id"`
	}{"trstctl.endpoint-purge-preview.v1", plan.TargetID, plan.TargetRevision,
		plan.IdentityID, plan.ExpectedFingerprint, plan.RequiredAgentID})
	if err != nil {
		return endpointContainmentPreview{}, err
	}
	plan.PreviewFingerprint = crypto.SHA256Hex(body)
	return plan, nil
}

func (a *API) previewEndpointPurge(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	plan, err := a.endpointPurgePlan(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, plan)
}

//trstctl:mutation
func (a *API) purgeEndpoint(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	targetID := r.PathValue("id")
	var request endpointContainmentRequest
	if err := decodeJSON(r, &request); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	if strings.TrimSpace(request.Reason) == "" || strings.TrimSpace(request.PreviewFingerprint) == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "material removal needs a reason and the reviewed preview fingerprint"))
		return
	}
	principal, _ := r.Context().Value(principalCtxKey).(authz.Principal)
	bindingBody, err := json.Marshal(struct {
		Domain   string                     `json:"domain"`
		Actor    string                     `json:"actor"`
		TargetID string                     `json:"target_id"`
		Request  endpointContainmentRequest `json:"request"`
	}{"trstctl.endpoint-purge-command.v1", principal.Subject, targetID, request})
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateDurableBound(w, r, idempotencyKey, crypto.SHA256Hex(bindingBody),
		func(ctx context.Context, tenantID string) (int, any, error) {
			if a.orch == nil {
				return 0, nil, errors.New("endpoint purge orchestrator is unavailable")
			}
			plan, err := a.endpointPurgePlan(ctx, tenantID, targetID)
			if err != nil {
				return 0, nil, err
			}
			if request.TargetRevision != plan.TargetRevision || request.IdentityID != plan.IdentityID ||
				!strings.EqualFold(request.ExpectedFingerprint, plan.ExpectedFingerprint) ||
				request.RequiredAgentID != plan.RequiredAgentID ||
				request.PreviewFingerprint != plan.PreviewFingerprint {
				return 0, nil, errStatus(http.StatusConflict,
					"the target, identity, agent or served leaf changed after review; preview removal again")
			}
			target, err := a.store.GetDeploymentTarget(ctx, tenantID, targetID)
			if err != nil {
				return 0, nil, err
			}
			receipt, err := a.orch.RequestEndpointPurge(ctx, tenantID, orchestrator.EndpointPurgeRequest{
				TargetID: plan.TargetID, TargetRevision: plan.TargetRevision,
				IdentityID: plan.IdentityID, ExpectedFingerprint: plan.ExpectedFingerprint,
				RequiredAgentID: plan.RequiredAgentID, Connector: plan.Connector, TargetConfig: target.Config,
				Target: plan.TargetName, Reason: request.Reason,
				RequestedBy: principal.Subject, IdempotencyKey: idempotencyKey,
			})
			if err != nil {
				return 0, nil, err
			}
			return http.StatusAccepted, toConnectorDeliveryResponse(receipt), nil
		})
}
