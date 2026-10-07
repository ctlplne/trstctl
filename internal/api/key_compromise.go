// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

type keyCompromisePlanRequest struct {
	TargetID string `json:"target_id"`
}

type keyCompromiseCertificate struct {
	ID          string `json:"id"`
	Fingerprint string `json:"fingerprint"`
	Serial      string `json:"serial"`
	Authority   string `json:"authority"`
}

type keyCompromisePlan struct {
	Capability          string                     `json:"capability"`
	Ready               bool                       `json:"ready"`
	EffectFree          bool                       `json:"effect_free"`
	IdentityID          string                     `json:"identity_id"`
	ExpectedVersion     uint64                     `json:"expected_version"`
	Target              endpointContainmentPreview `json:"target"`
	Certificates        []keyCompromiseCertificate `json:"certificates"`
	PreviewFingerprint  string                     `json:"preview_fingerprint"`
	RequiredPermissions []string                   `json:"required_permissions"`
	ExecutionEffects    []string                   `json:"execution_effects"`
	VerificationSteps   []string                   `json:"verification_steps"`
}

type keyCompromiseExecutionRequest struct {
	TargetID            string `json:"target_id"`
	TargetRevision      string `json:"target_revision"`
	TargetName          string `json:"target_name"`
	Connector           string `json:"connector"`
	IdentityID          string `json:"identity_id"`
	ExpectedFingerprint string `json:"expected_fingerprint"`
	RequiredAgentID     string `json:"required_agent_id"`
	ExpectedVersion     uint64 `json:"expected_version"`
	PreviewFingerprint  string `json:"preview_fingerprint"`
}

type keyCompromiseResult struct {
	Identity    identityResponse          `json:"identity"`
	Revocation  store.OutboxAttempt       `json:"revocation"`
	Containment connectorDeliveryResponse `json:"containment"`
}

func (a *API) readKeyCompromise(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	principal, _ := r.Context().Value(principalCtxKey).(authz.Principal)
	scope := authz.Scope{TenantID: tenantID}
	if !principal.Can(authz.ConnectorsRead, scope) ||
		a.checkABAC(r.Context(), r, principal, authz.ConnectorsRead, scope) != nil {
		a.writeError(w, errStatus(http.StatusForbidden, "key compromise result needs connectors:read authority"))
		return
	}
	key := r.URL.Query().Get("request_key")
	if key == "" || a.orch == nil {
		a.writeError(w, errStatus(http.StatusBadRequest, "request_key and key compromise service are required"))
		return
	}
	identityID := r.PathValue("id")
	revocation, containment, err := a.orch.KeyCompromiseStatus(r.Context(), tenantID, identityID, key)
	if err != nil {
		a.writeError(w, err)
		return
	}
	identity, err := a.store.GetIdentity(r.Context(), tenantID, identityID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, keyCompromiseResult{
		Identity: toIdentityResponse(identity), Revocation: revocation,
		Containment: toConnectorDeliveryResponse(containment),
	})
}

func (a *API) keyCompromisePlan(ctx context.Context, tenantID, identityID, targetID, requester string) (keyCompromisePlan, error) {
	if err := a.validateContainmentExecutionReady(); err != nil {
		return keyCompromisePlan{}, err
	}
	identity, version, err := a.store.IdentityApprovalTarget(ctx, tenantID, identityID)
	if err != nil {
		return keyCompromisePlan{}, err
	}
	if identity.Kind != store.KindX509Certificate ||
		!orchestrator.CanTransition(orchestrator.State(identity.Status), orchestrator.StateRevoked) {
		return keyCompromisePlan{}, errStatus(http.StatusConflict, "key compromise requires an active X.509 lifecycle identity")
	}
	target, err := a.endpointContainmentPlan(ctx, tenantID, targetID)
	if err != nil {
		return keyCompromisePlan{}, err
	}
	if target.IdentityID != identityID {
		return keyCompromisePlan{}, errStatus(http.StatusConflict, "the exact served leaf belongs to a different identity")
	}
	certs, err := a.store.IdentityRevocationCertificates(ctx, tenantID, identityID, 101)
	if err != nil {
		return keyCompromisePlan{}, err
	}
	if len(certs) == 0 || len(certs) > 100 || a.certRevocationAuthority == nil {
		return keyCompromisePlan{}, errStatus(http.StatusConflict, "exact issuing CA revocation authority is unavailable or exceeds the bounded review")
	}
	reviewed := make([]keyCompromiseCertificate, 0, len(certs))
	for _, cert := range certs {
		authority, err := a.certRevocationAuthority(ctx, cert)
		if err != nil || authority == "" {
			return keyCompromisePlan{}, errStatus(http.StatusConflict, "the issuing CA cannot revoke every exact certificate; review certificate inventory")
		}
		reviewed = append(reviewed, keyCompromiseCertificate{
			ID: cert.ID, Fingerprint: cert.Fingerprint, Serial: cert.Serial, Authority: authority,
		})
	}
	material, err := json.Marshal(struct {
		Domain       string                     `json:"domain"`
		TenantID     string                     `json:"tenant_id"`
		Requester    string                     `json:"requester"`
		IdentityID   string                     `json:"identity_id"`
		Version      uint64                     `json:"version"`
		Target       endpointContainmentPreview `json:"target"`
		Certificates []keyCompromiseCertificate `json:"certificates"`
	}{"trstctl.key-compromise-preview.v1", tenantID, requester, identityID, version, target, reviewed})
	if err != nil {
		return keyCompromisePlan{}, err
	}
	return keyCompromisePlan{
		Capability: "key_compromise", Ready: true, EffectFree: true,
		IdentityID: identityID, ExpectedVersion: version, Target: target,
		Certificates: reviewed, PreviewFingerprint: crypto.SHA256Hex(material),
		RequiredPermissions: []string{string(authz.IdentitiesWrite), string(authz.ConnectorsWrite)},
		ExecutionEffects: []string{
			"One immutable identity.revoked event projects the revoked identity and queues separate CA publication and exact-fingerprint host containment jobs in the same tenant transaction.",
			"The CA publisher and host agent deliver independently; an accepted command is not either terminal result.",
		},
		VerificationSteps: []string{
			"Follow the CA revocation receipt and verify the exact serial through signed CRL or OCSP with a stock client.",
			"Follow the host containment receipt; independently verify that a fresh client no longer receives the compromised leaf.",
			"Deploy a new credential and independently read it back. Never restore the revoked predecessor.",
		},
	}, nil
}

func (a *API) requireKeyCompromiseAuthority(r *http.Request, tenantID string) (authz.Principal, error) {
	principal, _ := r.Context().Value(principalCtxKey).(authz.Principal)
	scope := authz.Scope{TenantID: tenantID}
	if !principal.Can(authz.ConnectorsWrite, scope) ||
		a.checkABAC(r.Context(), r, principal, authz.ConnectorsWrite, scope) != nil {
		return principal, errStatus(http.StatusForbidden, "key compromise host containment requires connectors:write authority")
	}
	return principal, nil
}

func (a *API) previewKeyCompromise(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	principal, err := a.requireKeyCompromiseAuthority(r, tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	var request keyCompromisePlanRequest
	if err := decodeJSON(r, &request); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	plan, err := a.keyCompromisePlan(r.Context(), tenantID, r.PathValue("id"), request.TargetID, principal.Subject)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, plan)
}

//trstctl:mutation
func (a *API) executeKeyCompromise(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	principal, err := a.requireKeyCompromiseAuthority(r, tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	var request keyCompromiseExecutionRequest
	if err := decodeJSON(r, &request); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	identityID := r.PathValue("id")
	if request.IdentityID != identityID || strings.TrimSpace(request.PreviewFingerprint) == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "key compromise needs the exact reviewed identity and preview fingerprint"))
		return
	}
	key := r.Header.Get("Idempotency-Key")
	bindingBody, err := json.Marshal(struct {
		Domain  string                        `json:"domain"`
		Actor   string                        `json:"actor"`
		Request keyCompromiseExecutionRequest `json:"request"`
	}{"trstctl.key-compromise-command.v1", principal.Subject, request})
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateDurableBound(w, r, key, crypto.SHA256Hex(bindingBody),
		func(ctx context.Context, tenantID string) (int, any, error) {
			identity, _, err := a.store.IdentityApprovalTarget(ctx, tenantID, identityID)
			if err != nil {
				return 0, nil, err
			}
			if identity.Status != string(orchestrator.StateRevoked) {
				plan, err := a.keyCompromisePlan(ctx, tenantID, identityID, request.TargetID, principal.Subject)
				if err != nil {
					return 0, nil, err
				}
				if request.ExpectedVersion != plan.ExpectedVersion ||
					request.TargetRevision != plan.Target.TargetRevision ||
					request.TargetName != plan.Target.TargetName ||
					request.Connector != plan.Target.Connector ||
					request.ExpectedFingerprint != plan.Target.ExpectedFingerprint ||
					request.RequiredAgentID != plan.Target.RequiredAgentID ||
					request.PreviewFingerprint != plan.PreviewFingerprint {
					return 0, nil, errStatus(http.StatusConflict, "identity, CA certificates, target or served leaf changed after review; preview the compromise again")
				}
			}
			req := transitionRequest{To: "revoked", Reason: "keyCompromise",
				ExpectedVersion: &request.ExpectedVersion,
				compromise: &orchestrator.EndpointContainmentRequest{
					TargetID: request.TargetID, TargetRevision: request.TargetRevision,
					IdentityID: identityID, ExpectedFingerprint: request.ExpectedFingerprint,
					RequiredAgentID: request.RequiredAgentID, Connector: request.Connector,
					Target: request.TargetName, Reason: "keyCompromise", RequestedBy: principal.Subject,
					IdempotencyKey: key,
				},
			}
			return a.executeIdentityTransition(ctx, tenantID, principal, identityID, req, key)
		})
}

func (a *API) replayIdentityKeyCompromise(ctx context.Context, tenantID string,
	principal authz.Principal, identityID string, req transitionRequest, key,
	keyDigest, csrDigest string) (int, any, error) {
	if a.orch == nil || req.compromise == nil {
		return 0, nil, errors.New("key compromise orchestrator is unavailable")
	}
	var receipt store.ConnectorDeliveryReceipt
	approvalRequest, found, err := a.store.ConsumedOperationApprovalForAttempt(ctx, tenantID,
		store.OperationApprovalAttempt{ResourceKind: "identity", ResourceID: identityID,
			Action: "revoke", Requester: principal.Subject, ToState: "revoked",
			Reason: "keyCompromise", IdempotencyKeyDigest: keyDigest, SubjectCSRDigest: csrDigest})
	if err != nil {
		return 0, nil, err
	}
	if found {
		approval, err := store.OperationApprovalUseFromRequest(approvalRequest)
		if err != nil {
			return 0, nil, err
		}
		receipt, err = a.orch.TransitionKeyCompromiseWithApproval(ctx, tenantID,
			identityID, key, req.ExpectedVersion, *req.compromise, approval)
		if err != nil {
			return 0, nil, err
		}
	} else {
		receipt, err = a.orch.TransitionKeyCompromise(ctx, tenantID,
			identityID, key, req.ExpectedVersion, *req.compromise)
		if err != nil {
			return 0, nil, err
		}
	}
	updated, err := a.store.GetIdentity(ctx, tenantID, identityID)
	if err != nil {
		return 0, nil, err
	}
	revocation, _, err := a.orch.KeyCompromiseStatus(ctx, tenantID, identityID, key)
	if err != nil {
		return 0, nil, err
	}
	return http.StatusAccepted, keyCompromiseResult{
		Identity: toIdentityResponse(updated), Revocation: revocation,
		Containment: toConnectorDeliveryResponse(receipt),
	}, nil
}
