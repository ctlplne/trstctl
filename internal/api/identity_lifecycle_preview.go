// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

type identityLifecyclePreviewResponse struct {
	Capability             string   `json:"capability"`
	Ready                  bool     `json:"ready"`
	IdentityID             string   `json:"identity_id"`
	IdentityName           string   `json:"identity_name"`
	IdentityKind           string   `json:"identity_kind"`
	OwnerID                string   `json:"owner_id"`
	OwnerName              string   `json:"owner_name,omitempty"`
	From                   string   `json:"from"`
	To                     string   `json:"to"`
	ExpectedVersion        uint64   `json:"expected_version"`
	EventType              string   `json:"event_type"`
	SideEffect             bool     `json:"side_effect"`
	SideEffectDestination  string   `json:"side_effect_destination,omitempty"`
	RequestFingerprint     string   `json:"request_fingerprint"`
	RequiredPermission     string   `json:"required_permission"`
	Prerequisites          []string `json:"prerequisites"`
	PreviewWrites          []string `json:"preview_writes"`
	PreviewExternalEffects []string `json:"preview_external_effects"`
	ExecutionWrites        []string `json:"execution_writes"`
	ExecutionEffects       []string `json:"execution_external_effects"`
	VerificationSteps      []string `json:"verification_steps"`
	Warnings               []string `json:"warnings"`
	Guidance               string   `json:"guidance"`
	// KeygenRefused says the issuance needs a requester key: the tenant has
	// control-plane key generation off and nothing else would supply one.
	KeygenRefused bool `json:"keygen_refused,omitempty"`
	// ProfileRefused says the certificate profile the mint would apply
	// refuses this issuance for a reason that needs no key (its protocol or
	// validity); ProfileRefusal is the profile's own reason.
	ProfileRefused bool   `json:"profile_refused,omitempty"`
	ProfileRefusal string `json:"profile_refusal,omitempty"`
	// refusals are the warnings that made Ready false, each as it reads in
	// Warnings; the application view's review plan names them apart from
	// the other warnings (A244-L2).
	refusals []string
}

// refuse marks the plan not ready for reason, which reads among its warnings.
func (p *identityLifecyclePreviewResponse) refuse(reason string) {
	p.Ready = false
	p.Warnings = append(p.Warnings, reason)
	p.refusals = append(p.refusals, reason)
}

// transitionReadback is how to confirm an accepted lifecycle transition: the
// identity's status, its audit event and, for an edge with an outbox effect,
// that effect's receipt.
func transitionReadback(id, to, eventType string, sideEffect bool) []string {
	out := []string{
		"Read /api/v1/identities/" + id + " and confirm status is " + to + ".",
		"Find the immutable " + eventType + " audit event for this identity.",
	}
	if sideEffect {
		out = append(out, "Follow the matching delivery or rotation receipt; accepted lifecycle state is not the same as completed external delivery.")
	}
	return out
}

func lifecyclePreviewAPIError(err error) error {
	if errors.Is(err, store.ErrIdentityIssuanceBusy) {
		return errWithStatus(http.StatusConflict, err)
	}
	if errors.Is(err, store.ErrIdentityEnrollmentConflict) {
		return errWithStatus(http.StatusConflict, err)
	}
	if errors.Is(err, orchestrator.ErrStaleLifecyclePreview) {
		return errStatus(http.StatusConflict, "The identity changed after this lifecycle action was previewed. Review the current state and preview the action again.")
	}
	if errors.Is(err, orchestrator.ErrKeyCompromiseContainmentRequired) {
		refusal := errStatus(http.StatusConflict, orchestrator.ErrKeyCompromiseContainmentRequired.Error())
		refusal.ext = map[string]any{
			"code":                  "key_compromise_containment_required",
			"recovery_operation_id": "previewKeyCompromise",
		}
		return refusal
	}
	return err
}

// previewIdentityTransition is a POST-shaped read because the proposed target,
// reason, and optional public CSR live in a structured body. It emits no event,
// writes no projection, enqueues no outbox intent, and contacts no signer or
// external system. Execution rechecks ExpectedVersion while holding the identity
// row lock, so this explanation cannot authorize work against newer state.
func (a *API) previewIdentityTransition(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	var req transitionRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	plan, err := a.identityTransitionPlan(r.Context(), tenantID, r.PathValue("id"), req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, plan)
}

// identityTransitionPlan is the preview's plan for one transition (the
// identity application view's review plan carries it too, A244-L2). It emits
// no event, writes no projection, enqueues no outbox intent, and contacts no
// signer or external system.
func (a *API) identityTransitionPlan(ctx context.Context, tenantID, id string, req transitionRequest) (identityLifecyclePreviewResponse, error) {
	// A client cannot choose the preview fence. The server returns the current
	// immutable projection sequence and execution must echo that value.
	req.ExpectedVersion = nil
	if err := canonicalizeTransitionRequest(&req); err != nil {
		return identityLifecyclePreviewResponse{}, err
	}
	identity, version, err := a.store.IdentityApprovalTarget(ctx, tenantID, id)
	if err != nil {
		return identityLifecyclePreviewResponse{}, err
	}
	to := orchestrator.State(req.To)
	eventType, valid := orchestrator.EventTypeFor(orchestrator.State(identity.Status), to)
	if !valid {
		return identityLifecyclePreviewResponse{}, &orchestrator.TransitionError{IdentityID: id, From: orchestrator.State(identity.Status), To: to}
	}
	var profileRefusal error
	if to == orchestrator.StateIssued && (identity.Kind == store.KindX509Certificate || identity.Kind == "x509") {
		requirement, err := a.orch.ProfileApprovalRequirement(ctx, tenantID, id)
		if err == nil && requirement.ProfileName == "" && a.gate.Profile != "" {
			requirement, err = a.orch.ProfileApprovalRequirementByName(ctx, tenantID, a.gate.Profile)
		}
		if err == nil {
			err = a.validateIdentityProfileLifetime(ctx, tenantID, identity, requirement, req.SubjectCSRPEM)
		}
		if errors.Is(err, orchestrator.ErrIssuanceProfileRefused) {
			// The plan below reports it: execution refuses this issuance
			// before recording anything.
			profileRefusal, err = err, nil
		}
		if err != nil {
			return identityLifecyclePreviewResponse{}, err
		}
	}
	if to == orchestrator.StateRenewing {
		pending, err := a.store.IdentityRenewalWorkPending(ctx, tenantID, id)
		if err != nil {
			return identityLifecyclePreviewResponse{}, err
		}
		if pending {
			return identityLifecyclePreviewResponse{}, orchestrator.ErrRenewalWorkPending
		}
		replacement, err := a.store.ActiveEndpointReplacement(ctx, tenantID, id)
		if err != nil {
			return identityLifecyclePreviewResponse{}, err
		}
		if replacement != "" {
			return identityLifecyclePreviewResponse{}, errStatus(http.StatusConflict,
				"This identity has active replacement "+replacement+". Complete or revoke that replacement before renewing the original.")
		}
	}
	csrPEM := strings.TrimSpace(req.SubjectCSRPEM)
	if csrPEM != "" {
		if to != orchestrator.StateIssued {
			return identityLifecyclePreviewResponse{}, errStatus(http.StatusBadRequest, "subject_csr_pem is only meaningful on a transition to issued")
		}
		if err := a.validateSubjectCSRPEM(ctx, tenantID, csrPEM); err != nil {
			return identityLifecyclePreviewResponse{}, errWithStatus(http.StatusBadRequest, err)
		}
	}
	owner, err := a.store.GetOwner(ctx, tenantID, identity.OwnerID)
	if err != nil {
		return identityLifecyclePreviewResponse{}, err
	}
	destination, sideEffect := orchestrator.SideEffectFor(orchestrator.State(identity.Status), to)
	principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
	fingerprintBody, err := json.Marshal(struct {
		Domain          string `json:"domain"`
		TenantID        string `json:"tenant_id"`
		Requester       string `json:"requester"`
		IdentityID      string `json:"identity_id"`
		ExpectedVersion uint64 `json:"expected_version"`
		To              string `json:"to"`
		Reason          string `json:"reason"`
		CSRDigest       string `json:"csr_digest,omitempty"`
	}{
		Domain: "trstctl.api.identity-lifecycle-preview.v2", TenantID: tenantID, Requester: principal.Subject,
		IdentityID: id, ExpectedVersion: version, To: req.To, Reason: req.Reason,
		CSRDigest: crypto.SHA256Hex([]byte(csrPEM)),
	})
	if err != nil {
		return identityLifecyclePreviewResponse{}, err
	}
	plan := identityLifecyclePreviewResponse{
		Capability: "nhi_lifecycle_transition", Ready: true,
		IdentityID: id, IdentityName: identity.Name, IdentityKind: string(identity.Kind),
		OwnerID: identity.OwnerID, OwnerName: owner.Name,
		From: identity.Status, To: req.To, ExpectedVersion: version, EventType: eventType,
		SideEffect: sideEffect, SideEffectDestination: destination,
		RequestFingerprint: crypto.SHA256Hex(fingerprintBody),
		RequiredPermission: string(authz.IdentitiesWrite),
		Prerequisites: []string{
			"The identity is still in " + identity.Status + " state at lifecycle version " + strconv.FormatUint(version, 10) + ".",
			"The tenant-local owner “" + owner.Name + "” is still assigned.",
			"Execution requires identities:write and one Idempotency-Key.",
		},
		PreviewWrites: []string{}, PreviewExternalEffects: []string{},
		ExecutionWrites: []string{
			"Append one tenant-scoped " + eventType + " event.",
			"Project the identity from " + identity.Status + " to " + req.To + ".",
		},
		ExecutionEffects:  []string{},
		VerificationSteps: transitionReadback(id, req.To, eventType, sideEffect),
		Warnings:          []string{},
		Guidance:          "This preview performed no write and contacted no external system. Execution rechecks the lifecycle version, policy, quota, approval, and idempotency boundaries.",
	}
	if sideEffect {
		plan.ExecutionWrites = append(plan.ExecutionWrites,
			"Enqueue one "+destination+" intent in the same PostgreSQL transaction as the state change.")
		plan.ExecutionEffects = append(plan.ExecutionEffects,
			"A bounded outbox worker performs "+destination+" asynchronously after the transaction commits.")
	}
	if to == orchestrator.StateIssued {
		plan.Prerequisites = append(plan.Prerequisites,
			"Certificate profile, quota, approval, CSR, and signer checks run again at execution.")
		authorityFact, authorityWarning := issuingAuthorityFacts(identity.Attributes)
		plan.Prerequisites = append(plan.Prerequisites, authorityFact)
		if authorityWarning != "" {
			plan.Warnings = append(plan.Warnings, authorityWarning)
		}
		admission := profileRefusal
		if admission == nil {
			admission = a.orch.IssuanceAdmissionRefusal(ctx, tenantID, identity, nil)
		}
		if errors.Is(admission, orchestrator.ErrIssuanceProfileRefused) {
			// The profile the mint would apply refuses it; execution would
			// refuse this issuance before recording anything.
			plan.ProfileRefused = true
			plan.ProfileRefusal = admission.Error()
			plan.refuse(admission.Error())
		} else if admission != nil {
			return identityLifecyclePreviewResponse{}, admission
		}
		if csrPEM == "" {
			if err := a.orch.ControlPlaneKeygenRefusal(ctx, tenantID, identity, csrPEM); errors.Is(err, orchestrator.ErrControlPlaneKeygenOff) {
				// The tenant turned control-plane key generation off; execution
				// would refuse this issuance before recording anything.
				plan.KeygenRefused = true
				plan.refuse(err.Error())
			} else if err != nil {
				return identityLifecyclePreviewResponse{}, err
			} else {
				plan.Warnings = append(plan.Warnings,
					"No requester-generated CSR is attached. The deprecated compatibility path may generate a subject key inside the control plane.")
			}
		}
	}
	if to == orchestrator.StateRevoked && (identity.Kind == store.KindX509Certificate || identity.Kind == "x509") {
		if orchestrator.KeyCompromiseNeedsContainment(identity, to, req.Reason) {
			plan.refuse(
				"This X.509 identity may still be serving a compromised leaf. The disabled ordinary transition would queue CA revocation but no host containment, so it cannot complete a key-compromise response. Use Certificates → Revocation & CT → Revocation center, select the exact host target, and review the compound key-compromise command. If no managed target is available, revoke the exact certificate with its issuing CA and stop the host through an independently verified procedure.")
			plan.Guidance = "Ordinary key-compromise revocation is unavailable for a serving X.509 identity. Review CA revocation and host containment together in the Revocation center."
			plan.VerificationSteps = append(plan.VerificationSteps,
				"Follow both CA publication and host containment receipts, then verify signed CA revocation evidence and the fresh served leaf with stock clients.")
		}
		certs, err := a.store.IdentityRevocationCertificates(ctx, tenantID, id, 101)
		if err != nil {
			return identityLifecyclePreviewResponse{}, err
		}
		if len(certs) > 100 {
			plan.refuse(
				"More than 100 exact certificates need revocation. This preview cannot confirm every issuing CA in one bounded read; review the certificate inventory and revocation receipts.")
		}
		for _, cert := range certs {
			if a.certRevocationAuthority == nil {
				plan.refuse(
					"The issuing CA revocation capability is unavailable for certificate " + cert.ID + ". Confirm revocation with its issuing CA.")
				continue
			}
			if _, err := a.certRevocationAuthority(ctx, cert); err != nil {
				if !errors.Is(err, orchestrator.ErrCertificateRevocationUnsupported) {
					return identityLifecyclePreviewResponse{}, err
				}
				plan.refuse(
					"trstctl cannot confirm revocation through the issuing CA for exact certificate " + cert.ID + ". Revoke it with its issuing CA and verify upstream CRL or OCSP status; a local identity state change does not revoke the certificate.")
			}
		}
		if len(certs) != 0 {
			plan.VerificationSteps = append(plan.VerificationSteps,
				"Confirm every exact certificate with its issuing CA and verify upstream revocation evidence; identity status alone is not certificate revocation.")
		}
		if identity.Status == "deployed" || identity.Status == "renewing" || identity.Status == "renewal_failed" {
			var binding struct {
				TargetID string `json:"deployment_target_id"`
			}
			if len(identity.Attributes) != 0 {
				if err := json.Unmarshal(identity.Attributes, &binding); err != nil {
					return identityLifecyclePreviewResponse{}, err
				}
			}
			target := "a bound serving workload"
			if binding.TargetID != "" {
				target = "deployment target " + binding.TargetID
			}
			plan.Warnings = append(plan.Warnings,
				"CA revocation and an identity state change alone do not stop "+target+
					". It may still serve the revoked certificate to clients that do not enforce CRLs or OCSP. For key compromise, stop or replace the serving credential immediately; never roll back to a revoked predecessor.")
			plan.VerificationSteps = append(plan.VerificationSteps,
				"Open a fresh connection to the serving target and confirm that no revoked serial or fingerprint is served. Confirm a verified replacement delivery or independently verify service refusal; CA revocation alone is not endpoint containment.")
		}
	}
	return plan, nil
}

// issuingAuthorityFacts explains which CA will sign when this identity moves to
// issued. The dispatcher pins the authority from the identity's
// issuing_authority_* attributes and otherwise falls back to the built-in
// platform CA. That fallback was invisible in the preview: an operator who
// claimed a discovered listener and pressed Issue got a platform-CA
// certificate without ever choosing a CA. The preview now names the authority
// and warns when it is the silent default, so a CA-preserving customer can stop
// before execution and use the endpoint lifecycle wizard instead.
func issuingAuthorityFacts(raw json.RawMessage) (fact, warning string) {
	const defaultFact = "Issuing authority: the built-in platform CA (trstctl issuing CA) — no CA is pinned on this identity."
	const defaultWarning = "No issuing authority is pinned on this identity, so execution uses the built-in platform CA. " +
		"To issue through an external or private CA, use the endpoint lifecycle wizard or pin the authority before issuing."
	if len(raw) == 0 {
		return defaultFact, defaultWarning
	}
	var attrs map[string]any
	if err := json.Unmarshal(raw, &attrs); err != nil {
		return defaultFact, defaultWarning
	}
	source, _ := attrs["issuing_authority_source"].(string)
	id, _ := attrs["issuing_authority_id"].(string)
	name, _ := attrs["issuing_authority_name"].(string)
	source, id, name = strings.TrimSpace(source), strings.TrimSpace(id), strings.TrimSpace(name)
	if source == "" && id == "" {
		return defaultFact, defaultWarning
	}
	label := name
	if label == "" {
		label = id
	}
	switch source {
	case "external":
		return "Issuing authority: external CA " + label + " (" + source + ":" + id + "), pinned on this identity; no built-in CA is substituted.", ""
	case "private":
		return "Issuing authority: private CA " + label + " (" + source + ":" + id + "), pinned on this identity; no built-in CA is substituted.", ""
	case "platform":
		return "Issuing authority: the built-in platform CA (" + label + "), pinned on this identity.", ""
	default:
		return "Issuing authority: " + source + ":" + id + " is pinned on this identity but is not a supported source; execution refuses rather than substituting a CA.", ""
	}
}
