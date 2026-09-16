// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"time"

	googleuuid "github.com/google/uuid"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/profile"
	"trstctl.com/trstctl/internal/store"
)

// Retain the reviewed inputs before creating anything. A second durable stage
// retains the resulting identity/version before asking for issuance approval.
// Retrying the same request can therefore wait for approval without duplicate
// binding events or a second approval intent. The full prepared identity is
// checked at issuance because metadata edits do not advance lifecycle versions.
type endpointEnrollmentSnapshot struct {
	Preview    endpointBindingPreviewResponse
	IdentityID string
	TargetID   string
	Replaced   store.Identity
}

type endpointEnrollmentPrepared struct {
	Identity store.Identity
	Version  uint64
	Target   store.DeploymentTarget
}

func (a *API) endpointIssuanceRequirement(ctx context.Context, tenantID string, existing *identityResponse, selectedProfile string) (orchestrator.ProfileApprovalRequirement, error) {
	if existing != nil {
		req, err := a.orch.ProfileApprovalRequirement(ctx, tenantID, existing.ID)
		if err != nil {
			return req, err
		}
		if req.ProfileName == "" {
			req, err = a.orch.ProfileApprovalRequirementByName(ctx, tenantID, a.gate.Profile)
			if err != nil {
				return req, err
			}
		}
		if selectedProfile != "" && selectedProfile != req.ProfileName {
			return orchestrator.ProfileApprovalRequirement{}, errStatus(http.StatusConflict, "the existing identity uses a different certificate profile; review its policy on the identity before enrolling it, or keep its current profile")
		}
		return req, nil
	}
	if selectedProfile != "" {
		return a.orch.ProfileApprovalRequirementByName(ctx, tenantID, selectedProfile)
	}
	return a.orch.ProfileApprovalRequirementByName(ctx, tenantID, a.gate.Profile)
}

func (a *API) validateEndpointProfileMetadata(ctx context.Context, tenantID, dnsName string, requirement orchestrator.ProfileApprovalRequirement) error {
	if requirement.ProfileName == "" {
		return nil
	}
	record, err := a.store.GetProfileVersion(ctx, tenantID, requirement.ProfileName, requirement.ProfileVersion)
	if err != nil {
		return err
	}
	if record.ID != requirement.ProfileID || store.ProfileSpecDigest(record.Spec) != requirement.ProfileSpecDigest {
		return errStatus(http.StatusConflict, "endpoint certificate profile changed during preview; preview again")
	}
	var policy profile.CertificateProfile
	if err := json.Unmarshal(record.Spec, &policy); err != nil {
		return fmt.Errorf("decode endpoint certificate profile: %w", err)
	}
	policy.Name, policy.Version = record.Name, record.Version
	if err := policy.ValidateRequestMetadata(profile.Request{
		Protocol: "api", DNSNames: []string{dnsName},
		TTL: time.Duration(requirement.EffectiveTTLSeconds) * time.Second,
	}); err != nil {
		return errStatus(http.StatusUnprocessableEntity, err.Error()+"; choose a certificate profile that permits this endpoint before authorizing issuance; nothing was queued")
	}
	return nil
}

func requireEndpointIssuancePermission(ctx context.Context, tenantID string) error {
	p, _ := ctx.Value(principalCtxKey).(authz.Principal)
	if !p.Can(authz.CertsIssue, authz.Scope{TenantID: tenantID}) {
		return errStatus(http.StatusForbidden, "endpoint enrollment issues a certificate and requires certs:issue as well as connectors:write; nothing was changed")
	}
	return nil
}

//trstctl:mutation
func (a *API) createEndpointBinding(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("Idempotency-Key")
	a.mutateDurable(w, r, key, func(ctx context.Context, tenantID string) (int, any, error) {
		if err := requireEndpointIssuancePermission(ctx, tenantID); err != nil {
			return 0, nil, err
		}
		req, err := decodeEndpointBindingRequest(r)
		if err != nil {
			return 0, nil, err
		}
		principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
		requestJSON, err := json.Marshal(struct {
			Subject string
			Request endpointBindingRequest
		}{principal.Subject, req})
		if err != nil {
			return 0, nil, err
		}
		binding := crypto.SHA256Hex(requestJSON)
		keyDigest := crypto.SHA256Hex([]byte(key))
		snapshot, err := a.endpointEnrollmentSnapshot(ctx, tenantID, keyDigest, binding, req)
		if err != nil {
			return 0, nil, err
		}
		prepared, err := a.prepareEndpointEnrollment(ctx, tenantID, keyDigest, binding, req, snapshot)
		if err != nil {
			return 0, nil, err
		}
		identity := prepared.Identity
		if identity.Status == string(orchestrator.StateRequested) {
			// The identity's immutable issued transition proves the exact raw
			// request key even after the HTTP result was lost and the worker
			// advanced its lifecycle. This branch only recovers a receipt.
			_, acceptedErr := a.store.GetIdentityIssuanceResult(ctx, tenantID, identity.ID, key)
			if acceptedErr != nil {
				if !store.IsNotFound(acceptedErr) {
					return 0, nil, acceptedErr
				}
				if err := a.validateEndpointEnrollmentSnapshot(ctx, tenantID, req, snapshot); err != nil {
					return 0, nil, err
				}
				transition := transitionRequest{To: string(orchestrator.StateIssued), Reason: endpointBindingReason(req), ExpectedVersion: &prepared.Version, reviewedIdentity: &prepared.Identity}
				if _, _, err := a.executeIdentityTransition(ctx, tenantID, principal, identity.ID, transition, key, snapshot.Preview); err != nil {
					return 0, nil, err
				}
			}
			// Return the accepted command snapshot, independent of how quickly
			// background issuance updates validity or deployment metadata.
			identity.Status = string(orchestrator.StateIssued)
		} else if snapshot.Preview.ReplacedIdentity == nil {
			return 0, nil, errStatus(http.StatusConflict, "prepared identity already advanced without this enrollment receipt; inspect its issuance history")
		}
		// EnsureEndpointReplacement validates the complete original and exact
		// reviewed successor binding. An already-accepted successor is read
		// here; no approval is reused and no issuance is queued again.
		return http.StatusCreated, endpointBindingResponse{
			Identity: toIdentityResponse(identity), ReplacedIdentityID: req.ReplaceIdentityID,
			Target: toDeploymentTargetResponse(prepared.Target), Issuer: snapshot.Preview.Issuer,
			PreviewFingerprint:     snapshot.Preview.RequestFingerprint,
			QueuedLifecycleIntents: []string{"ca.issue", "connector.deploy"}, RenewalIntent: "ca.renew",
		}, nil
	})
}

func (a *API) endpointEnrollmentSnapshot(ctx context.Context, tenantID, keyDigest, binding string, req endpointBindingRequest) (endpointEnrollmentSnapshot, error) {
	var out endpointEnrollmentSnapshot
	raw, err := a.idem.DoBound(ctx, tenantID, "endpoint-review:v1:"+keyDigest, binding, func(ctx context.Context) ([]byte, error) {
		preview, err := a.endpointBindingPreview(ctx, tenantID, req)
		if err != nil {
			return nil, err
		}
		if req.PreviewFingerprint == "" {
			return nil, errStatus(http.StatusConflict, "preview_fingerprint is required; preview the exact endpoint before enrollment; nothing was queued or changed")
		}
		if req.PreviewFingerprint != preview.RequestFingerprint {
			return nil, errStatus(http.StatusConflict, "endpoint binding changed after preview or preview_fingerprint is missing; preview the exact owner, issuer, destination, DNS name and profile again; nothing was queued or changed")
		}
		snapshot := endpointEnrollmentSnapshot{Preview: preview, IdentityID: googleuuid.NewString(), TargetID: req.TargetID, Replaced: preview.replacementSource}
		if preview.ExistingIdentity != nil {
			snapshot.IdentityID = preview.ExistingIdentity.ID
		}
		if snapshot.TargetID == "" {
			snapshot.TargetID = googleuuid.NewString()
		}
		return json.Marshal(snapshot)
	})
	defer secret.Wipe(raw)
	if err != nil {
		return out, err
	}
	err = json.Unmarshal(raw, &out)
	return out, err
}

func (a *API) validateEndpointEnrollmentSnapshot(ctx context.Context, tenantID string, req endpointBindingRequest, snapshot endpointEnrollmentSnapshot) error {
	if _, err := a.store.ValidateHostTargetAssignment(ctx, tenantID, snapshot.Preview.Target.Connector, snapshot.Preview.Target.Config); err != nil {
		return errWithStatus(http.StatusConflict, err)
	}
	owner, err := a.store.GetOwner(ctx, tenantID, req.OwnerID)
	if err != nil {
		return err
	}
	if cadence := a.ownershipAttestationCadence; cadence > 0 {
		if ready, _ := ownerReadyForLifecycle(owner, time.Now().UTC(), cadence); !ready {
			return errStatus(http.StatusConflict, "endpoint owner is no longer ready; restore accountability before issuance")
		}
	}
	issuer, err := a.resolveEndpointIssuer(ctx, tenantID, req.Issuer)
	if err != nil {
		return err
	}
	if err := a.checkEndpointIssuerValidationPrerequisites(ctx, tenantID, issuer, req.IdentityName); err != nil {
		return err
	}
	// DNS-01 capability is runtime-only metadata and is intentionally omitted
	// from the durable JSON review. Check its current prerequisites above, then
	// compare the issuer facts that were actually retained for authorization.
	reviewedIssuer := snapshot.Preview.Issuer
	reviewedIssuer.upstreamDNS01 = issuer.upstreamDNS01
	if !reflect.DeepEqual(issuer, reviewedIssuer) {
		return errStatus(http.StatusConflict, "endpoint issuer changed after review; preview again")
	}
	profile, err := a.endpointIssuanceRequirement(ctx, tenantID, snapshot.Preview.ExistingIdentity, req.ProfileName)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(profile.IssuanceBinding(), snapshot.Preview.Issuance) ||
		(a.gate.RequireApproval || profile.RequiresApproval) != snapshot.Preview.ApprovalRequired {
		return errStatus(http.StatusConflict, "endpoint certificate profile or approval policy changed after review; build a fresh preview with a new request key")
	}
	if req.TargetID != "" {
		target, err := a.endpointBindingPreviewTarget(ctx, tenantID, req)
		if err != nil {
			return err
		}
		target.Config, err = canonicalEndpointBindingConfig(target.Config)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(target, snapshot.Preview.Target) {
			return errStatus(http.StatusConflict, "endpoint destination changed after review; build a fresh preview with a new request key")
		}
	}
	return nil
}

func (a *API) prepareEndpointEnrollment(ctx context.Context, tenantID, keyDigest, binding string, req endpointBindingRequest, snapshot endpointEnrollmentSnapshot) (endpointEnrollmentPrepared, error) {
	var out endpointEnrollmentPrepared
	raw, err := a.idem.DoBound(ctx, tenantID, "endpoint-identity:v1:"+keyDigest, binding, func(ctx context.Context) ([]byte, error) {
		if err := a.validateEndpointEnrollmentSnapshot(ctx, tenantID, req, snapshot); err != nil {
			return nil, err
		}
		target, err := a.endpointEnrollmentTarget(ctx, tenantID, req, snapshot)
		if err != nil {
			return nil, err
		}
		issuer := store.IdentityEndpointIssuer{OwnerID: req.OwnerID, Source: snapshot.Preview.Issuer.Source,
			ID: snapshot.Preview.Issuer.ID, Name: snapshot.Preview.Issuer.Name, PreviewFingerprint: snapshot.Preview.RequestFingerprint}
		var identity store.Identity
		if snapshot.Preview.ReplacedIdentity != nil {
			identity, err = a.orch.EnsureEndpointReplacementWithProfile(ctx, tenantID, snapshot.Replaced, snapshot.Preview.ReplacedIdentityVersion, target, issuer, req.ProfileName)
		} else {
			attrs := map[string]string{"issuing_authority_source": issuer.Source,
				"issuing_authority_id": issuer.ID, "issuing_authority_name": issuer.Name, "endpoint_preview_sha256": issuer.PreviewFingerprint}
			if req.ProfileName != "" {
				attrs["profile_name"] = req.ProfileName
			}
			attributes, marshalErr := json.Marshal(attrs)
			if marshalErr != nil {
				return nil, marshalErr
			}
			if snapshot.Preview.ExistingIdentity != nil {
				identity, err = a.store.GetIdentity(ctx, tenantID, snapshot.IdentityID)
			} else {
				identity, err = a.orch.EnsureIdentity(ctx, tenantID, snapshot.IdentityID, store.Identity{
					Kind: store.KindX509Certificate, Name: req.IdentityName, OwnerID: req.OwnerID, Attributes: attributes})
			}
			if err == nil {
				var expectedVersion *uint64
				if snapshot.Preview.ExistingIdentity != nil {
					expectedVersion = &snapshot.Preview.ExistingIdentityVersion
				} else if identity.Name != req.IdentityName || identity.Kind != store.KindX509Certificate || !endpointCreatedIdentityMatches(identity, issuer, req.ProfileName) {
					return nil, errStatus(http.StatusConflict, "prepared endpoint identity changed; review its current state before continuing")
				}
				var reviewed []store.Identity
				if source := snapshot.Preview.ExistingIdentity; source != nil {
					reviewed = append(reviewed, store.Identity{ID: source.ID, TenantID: source.TenantID, Kind: store.IdentityKind(source.Kind), Name: source.Name, OwnerID: source.OwnerID, IssuerID: source.IssuerID, Status: source.Status, NotBefore: source.NotBefore, NotAfter: source.NotAfter, Attributes: source.Attributes, CreatedAt: source.CreatedAt})
				}
				identity, err = a.orch.BindIdentityEndpointAtVersion(ctx, tenantID, identity.ID, target, issuer, expectedVersion, reviewed...)
			}
		}
		if err != nil {
			if errors.Is(err, store.ErrIdentityEnrollmentConflict) {
				return nil, errWithStatus(http.StatusConflict, err)
			}
			return nil, err
		}
		identity, version, err := a.store.IdentityApprovalTarget(ctx, tenantID, identity.ID)
		if err != nil {
			return nil, err
		}
		return json.Marshal(endpointEnrollmentPrepared{Identity: identity, Version: version, Target: target})
	})
	defer secret.Wipe(raw)
	if err != nil {
		return out, err
	}
	err = json.Unmarshal(raw, &out)
	return out, err
}

func (a *API) endpointEnrollmentTarget(ctx context.Context, tenantID string, req endpointBindingRequest, snapshot endpointEnrollmentSnapshot) (store.DeploymentTarget, error) {
	if req.TargetID != "" {
		return a.store.GetDeploymentTarget(ctx, tenantID, req.TargetID)
	}
	if target, err := a.store.GetDeploymentTarget(ctx, tenantID, snapshot.TargetID); err == nil {
		config, configErr := canonicalEndpointBindingConfig(target.Config)
		if configErr != nil {
			return store.DeploymentTarget{}, configErr
		}
		if target.Name != snapshot.Preview.Target.Name || target.Type != snapshot.Preview.Target.Connector || !target.Enabled || !reflect.DeepEqual(config, snapshot.Preview.Target.Config) {
			return store.DeploymentTarget{}, errStatus(http.StatusConflict, "prepared endpoint destination changed; review its current state before continuing")
		}
		return target, nil
	} else if !store.IsNotFound(err) {
		return store.DeploymentTarget{}, err
	}
	return a.orch.UpsertDeploymentTarget(ctx, tenantID, store.DeploymentTarget{ID: snapshot.TargetID,
		Name: req.Target.Name, Type: req.Target.Connector, Config: req.Target.Config, Enabled: true})
}

func endpointCreatedIdentityMatches(identity store.Identity, issuer store.IdentityEndpointIssuer, profileName string) bool {
	var attrs map[string]json.RawMessage
	if json.Unmarshal(identity.Attributes, &attrs) != nil {
		return false
	}
	for key, want := range map[string]string{"issuing_authority_source": issuer.Source, "issuing_authority_id": issuer.ID,
		"issuing_authority_name": issuer.Name, "endpoint_preview_sha256": issuer.PreviewFingerprint} {
		var got string
		if json.Unmarshal(attrs[key], &got) != nil || got != want {
			return false
		}
	}
	// A recovered preparation cannot adopt a newly edited identity policy.
	var retainedProfile, legacyProfile string
	if raw, ok := attrs["profile_name"]; ok && json.Unmarshal(raw, &retainedProfile) != nil {
		return false
	}
	if raw, ok := attrs["profile"]; ok && json.Unmarshal(raw, &legacyProfile) != nil {
		return false
	}
	if retainedProfile != profileName || legacyProfile != "" {
		return false
	}
	return true
}
