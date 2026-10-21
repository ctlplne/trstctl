// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// Connector-side takedown of rogue certificates (A43).
//
// A rogue or non-compliant finding used to end at a recommendation. The
// listing now says where trstctl delivered the leaf and what can remove it
// there: a host target through the enrolled agent's purge (A49), an appliance
// target through a network relay's object takedown, or nothing for families
// that cannot address an installed object. The takedown route dispatches to
// the right one and answers with the queued receipt.

const (
	rogueRemediationHostPurge         = "host_purge"
	rogueRemediationApplianceTakedown = "appliance_takedown"
	rogueRemediationNone              = "none"
)

type rogueInstalledTarget struct {
	TargetID   string `json:"target_id"`
	TargetName string `json:"target_name"`
	Connector  string `json:"connector"`
	Model      string `json:"model"`
	Note       string `json:"note,omitempty"`
}

type rogueCertificateTakedownRequest struct {
	Fingerprint string `json:"fingerprint"`
	TargetID    string `json:"target_id"`
	Reason      string `json:"reason"`
}

// rogueRemediationModel names what trstctl can execute against one target for
// a leaf it delivered there.
func rogueRemediationModel(target store.DeploymentTarget) (string, string) {
	switch {
	case connector.CanRollbackOnHost(target.Type):
		if !relay.HostPredecessorLayoutComplete(target.Type, target.Config) {
			return rogueRemediationNone, "this host family keeps its material outside an addressable file layout; remove it on the host by hand"
		}
		return rogueRemediationHostPurge, "the enrolled host agent removes the certificate and key files and wipes its rollback ledger"
	case connector.CanTakedown(target.Type):
		return rogueRemediationApplianceTakedown, "a network relay deletes the fingerprint-named object; a bound object is refused until it is re-bound"
	default:
		return rogueRemediationNone, "this connector family cannot remove an installed object by name; remove it on the device by hand"
	}
}

// attachRogueInstalledTargets resolves, for each finding with a fingerprint,
// the targets trstctl delivered it to and the remediation each can execute.
func (a *API) attachRogueInstalledTargets(ctx context.Context, tenantID string, findings []rogueCertificateFinding) error {
	if a.store == nil {
		return nil
	}
	var targets []store.DeploymentTarget
	loaded := false
	for i := range findings {
		fingerprint := strings.TrimSpace(findings[i].Fingerprint)
		if fingerprint == "" {
			continue
		}
		delivered, err := a.store.DeliveredTargetsForFingerprint(ctx, tenantID, fingerprint)
		if err != nil {
			return err
		}
		if len(delivered) == 0 {
			continue
		}
		if !loaded {
			targets, err = a.store.ListDeploymentTargets(ctx, tenantID)
			if err != nil {
				return err
			}
			loaded = true
		}
		for _, d := range delivered {
			for _, target := range targets {
				route := strings.TrimSpace(orchestrator.DeploymentRoute(target))
				if route == "" {
					route = target.Name
				}
				if target.Type != d.Connector || (target.Name != d.Target && route != d.Target) {
					continue
				}
				model, note := rogueRemediationModel(target)
				findings[i].InstalledOn = append(findings[i].InstalledOn, rogueInstalledTarget{
					TargetID: target.ID, TargetName: target.Name, Connector: target.Type, Model: model, Note: note,
				})
			}
		}
	}
	return nil
}

//trstctl:mutation
func (a *API) takedownRogueCertificate(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	var request rogueCertificateTakedownRequest
	if err := decodeJSON(r, &request); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	request.Fingerprint = strings.ToLower(strings.TrimSpace(request.Fingerprint))
	request.TargetID = strings.TrimSpace(request.TargetID)
	request.Reason = strings.TrimSpace(request.Reason)
	if request.Fingerprint == "" || request.TargetID == "" || request.Reason == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "takedown needs the leaf fingerprint, the target id and a reason"))
		return
	}
	principal, _ := r.Context().Value(principalCtxKey).(authz.Principal)
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.orch == nil {
			return 0, nil, errors.New("connector orchestrator is unavailable")
		}
		target, err := a.store.GetDeploymentTarget(ctx, tenantID, request.TargetID)
		if err != nil {
			return 0, nil, err
		}
		if _, err := a.store.GetCertificateByFingerprint(ctx, tenantID, request.Fingerprint); err != nil {
			return 0, nil, errStatus(http.StatusConflict, "the fingerprint is not in this tenant's certificate inventory; a takedown needs the delivered leaf")
		}
		route := strings.TrimSpace(orchestrator.DeploymentRoute(target))
		if route == "" {
			route = target.Name
		}
		delivered, err := a.store.DeployDeliveredToTarget(ctx, tenantID, route, request.Fingerprint)
		if err != nil {
			return 0, nil, err
		}
		if !delivered {
			if byName, err := a.store.DeployDeliveredToTarget(ctx, tenantID, target.Name, request.Fingerprint); err != nil {
				return 0, nil, err
			} else if !byName {
				return 0, nil, errStatus(http.StatusConflict,
					"trstctl never delivered this leaf to that target, so there is no installed object of its name to remove; nothing was queued")
			}
		}
		model, note := rogueRemediationModel(target)
		switch model {
		case rogueRemediationHostPurge:
			plan, err := a.endpointPurgePlan(ctx, tenantID, target.ID)
			if err != nil {
				return 0, nil, err
			}
			if !strings.EqualFold(plan.ExpectedFingerprint, request.Fingerprint) {
				return 0, nil, errStatus(http.StatusConflict,
					"the host's last delivered leaf is not this fingerprint; the agent would find a different certificate installed, so nothing was queued")
			}
			receipt, err := a.orch.RequestEndpointPurge(ctx, tenantID, orchestrator.EndpointPurgeRequest{
				TargetID: plan.TargetID, TargetRevision: plan.TargetRevision,
				IdentityID: plan.IdentityID, ExpectedFingerprint: plan.ExpectedFingerprint,
				RequiredAgentID: plan.RequiredAgentID, Connector: plan.Connector, TargetConfig: target.Config,
				Target: plan.TargetName, Reason: request.Reason, RequestedBy: principal.Subject, IdempotencyKey: idempotencyKey,
			})
			if err != nil {
				return 0, nil, err
			}
			return http.StatusAccepted, toConnectorDeliveryResponse(receipt), nil
		case rogueRemediationApplianceTakedown:
			receipt, err := a.orch.RequestConnectorTakedown(ctx, tenantID, orchestrator.ConnectorTakedownRequest{
				Connector: target.Type, Target: route, TargetID: target.ID, TargetRevision: target.RevisionID,
				Fingerprint: request.Fingerprint, TargetConfig: target.Config,
				Reason: request.Reason, RequestedBy: principal.Subject, IdempotencyKey: idempotencyKey,
			})
			if err != nil {
				return 0, nil, err
			}
			return http.StatusAccepted, toConnectorDeliveryResponse(receipt), nil
		default:
			return 0, nil, errStatus(http.StatusConflict, "no executable takedown for this target: "+note)
		}
	})
}
