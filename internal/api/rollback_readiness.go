// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"strings"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/store"
)

// Rollback readiness (A46).
//
// A rollback that would find nothing to restore used to be discovered only by
// asking for one: the route refused, or the relay reported the predecessor
// object absent. Both are truthful and both are late. The target read now
// answers the same question up front, applying the same refusals the rollback
// route applies, so an operator knows before an incident whether this target
// can be put back and what would make it rollable.

type rollbackReadiness struct {
	// Model is how a rollback would execute: re-bind on the appliance, restore
	// from the host agent's ledger, or none for a family without a route.
	Model string `json:"model"`
	Ready bool   `json:"ready"`
	// Reason says what a rollback would be refused for, or what would make the
	// target rollable; empty when ready.
	Reason                 string `json:"reason,omitempty"`
	IdentityID             string `json:"identity_id,omitempty"`
	PredecessorFingerprint string `json:"predecessor_fingerprint,omitempty"`
	PredecessorSerial      string `json:"predecessor_serial,omitempty"`
}

// rollbackReadinessInputs are the resolved facts the verdict is computed from,
// so the rules are testable without a store.
type rollbackReadinessInputs struct {
	Family       string
	Config       json.RawMessage
	Rebind       bool
	HostRollback bool

	HostEvidenceFound          bool
	HostIdentityID             string
	HostFingerprint            string
	HostPredecessorFingerprint string

	BoundIdentityID string

	PredecessorKnown         bool
	PredecessorRevoked       bool
	PredecessorFingerprint   string
	PredecessorSerial        string
	PredecessorDeliveredHere bool
}

func rollbackReadinessFrom(in rollbackReadinessInputs) rollbackReadiness {
	switch {
	case in.HostRollback:
		out := rollbackReadiness{Model: "host"}
		if !in.HostEvidenceFound {
			out.Reason = "no successful enrolled host-agent deploy owns a predecessor for this target; the first successful host deploy records the current certificate, the second makes it rollable"
			return out
		}
		out.IdentityID = in.HostIdentityID
		if in.HostPredecessorFingerprint == "" {
			out.Reason = "the host has one successful deploy, no earlier trstctl delivery for the same identity and target, and its agent reported no adopted pre-trstctl pair; a second successful deploy makes it rollable"
			return out
		}
		out.PredecessorFingerprint = in.HostPredecessorFingerprint
		out.PredecessorSerial = in.PredecessorSerial
		if !in.PredecessorKnown {
			out.Reason = "the host's retained predecessor is not in this tenant's certificate inventory; a rollback would be refused"
			return out
		}
		if in.PredecessorRevoked {
			out.Reason = "the retained predecessor is revoked; a rollback would be refused rather than restore a revoked certificate"
			return out
		}
		out.Ready = true
		return out
	case in.Rebind:
		out := rollbackReadiness{Model: "re-bind"}
		if reason := rebindBindingMissing(in.Family, in.Config); reason != "" {
			out.Reason = reason
			return out
		}
		if in.BoundIdentityID == "" {
			out.Reason = "no identity is bound to this target; a rollback needs the identity whose predecessor to re-bind"
			return out
		}
		out.IdentityID = in.BoundIdentityID
		if !in.PredecessorKnown || in.PredecessorFingerprint == "" {
			out.Reason = "no predecessor certificate: the bound identity has not been renewed onto this target yet; it becomes rollable after its next deployment"
			return out
		}
		out.PredecessorFingerprint = in.PredecessorFingerprint
		out.PredecessorSerial = in.PredecessorSerial
		if in.PredecessorRevoked {
			out.Reason = "the predecessor certificate is revoked; a rollback would be refused rather than restore it"
			return out
		}
		if !in.PredecessorDeliveredHere {
			out.Reason = "the predecessor was never delivered to this target through trstctl, so no installed object of its name exists to re-bind; the target becomes rollable after one more deployment"
			return out
		}
		out.Ready = true
		return out
	default:
		return rollbackReadiness{Model: "none", Reason: "this connector family has no executable rollback route"}
	}
}

// rebindBindingMissing names the binding a fortigate or paloalto target must
// configure before its deploys become fingerprint-named and re-bindable.
func rebindBindingMissing(family string, config json.RawMessage) string {
	var fields struct {
		BindTo        string `json:"bind_to"`
		SSLTLSProfile string `json:"ssl_tls_profile"`
		CommitAdmin   string `json:"commit_admin"`
	}
	_ = json.Unmarshal(config, &fields)
	switch family {
	case "fortigate":
		if strings.TrimSpace(fields.BindTo) == "" {
			return "this fortigate target names no bind_to (admin or ssl-vpn); its deploys install in place under the target name and leave no predecessor to re-bind"
		}
	case "paloalto":
		if strings.TrimSpace(fields.SSLTLSProfile) == "" || strings.TrimSpace(fields.CommitAdmin) == "" {
			return "this paloalto target names no ssl_tls_profile with commit_admin; its imports land in place under the target name and leave no predecessor to re-bind"
		}
	}
	return ""
}

// rollbackReadiness resolves the facts for one target and computes the verdict.
func (a *API) rollbackReadiness(ctx context.Context, tenantID string, target store.DeploymentTarget) rollbackReadiness {
	in := rollbackReadinessInputs{Family: target.Type, Config: target.Config,
		Rebind: connector.CanRollback(target.Type), HostRollback: connector.CanRollbackOnHost(target.Type)}
	if a.store == nil {
		return rollbackReadinessFrom(in)
	}
	switch {
	case in.HostRollback:
		evidence, found, err := a.store.LastSuccessfulHostDeployEvidence(ctx, tenantID, target.ID)
		if err != nil {
			return rollbackReadiness{Model: "host", Reason: "host deploy evidence could not be read: " + err.Error()}
		}
		in.HostEvidenceFound, in.HostIdentityID, in.HostFingerprint, in.HostPredecessorFingerprint =
			found, evidence.IdentityID, evidence.Fingerprint, evidence.PredecessorFingerprint
		if in.HostPredecessorFingerprint != "" {
			if previous, err := a.store.GetCertificateByFingerprint(ctx, tenantID, in.HostPredecessorFingerprint); err == nil {
				in.PredecessorKnown, in.PredecessorSerial, in.PredecessorRevoked = true, previous.Serial, previous.Status == "revoked"
			}
		}
	case in.Rebind:
		if rebindBindingMissing(target.Type, target.Config) != "" {
			return rollbackReadinessFrom(in)
		}
		ids, err := a.store.IdentityIDsBoundToDeploymentTarget(ctx, tenantID, target.ID)
		if err != nil {
			return rollbackReadiness{Model: "re-bind", Reason: "bound identities could not be read: " + err.Error()}
		}
		for _, id := range ids {
			predecessor := a.store.ResolvePredecessorCertificate(ctx, tenantID, id)
			if in.BoundIdentityID == "" || predecessor.Fingerprint != "" {
				in.BoundIdentityID = id
			}
			if predecessor.Fingerprint == "" {
				continue
			}
			in.PredecessorKnown, in.PredecessorFingerprint, in.PredecessorSerial = true, predecessor.Fingerprint, predecessor.Serial
			if previous, err := a.store.GetCertificateByFingerprint(ctx, tenantID, predecessor.Fingerprint); err == nil {
				in.PredecessorRevoked = previous.Status == "revoked"
			}
			route := strings.TrimSpace(target.Name)
			delivered, err := a.store.DeployDeliveredToTarget(ctx, tenantID, route, predecessor.Fingerprint)
			if err != nil {
				return rollbackReadiness{Model: "re-bind", Reason: "delivery receipts could not be read: " + err.Error()}
			}
			in.PredecessorDeliveredHere = delivered
			break
		}
	}
	return rollbackReadinessFrom(in)
}
