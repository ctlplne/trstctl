// SPDX-License-Identifier: MPL-2.0

package api

import (
	"net/http"
	"sort"

	"trstctl.com/trstctl/internal/custody"
)

// Where each endpoint's private key is generated (epic B2).
//
// B2 changes a custody fact: for a target marked agent-executed, the subject key
// is generated on the host that will serve it and the control plane never holds
// it. The change is invisible from every other surface — the certificates look
// identical, the deploys look identical — so without this view an operator
// migrating an estate has no way to answer the only question that matters:
// which of my endpoints have actually moved?
//
// It is deliberately a MIGRATION view rather than a compliance badge. Most rows
// in a real estate will say control_plane for a long time, and that is not a
// finding to be hidden — it is the work remaining, and an operator cannot plan
// against a surface that only shows the parts already done.

// EndpointKeyCustody is one deployment target's key-generation posture.
type EndpointKeyCustody struct {
	TargetID  string `json:"target_id"`
	Name      string `json:"name"`
	Connector string `json:"connector"`
	// Executor is what the target's configuration says: "agent" means this
	// target has opted into host-generated keys, anything else means the legacy
	// control-plane path.
	Executor string `json:"executor"`
	// Origin is the custody vocabulary term for where keys for this target are
	// generated NOW — a fact about configuration, not about any one
	// certificate. Certificates issued before a target was migrated keep their
	// own recorded origin, which is why the two are reported separately.
	Origin string `json:"origin"`
	// KeyBytesLeaveControlPlane states the property in the terms an auditor
	// asks about, rather than making them derive it from Executor.
	KeyBytesLeaveControlPlane bool `json:"key_bytes_leave_control_plane"`
	// Enabled is carried because a disabled target deploys nothing, and a
	// migration surface that showed it as outstanding work would send an
	// operator to fix something that is switched off.
	Enabled bool `json:"enabled"`
	// Detail is the one-line explanation for this row's posture.
	Detail string `json:"detail"`
	// LastExecutedByAgent is the agent that last performed a host-generated
	// renewal for this target, read from the receipt it signed.
	//
	// An OBSERVATION, not an assignment: a target is not bound to a named agent
	// in this design, so this says who last did the work rather than who is
	// responsible for it. Empty means no host-generated renewal has been
	// observed for this target — which for a control-plane target is simply the
	// expected state, and for an agent-executed one means the migration is
	// configured but has not run yet.
	LastExecutedByAgent string `json:"last_executed_by_agent,omitempty"`
	LastExecutedAt      string `json:"last_executed_at,omitempty"`
	LastExecutedOutcome string `json:"last_executed_outcome,omitempty"`
}

// EndpointKeyCustodyList is the served migration view.
type EndpointKeyCustodyList struct {
	Items   []EndpointKeyCustody   `json:"items"`
	Summary EndpointCustodySummary `json:"summary"`
	// Guidance travels with the data rather than living in documentation
	// nobody opens mid-migration.
	Guidance string `json:"guidance"`
}

// EndpointCustodySummary is the migration headline.
type EndpointCustodySummary struct {
	Targets int `json:"targets"`
	// HostGenerated counts targets where the key is born on the host.
	HostGenerated int `json:"host_generated"`
	// ControlPlaneGenerated counts targets still on the legacy path. Named for
	// what it IS rather than "remaining" or "at risk": these targets work, and
	// an estate that never migrates one of them is not broken.
	ControlPlaneGenerated int `json:"control_plane_generated"`
	// MigratedPercent is a percentage OF CONFIGURED TARGETS. An estate with no
	// deployment targets reports zero rather than a hundred — nothing has
	// migrated, and rounding an empty set up to complete is the exact class of
	// flattery this workstream exists to remove.
	MigratedPercent int `json:"migrated_percent"`
}

const endpointCustodyGuidance = "This view answers one question: for each deployment target, whose process " +
	"generates the private key. A target marked executor=agent has its key generated on the host that will serve " +
	"it, and the control plane refuses to send key material to it at all — that refusal is enforced, not advisory, " +
	"so a target cannot appear migrated while still receiving keys. Every other target uses the control-plane path, " +
	"which works and is not a defect; it is the migration remaining. Certificates issued before a target moved keep " +
	"the custody recorded at their own issuance, so this row describes the target's posture today rather than the " +
	"history of what it has served."

// The marker is read through internal/custody, the same definition the control
// plane's parity gate uses. It was briefly duplicated here with a comment
// claiming a guard test aligned the two; no such test existed, and a console
// that read the marker differently would report a target as migrated while the
// control plane kept sending it keys.

// EndpointRenewalExecutorView is the internal shape used to join observed
// executors onto targets.
type EndpointRenewalExecutorView struct {
	Agent      string
	Outcome    string
	ObservedAt string
}

func (a *API) listEndpointKeyCustody(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.store == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "deployment targets are not configured"))
		return
	}
	targets, err := a.store.ListDeploymentTargets(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}

	// Best effort: a control plane that cannot read receipts still reports the
	// custody posture, which is the load-bearing part. Losing the executor name
	// costs an operator a detail; losing the posture would cost them the answer.
	executors := map[string]EndpointRenewalExecutorView{}
	if observed, execErr := a.store.LastRenewalExecutors(r.Context(), tenantID); execErr == nil {
		for _, rec := range observed {
			executors[rec.TargetID] = EndpointRenewalExecutorView{
				Agent: rec.Agent, Outcome: rec.Outcome, ObservedAt: rec.ObservedAt,
			}
		}
	}

	out := EndpointKeyCustodyList{
		Items:    make([]EndpointKeyCustody, 0, len(targets)),
		Guidance: endpointCustodyGuidance,
	}
	for _, t := range targets {
		hostGenerated := custody.TargetExecutorIsAgent(t.Config)
		item := EndpointKeyCustody{
			TargetID: t.ID, Name: t.Name, Connector: t.Type, Enabled: t.Enabled,
		}
		if hostGenerated {
			item.Executor = custody.ExecutorAgent
			item.Origin = string(custody.OriginHostAgent)
			item.KeyBytesLeaveControlPlane = false
			item.Detail = "Keys for this target are generated on the host that serves them. The control " +
				"plane refuses to send private key material here."
			out.Summary.HostGenerated++
		} else {
			item.Executor = "control_plane"
			item.Origin = string(custody.OriginControlPlane)
			item.KeyBytesLeaveControlPlane = true
			item.Detail = "Keys for this target are generated by the control plane and delivered sealed. " +
				"Set executor=agent on this target, with a host agent enrolled, to move key generation " +
				"onto the host."
			out.Summary.ControlPlaneGenerated++
		}
		if exec, ok := executors[t.ID]; ok {
			item.LastExecutedByAgent = exec.Agent
			item.LastExecutedAt = exec.ObservedAt
			item.LastExecutedOutcome = exec.Outcome
		}
		out.Items = append(out.Items, item)
	}
	out.Summary.Targets = len(targets)
	if out.Summary.Targets > 0 {
		out.Summary.MigratedPercent = out.Summary.HostGenerated * 100 / out.Summary.Targets
	}
	// Stable order so a console table does not reshuffle between polls.
	sort.SliceStable(out.Items, func(i, j int) bool { return out.Items[i].Name < out.Items[j].Name })
	a.writeJSON(w, http.StatusOK, out)
}
