// SPDX-License-Identifier: MPL-2.0

package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"trstctl.com/trstctl/internal/graph"
	"trstctl.com/trstctl/internal/migration"
	"trstctl.com/trstctl/internal/store"
)

// The migration wave surface (epic H2).
//
// Two routes, and the split between them is the point. Assess is read-only and
// says what a migration WOULD touch and what is unknown about it; the plan
// routes are what actually runs. Keeping them apart in the API — rather than a
// dry_run flag on one endpoint — means a caller cannot accidentally execute by
// omitting a parameter, which is the failure mode a boolean invites.

// migrationAssessRequest names the cohort an operator wants assessed.
type migrationAssessRequest struct {
	PlanID string `json:"plan_id"`
	// Waves are ordered cohorts of identity IDs.
	Waves []struct {
		ID      string   `json:"id"`
		Ordinal int      `json:"ordinal"`
		Members []string `json:"members"`
	} `json:"waves"`
	RequireFullTrust bool `json:"require_full_trust"`
	MinTrustPercent  int  `json:"min_trust_percent"`
}

// assessMigration enumerates what a migration would touch, mutating nothing.
func (a *API) assessMigration(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	var req migrationAssessRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, "invalid JSON body: "+err.Error()))
		return
	}
	plan := migration.Plan{
		ID: req.PlanID, RequireFullTrust: req.RequireFullTrust,
		MinTrustPercent: req.MinTrustPercent,
	}
	for _, wv := range req.Waves {
		plan.Waves = append(plan.Waves, migration.Wave{
			ID: wv.ID, Ordinal: wv.Ordinal, Members: wv.Members, Phase: migration.PhasePlanned,
		})
	}
	if err := migration.ValidatePlan(plan); err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, err.Error()))
		return
	}

	facts, err := a.migrationFacts(r, tenantID, plan)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, migration.Assess(plan, facts))
}

// migrationFacts gathers what is already known about each member.
//
// It reads the trust graph (H1) and the deployment targets, and it is the reason
// the assessment can distinguish "no trust store" from "an empty trust store":
// the graph records what was OBSERVED, so a member whose host has no store node
// is a member nobody scanned, not a member confirmed bare.
func (a *API) migrationFacts(r *http.Request, tenantID string, plan migration.Plan) (map[string]migration.MemberFacts, error) {
	out := map[string]migration.MemberFacts{}
	if a.store == nil {
		return out, nil
	}
	g, err := graph.Build(r.Context(), a.store, tenantID)
	if err != nil {
		return nil, err
	}
	targets, err := a.store.ListDeploymentTargets(r.Context(), tenantID)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]store.DeploymentTarget, len(targets))
	for _, t := range targets {
		byID[t.ID] = t
	}

	// Count trust stores per host once, rather than per member: a wave of a
	// hundred identities on ten hosts should walk the graph once.
	storesByHost := map[string]int{}
	for _, n := range g.Nodes() {
		if n.Kind == graph.KindTrustStore {
			storesByHost[n.Attrs["host"]]++
		}
	}

	for _, wv := range plan.Waves {
		for _, m := range wv.Members {
			ident, identErr := a.store.GetIdentity(r.Context(), tenantID, m)
			if identErr != nil {
				// An identity we cannot read stays ABSENT from the facts map, so
				// Assess reports it as unknown rather than as assessed-and-fine.
				continue
			}
			f := migration.MemberFacts{Member: m}
			if t, found := byID[targetIDFromIdentityAttrs(ident.Attributes)]; found {
				f.HasDeploymentTarget = true
				f.HasVerifyAddress = targetHasVerifyAddress(t.Config)
				f.TrustStoresObserved = storesByHost[t.Name]
			}
			out[m] = f
		}
	}
	return out, nil
}

// targetIDFromIdentityAttrs reads the deployment target an identity is bound to.
func targetIDFromIdentityAttrs(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var attrs map[string]any
	if err := json.Unmarshal(raw, &attrs); err != nil {
		return ""
	}
	id, _ := attrs["deployment_target_id"].(string)
	return id
}

// targetHasVerifyAddress reports whether a target can ever satisfy the live gate.
//
// Absent means it cannot: D2's verification only runs against a configured
// listener, so a member without one would sit unobserved forever rather than
// failing — which is exactly the kind of silent stall the assessment exists to
// surface before the migration starts rather than during it.
func targetHasVerifyAddress(cfg json.RawMessage) bool {
	if len(cfg) == 0 {
		return false
	}
	var fields map[string]any
	if err := json.Unmarshal(cfg, &fields); err != nil {
		return false
	}
	addr, _ := fields["verify_address"].(string)
	return strings.TrimSpace(addr) != ""
}
