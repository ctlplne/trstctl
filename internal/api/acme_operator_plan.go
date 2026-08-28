// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"net/http"
	"time"
)

// ACMEOperatorAction is the one next step selected by the assembled server. The
// browser may render or invoke this step; it must not infer a different action
// from partial configuration reads.
type ACMEOperatorAction struct {
	Kind   string `json:"kind"`
	Label  string `json:"label"`
	Detail string `json:"detail"`
	Method string `json:"method,omitempty"`
	Path   string `json:"path,omitempty"`
}

// ACMEOperatorPlan is a tenant-bound, secret-free, effect-free answer to "can an
// ACME client use this control plane now?" It joins the mounted responder,
// activation gate, issuing profile, EAB admission, and DNS automation state at
// request time. Empty preview effect lists are explicit evidence, not an omitted
// implementation detail.
type ACMEOperatorPlan struct {
	Ready                  bool               `json:"ready"`
	Served                 bool               `json:"served"`
	TenantBound            bool               `json:"tenant_bound"`
	DirectoryPath          string             `json:"directory_path"`
	ChallengeMethods       []string           `json:"challenge_methods"`
	EABRequired            bool               `json:"eab_required"`
	EABConfigured          int                `json:"eab_configured"`
	EABActive              int                `json:"eab_active"`
	DNS01ProviderConfigs   int                `json:"dns01_provider_configs"`
	IssuingProfile         string             `json:"issuing_profile"`
	IssuingProfileReady    bool               `json:"issuing_profile_ready"`
	ActivationMode         string             `json:"activation_mode"`
	ActivationRequired     bool               `json:"activation_required"`
	ActivationAvailable    bool               `json:"activation_available"`
	NextAction             ACMEOperatorAction `json:"next_action"`
	Blockers               []string           `json:"blockers"`
	Warnings               []string           `json:"warnings"`
	RecoverySteps          []string           `json:"recovery_steps"`
	PreviewWrites          []string           `json:"preview_writes"`
	PreviewExternalEffects []string           `json:"preview_external_effects"`
	GeneratedAt            time.Time          `json:"generated_at"`
}

// ACMEOperatorPlanProvider resolves the late-bound protocol assembly for one
// authenticated tenant. Server.Build constructs the API before it constructs the
// protocol mounts, so this must be a provider rather than a captured value.
type ACMEOperatorPlanProvider func(ctx context.Context, tenantID string) (ACMEOperatorPlan, error)

// WithACMEOperatorPlan wires the server-owned ACME readiness and recovery plan.
func WithACMEOperatorPlan(provider ACMEOperatorPlanProvider) Option {
	return func(c *config) { c.acmeOperatorPlan = provider }
}

func (a *API) getACMEOperatorPlan(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.acmeOperatorPlan == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "ACME operator plan is not assembled"))
		return
	}
	plan, err := a.acmeOperatorPlan(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	if plan.ChallengeMethods == nil {
		plan.ChallengeMethods = []string{}
	}
	if plan.Blockers == nil {
		plan.Blockers = []string{}
	}
	if plan.Warnings == nil {
		plan.Warnings = []string{}
	}
	if plan.RecoverySteps == nil {
		plan.RecoverySteps = []string{}
	}
	if plan.PreviewWrites == nil {
		plan.PreviewWrites = []string{}
	}
	if plan.PreviewExternalEffects == nil {
		plan.PreviewExternalEffects = []string{}
	}
	if plan.GeneratedAt.IsZero() {
		plan.GeneratedAt = time.Now().UTC()
	}
	a.writeJSON(w, http.StatusOK, plan)
}
