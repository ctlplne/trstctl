// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"net/http"
	"time"

	"trstctl.com/trstctl/internal/api/problem"
)

// LifecycleAutomationPlanProvider owns the lifecycle scheduler explanation. The
// browser consumes this read model instead of reimplementing renewal policy from
// several unrelated endpoints.
type LifecycleAutomationPlanProvider interface {
	LifecycleAutomationPlan(context.Context, string, time.Time) (LifecycleAutomationPlan, error)
}

type LifecycleAutomationPlan struct {
	Capability             string                       `json:"capability"`
	Ready                  bool                         `json:"ready"`
	GeneratedAt            time.Time                    `json:"generated_at"`
	Scheduler              LifecycleAutomationScheduler `json:"scheduler"`
	Summary                LifecycleAutomationSummary   `json:"summary"`
	Items                  []LifecycleAutomationItem    `json:"items"`
	Controls               []LifecycleAutomationControl `json:"controls"`
	PreviewWrites          []string                     `json:"preview_writes"`
	PreviewExternalEffects []string                     `json:"preview_external_effects"`
	ExecutionWrites        []string                     `json:"execution_writes"`
	ExecutionEffects       []string                     `json:"execution_external_effects"`
	VerificationSteps      []string                     `json:"verification_steps"`
}

type LifecycleAutomationScheduler struct {
	Status                  string     `json:"status"`
	RenewBefore             string     `json:"renew_before"`
	RenewBeforeSeconds      int64      `json:"renew_before_seconds"`
	AlertBefore             string     `json:"alert_before"`
	AlertBeforeSeconds      int64      `json:"alert_before_seconds"`
	Interval                string     `json:"interval"`
	IntervalSeconds         int64      `json:"interval_seconds"`
	ARIFirst                bool       `json:"ari_first"`
	MaintenanceWindowStatus string     `json:"maintenance_window_status"`
	MaintenanceDeferral     string     `json:"maintenance_deferral,omitempty"`
	NextOpen                *time.Time `json:"next_open,omitempty"`
}

type LifecycleAutomationSummary struct {
	Monitored        int `json:"monitored"`
	DueNow           int `json:"due_now"`
	RenewalFailed    int `json:"renewal_failed"`
	OutboxPending    int `json:"outbox_pending"`
	OutboxProcessing int `json:"outbox_processing"`
	OutboxFailed     int `json:"outbox_failed"`
}

type LifecycleAutomationItem struct {
	IdentityID      string     `json:"identity_id"`
	IdentityName    string     `json:"identity_name"`
	IdentityStatus  string     `json:"identity_status"`
	OwnerID         string     `json:"owner_id"`
	OwnerName       string     `json:"owner_name"`
	CertificateID   string     `json:"certificate_id"`
	NotAfter        *time.Time `json:"not_after,omitempty"`
	Due             bool       `json:"due"`
	RenewalSource   string     `json:"renewal_source"`
	Reason          string     `json:"reason"`
	LatestRunID     string     `json:"latest_run_id,omitempty"`
	LatestRunStatus string     `json:"latest_run_status,omitempty"`
	RollbackRef     string     `json:"rollback_ref,omitempty"`
	Blockers        []string   `json:"blockers"`
}

type LifecycleAutomationControl struct {
	Action string `json:"action"`
	State  string `json:"state"`
	Detail string `json:"detail"`
}

// WithLifecycleAutomationPlan wires the effect-free F6 operator plan.
func WithLifecycleAutomationPlan(provider LifecycleAutomationPlanProvider) Option {
	return func(c *config) { c.lifecycleAutomationPlan = provider }
}

func (a *API) getLifecycleAutomationPlan(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.lifecycleAutomationPlan == nil {
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "lifecycle automation plan is not assembled"))
		return
	}
	plan, err := a.lifecycleAutomationPlan.LifecycleAutomationPlan(r.Context(), tenantID, time.Now().UTC())
	if err != nil {
		a.writeError(w, err)
		return
	}
	plan.Items = append([]LifecycleAutomationItem{}, plan.Items...)
	plan.Controls = append([]LifecycleAutomationControl{}, plan.Controls...)
	plan.PreviewWrites = append([]string{}, plan.PreviewWrites...)
	plan.PreviewExternalEffects = append([]string{}, plan.PreviewExternalEffects...)
	plan.ExecutionWrites = append([]string{}, plan.ExecutionWrites...)
	plan.ExecutionEffects = append([]string{}, plan.ExecutionEffects...)
	plan.VerificationSteps = append([]string{}, plan.VerificationSteps...)
	for index := range plan.Items {
		plan.Items[index].Blockers = append([]string{}, plan.Items[index].Blockers...)
	}
	a.writeJSON(w, http.StatusOK, plan)
}
