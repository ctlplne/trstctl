// SPDX-License-Identifier: MPL-2.0

package api

import (
	"net/http"
	"time"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/store"
)

type KubernetesPostureSummary struct {
	Controllers int `json:"controllers"`
	Complete    int `json:"complete_controllers"`
	Stale       int `json:"stale_controllers"`
	Observed    int `json:"observed"`
	Ready       int `json:"ready"`
	Pending     int `json:"pending"`
	Failed      int `json:"failed"`
}

type KubernetesPostureController struct {
	ControllerID      string `json:"controller_id"`
	ClusterID         string `json:"cluster_id"`
	ReportID          string `json:"report_id"`
	ReconcileComplete bool   `json:"reconcile_complete"`
	FailureCode       string `json:"failure_code,omitempty"`
	LastSync          string `json:"last_sync"`
	Stale             bool   `json:"stale"`
	Observed          int    `json:"observed"`
	Ready             int    `json:"ready"`
	Pending           int    `json:"pending"`
	Failed            int    `json:"failed"`
}

type KubernetesPostureObject struct {
	ControllerID    string `json:"controller_id"`
	ClusterID       string `json:"cluster_id"`
	Namespace       string `json:"namespace,omitempty"`
	Name            string `json:"name"`
	UID             string `json:"uid"`
	ResourceVersion string `json:"resource_version"`
	State           string `json:"state"`
	Reason          string `json:"reason"`
	PublicHash      string `json:"public_hash,omitempty"`
}

type KubernetesCSRSupport struct {
	Capability  string                        `json:"capability"`
	Served      bool                          `json:"served"`
	GeneratedAt string                        `json:"generated_at"`
	LastSync    string                        `json:"last_sync"`
	APIGroup    string                        `json:"api_group"`
	APIVersion  string                        `json:"api_version"`
	Resource    string                        `json:"resource"`
	Summary     KubernetesPostureSummary      `json:"summary"`
	Controllers []KubernetesPostureController `json:"controllers"`
	Objects     []KubernetesPostureObject     `json:"objects"`
}

type KubernetesTrustBundleDistribution struct {
	Capability  string                        `json:"capability"`
	Served      bool                          `json:"served"`
	GeneratedAt string                        `json:"generated_at"`
	LastSync    string                        `json:"last_sync"`
	APIGroup    string                        `json:"api_group"`
	APIVersion  string                        `json:"api_version"`
	Resource    string                        `json:"resource"`
	Summary     KubernetesPostureSummary      `json:"summary"`
	Controllers []KubernetesPostureController `json:"controllers"`
	Objects     []KubernetesPostureObject     `json:"objects"`
}

func (a *API) getKubernetesCSRSupport(w http.ResponseWriter, r *http.Request) {
	rows, ok := a.kubernetesPostureRows(w, r, store.KubernetesPostureCertificateSigningRequests)
	if !ok {
		return
	}
	generatedAt := time.Now().UTC()
	state := buildKubernetesPosture(rows, generatedAt)
	a.writeJSON(w, http.StatusOK, KubernetesCSRSupport{
		Capability: "CAP-K8S-04", Served: state.served,
		GeneratedAt: generatedAt.Format(time.RFC3339), LastSync: state.lastSync,
		APIGroup: "certificates.k8s.io", APIVersion: "certificates.k8s.io/v1", Resource: "certificatesigningrequests",
		Summary: state.summary, Controllers: state.controllers, Objects: state.objects,
	})
}

func (a *API) getKubernetesTrustBundleDistribution(w http.ResponseWriter, r *http.Request) {
	rows, ok := a.kubernetesPostureRows(w, r, store.KubernetesPostureTrustBundles)
	if !ok {
		return
	}
	generatedAt := time.Now().UTC()
	state := buildKubernetesPosture(rows, generatedAt)
	a.writeJSON(w, http.StatusOK, KubernetesTrustBundleDistribution{
		Capability: "CAP-K8S-07", Served: state.served,
		GeneratedAt: generatedAt.Format(time.RFC3339), LastSync: state.lastSync,
		APIGroup: "trstctl.com", APIVersion: "trstctl.com/v1alpha1", Resource: "trustbundles",
		Summary: state.summary, Controllers: state.controllers, Objects: state.objects,
	})
}

func (a *API) kubernetesPostureRows(w http.ResponseWriter, r *http.Request, capability string) ([]store.KubernetesControllerPosture, bool) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return nil, false
	}
	if a.store == nil {
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "Kubernetes controller posture store is not configured"))
		return nil, false
	}
	rows, err := a.store.ListKubernetesControllerPosture(r.Context(), tenantID, capability)
	if err != nil {
		a.writeError(w, err)
		return nil, false
	}
	if len(rows) == 0 {
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "no authenticated Kubernetes controller report has been received for this tenant"))
		return nil, false
	}
	return rows, true
}

type kubernetesPostureState struct {
	served      bool
	lastSync    string
	summary     KubernetesPostureSummary
	controllers []KubernetesPostureController
	objects     []KubernetesPostureObject
}

func buildKubernetesPosture(rows []store.KubernetesControllerPosture, now time.Time) kubernetesPostureState {
	state := kubernetesPostureState{
		controllers: make([]KubernetesPostureController, 0, len(rows)),
		objects:     make([]KubernetesPostureObject, 0),
	}
	var latest time.Time
	for _, row := range rows {
		controller := KubernetesPostureController{
			ControllerID: row.ControllerID, ClusterID: row.ClusterID, ReportID: row.ReportID,
			ReconcileComplete: row.ReconcileComplete, FailureCode: row.FailureCode,
			LastSync: row.ReportedAt.UTC().Format(time.RFC3339), Observed: len(row.Resources),
		}
		staleAfter := 2 * time.Duration(row.ReconcileIntervalSeconds) * time.Second
		if staleAfter < time.Minute {
			staleAfter = time.Minute
		}
		controller.Stale = now.Sub(row.ReportedAt) > staleAfter
		for _, resource := range row.Resources {
			switch resource.State {
			case "ready":
				controller.Ready++
			case "pending":
				controller.Pending++
			case "failed":
				controller.Failed++
			}
			state.objects = append(state.objects, KubernetesPostureObject{
				ControllerID: row.ControllerID, ClusterID: row.ClusterID,
				Namespace: resource.Namespace, Name: resource.Name, UID: resource.UID,
				ResourceVersion: resource.ResourceVersion, State: resource.State,
				Reason: resource.Reason, PublicHash: resource.PublicHash,
			})
		}
		state.summary.Controllers++
		if controller.Stale {
			state.summary.Stale++
		}
		if row.ReconcileComplete {
			state.summary.Complete++
			if !controller.Stale {
				state.served = true
			}
		}
		state.summary.Observed += controller.Observed
		state.summary.Ready += controller.Ready
		state.summary.Pending += controller.Pending
		state.summary.Failed += controller.Failed
		state.controllers = append(state.controllers, controller)
		if row.ReportedAt.After(latest) {
			latest = row.ReportedAt
		}
	}
	if !latest.IsZero() {
		state.lastSync = latest.UTC().Format(time.RFC3339)
	}
	return state
}
