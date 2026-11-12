// SPDX-License-Identifier: BUSL-1.1

package operator

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// The control plane's availability and metrics surfaces (HELM-O1), rendered
// the way the Helm chart renders them: a PodDisruptionBudget so a voluntary
// disruption (a node drain, a cluster upgrade) keeps control-plane pods
// serving, and a Prometheus Operator ServiceMonitor that scrapes /metrics
// through the control plane's Service.

// PodDisruptionBudgetSpec is the control plane's disruption budget. It is on
// when the control plane runs more than one replica, unless enabled says
// otherwise: a budget cannot protect a single replica, and one with
// minAvailable 1 would block every drain of its node.
type PodDisruptionBudgetSpec struct {
	Enabled      *bool `json:"enabled,omitempty"`
	MinAvailable int   `json:"minAvailable,omitempty"`
}

// ServiceMonitorSpec is an optional Prometheus Operator ServiceMonitor for the
// control plane's metrics. It needs the monitoring.coreos.com/v1 API.
type ServiceMonitorSpec struct {
	Enabled       bool              `json:"enabled"`
	Interval      string            `json:"interval,omitempty"`
	ScrapeTimeout string            `json:"scrapeTimeout,omitempty"`
	Path          string            `json:"path,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
	// TLSConfig is the endpoint's tlsConfig as the Prometheus Operator takes
	// it (for example caFile or ca, serverName); the API serves HTTPS.
	TLSConfig map[string]any `json:"tlsConfig,omitempty"`
}

func (s ControlPlaneSpec) podDisruptionBudgetEnabled() bool {
	if s.PodDisruptionBudget.Enabled != nil {
		return *s.PodDisruptionBudget.Enabled
	}
	return s.desiredReplicas() > 1
}

func (s ControlPlaneSpec) podDisruptionBudgetMinAvailable() int {
	if s.PodDisruptionBudget.MinAvailable > 0 {
		return s.PodDisruptionBudget.MinAvailable
	}
	return 1
}

// availabilityError refuses a budget that would block every drain, and a
// ServiceMonitor whose timings Prometheus could not use.
func (s ControlPlaneSpec) availabilityError() error {
	if s.PodDisruptionBudget.MinAvailable < 0 {
		return fmt.Errorf("operator: spec.podDisruptionBudget.minAvailable must be at least 1")
	}
	if s.podDisruptionBudgetEnabled() && s.podDisruptionBudgetMinAvailable() >= s.desiredReplicas() {
		return fmt.Errorf("operator: spec.podDisruptionBudget.minAvailable %d with %d replicas would block every voluntary disruption; run more replicas, lower minAvailable, or set spec.podDisruptionBudget.enabled false",
			s.podDisruptionBudgetMinAvailable(), s.desiredReplicas())
	}
	if !s.ServiceMonitor.Enabled {
		return nil
	}
	for field, value := range map[string]string{"interval": s.ServiceMonitor.Interval, "scrapeTimeout": s.ServiceMonitor.ScrapeTimeout} {
		if strings.TrimSpace(value) == "" {
			continue
		}
		if d, err := time.ParseDuration(value); err != nil || d <= 0 {
			return fmt.Errorf("operator: spec.serviceMonitor.%s %q is not a positive duration", field, value)
		}
	}
	if p := strings.TrimSpace(s.ServiceMonitor.Path); p != "" && !strings.HasPrefix(p, "/") {
		return fmt.Errorf("operator: spec.serviceMonitor.path %q must start with /", p)
	}
	return nil
}

func pdbCollectionPath(ns string) string {
	return fmt.Sprintf("/apis/policy/v1/namespaces/%s/poddisruptionbudgets", ns)
}
func pdbItemPath(ns, name string) string {
	return fmt.Sprintf("/apis/policy/v1/namespaces/%s/poddisruptionbudgets/%s", ns, name)
}

const serviceMonitorAPI = "/apis/monitoring.coreos.com/v1"

func serviceMonitorCollectionPath(ns string) string {
	return fmt.Sprintf("%s/namespaces/%s/servicemonitors", serviceMonitorAPI, ns)
}
func serviceMonitorItemPath(ns, name string) string {
	return fmt.Sprintf("%s/namespaces/%s/servicemonitors/%s", serviceMonitorAPI, ns, name)
}

// reconcileAvailability converges the disruption budget and the ServiceMonitor,
// removing either one the spec no longer asks for.
func (r *Reconciler) reconcileAvailability(ctx context.Context, namespace string, cr controlPlaneObject) (map[string]Action, error) {
	actions := map[string]Action{}
	name := r.deploymentName(cr.Metadata.Name)
	if cr.Spec.podDisruptionBudgetEnabled() {
		action, err := r.applyManaged(ctx, r.podDisruptionBudgetObject(namespace, cr))
		actions["podDisruptionBudget"] = action
		if err != nil {
			return actions, err
		}
	} else if removed, err := r.deleteManaged(ctx, "PodDisruptionBudget", pdbItemPath(namespace, name), cr.Metadata.Name); err != nil {
		return actions, err
	} else if removed {
		actions["podDisruptionBudget"] = ActionDelete
	}
	installed, err := r.serviceMonitorInstalled(ctx)
	if err != nil {
		return actions, err
	}
	switch {
	case cr.Spec.ServiceMonitor.Enabled && !installed:
		return actions, fmt.Errorf("operator: spec.serviceMonitor needs the monitoring.coreos.com/v1 API (the Prometheus Operator's ServiceMonitor), which this cluster does not serve; install it or set spec.serviceMonitor.enabled false")
	case cr.Spec.ServiceMonitor.Enabled:
		action, err := r.applyManaged(ctx, r.serviceMonitorObject(namespace, cr))
		actions["serviceMonitor"] = action
		if err != nil {
			return actions, err
		}
	case installed:
		removed, err := r.deleteManaged(ctx, "ServiceMonitor", serviceMonitorItemPath(namespace, name), cr.Metadata.Name)
		if err != nil {
			return actions, err
		}
		if removed {
			actions["serviceMonitor"] = ActionDelete
		}
	}
	return actions, nil
}

// serviceMonitorInstalled reports whether the cluster serves the Prometheus
// Operator's monitoring.coreos.com/v1 API.
func (r *Reconciler) serviceMonitorInstalled(ctx context.Context) (bool, error) {
	st, _, err := r.client.do(ctx, http.MethodGet, serviceMonitorAPI, "", nil)
	if err != nil {
		return false, err
	}
	switch {
	case st/100 == 2:
		return true, nil
	case st == http.StatusNotFound:
		return false, nil
	default:
		return false, fmt.Errorf("operator: discover %s: status %d", serviceMonitorAPI, st)
	}
}

func (r *Reconciler) podDisruptionBudgetObject(namespace string, cr controlPlaneObject) managedObject {
	name := r.deploymentName(cr.Metadata.Name)
	return managedObject{
		kind: "PodDisruptionBudget", name: name, namespace: namespace, controlPlaneCR: cr.Metadata.Name,
		collectionPath: pdbCollectionPath(namespace), itemPath: pdbItemPath(namespace, name),
		object: map[string]any{
			"apiVersion": "policy/v1",
			"kind":       "PodDisruptionBudget",
			"metadata":   ownedMetadata(namespace, name, cr, "control-plane"),
			"spec": map[string]any{
				"minAvailable": cr.Spec.podDisruptionBudgetMinAvailable(),
				"selector":     map[string]any{"matchLabels": map[string]any{controlPlaneLabel: cr.Metadata.Name}},
			},
		},
	}
}

func (r *Reconciler) serviceMonitorObject(namespace string, cr controlPlaneObject) managedObject {
	name := r.deploymentName(cr.Metadata.Name)
	meta := ownedMetadata(namespace, name, cr, "control-plane")
	labels := meta["labels"].(map[string]any)
	for key, value := range cr.Spec.ServiceMonitor.Labels {
		if _, reserved := labels[key]; !reserved {
			labels[key] = value
		}
	}
	endpoint := map[string]any{
		"port":          "https",
		"path":          firstSet(cr.Spec.ServiceMonitor.Path, "/metrics"),
		"scheme":        "https",
		"interval":      firstSet(cr.Spec.ServiceMonitor.Interval, "30s"),
		"scrapeTimeout": firstSet(cr.Spec.ServiceMonitor.ScrapeTimeout, "10s"),
	}
	if len(cr.Spec.ServiceMonitor.TLSConfig) > 0 {
		endpoint["tlsConfig"] = cr.Spec.ServiceMonitor.TLSConfig
	}
	return managedObject{
		kind: "ServiceMonitor", name: name, namespace: namespace, controlPlaneCR: cr.Metadata.Name,
		collectionPath: serviceMonitorCollectionPath(namespace), itemPath: serviceMonitorItemPath(namespace, name),
		object: map[string]any{
			"apiVersion": "monitoring.coreos.com/v1",
			"kind":       "ServiceMonitor",
			"metadata":   meta,
			"spec": map[string]any{
				// The control plane's own Service, not its isolated signer's.
				"selector":  map[string]any{"matchLabels": map[string]any{ownerLabel: cr.Metadata.Name, "app.kubernetes.io/component": "control-plane"}},
				"endpoints": []map[string]any{endpoint},
			},
		},
	}
}
