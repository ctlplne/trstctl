package operator

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// API paths for the two resource kinds the operator drives.
const (
	tcpAPIGroupVersion = "trstctl.com/v1alpha1"
	tcpPlural          = "trstctlcontrolplanes"
	deploymentsGroup   = "apps/v1"
)

// defaultControlPlaneImage is used when a TrstctlControlPlane omits spec.image.
// It names the single multi-binary control-plane image the release pipeline
// builds (deploy/docker/Dockerfile, .github/workflows/release.yml); the operator
// runs from that same image via an entrypoint override.
const defaultControlPlaneImage = "ghcr.io/imfeelingtheagi/trstctl:latest"

// ControlPlaneSpec is the desired state declared on a TrstctlControlPlane.spec.
// Only the fields the operator acts on are modelled; unknown fields are ignored.
type ControlPlaneSpec struct {
	Replicas   int    `json:"replicas"`
	Image      string `json:"image"`
	SignerMode string `json:"signerMode"`
}

// desiredReplicas returns the spec's replica count, defaulting to 1 (the CRD's
// minimum) when unset or invalid, so the operator never scales a control plane to
// zero from an omitted field.
func (s ControlPlaneSpec) desiredReplicas() int {
	if s.Replicas < 1 {
		return 1
	}
	return s.Replicas
}

// desiredImage returns the spec's image, defaulting to the built control-plane
// image when unset.
func (s ControlPlaneSpec) desiredImage() string {
	if strings.TrimSpace(s.Image) == "" {
		return defaultControlPlaneImage
	}
	return s.Image
}

// controlPlaneObject is a decoded TrstctlControlPlane custom resource.
type controlPlaneObject struct {
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"metadata"`
	Spec   ControlPlaneSpec `json:"spec"`
	Status struct {
		Phase         string `json:"phase"`
		ReadySurfaces int    `json:"readySurfaces"`
	} `json:"status"`
}

// deploymentState is the slice of the managed control-plane Deployment the
// reconciler compares against desired state.
type deploymentState struct {
	exists          bool
	replicas        int
	image           string
	resourceVersion string
}

// Action is the decision a single reconcile makes for one TrstctlControlPlane:
// it is what the operator will do to converge the Deployment toward the spec. It
// is returned (and asserted in tests) so the decision is observable, not hidden
// inside an HTTP call.
type Action string

const (
	// ActionNone means the live Deployment already matches the spec.
	ActionNone Action = "none"
	// ActionCreate means no Deployment exists; the operator creates it.
	ActionCreate Action = "create"
	// ActionUpdate means a Deployment exists but its replicas/image drifted from
	// the spec; the operator patches it back.
	ActionUpdate Action = "update"
)

// decideAction is the pure desired-vs-actual diff at the centre of the
// reconcile. Given the spec and the live Deployment, it returns the action to
// take. Keeping it pure makes the controller's behaviour unit-testable without a
// cluster: the reconcile test asserts decideAction returns the right action for
// each missing/drifted/in-sync case.
func decideAction(spec ControlPlaneSpec, live deploymentState) Action {
	if !live.exists {
		return ActionCreate
	}
	if live.replicas != spec.desiredReplicas() || live.image != spec.desiredImage() {
		return ActionUpdate
	}
	return ActionNone
}

// Reconciler drives TrstctlControlPlane resources toward their declared state.
// It is intentionally level-based (reconcile reads the world and converges it),
// so a missed event cannot leave the cluster wedged — the next poll re-reads and
// re-acts. The deploymentName/labels keep the managed object stable across
// reconciles so the operator owns exactly one control-plane Deployment per CR.
type Reconciler struct {
	client *Client
	// deploymentName is the name of the control-plane Deployment the operator
	// manages for a given TrstctlControlPlane (derived from the CR name).
	deploymentSuffix string
}

// NewReconciler returns a Reconciler using client for all API access.
func NewReconciler(client *Client) *Reconciler {
	return &Reconciler{client: client, deploymentSuffix: "-control-plane"}
}

// deploymentName is the control-plane Deployment name the operator manages for
// the named TrstctlControlPlane.
func (r *Reconciler) deploymentName(cr string) string { return cr + r.deploymentSuffix }

func tcpItemPath(ns, name string) string {
	return fmt.Sprintf("/apis/trstctl.com/v1alpha1/namespaces/%s/%s/%s", ns, tcpPlural, name)
}

func tcpCollectionPath(ns string) string {
	return fmt.Sprintf("/apis/trstctl.com/v1alpha1/namespaces/%s/%s", ns, tcpPlural)
}

func deploymentItemPath(ns, name string) string {
	return fmt.Sprintf("/apis/apps/v1/namespaces/%s/deployments/%s", ns, name)
}

func deploymentCollectionPath(ns string) string {
	return fmt.Sprintf("/apis/apps/v1/namespaces/%s/deployments", ns)
}

// ReconcileNamespace reconciles every TrstctlControlPlane in namespace and
// returns the per-resource actions taken (keyed by resource name), so the caller
// (and tests) can see exactly what converged. A reconcile error for one resource
// is returned immediately; the next poll retries the whole set.
func (r *Reconciler) ReconcileNamespace(ctx context.Context, namespace string) (map[string]Action, error) {
	st, body, err := r.client.do(ctx, http.MethodGet, tcpCollectionPath(namespace), "", nil)
	if err != nil {
		return nil, err
	}
	if st/100 != 2 {
		return nil, fmt.Errorf("operator: list trstctlcontrolplanes in %s: status %d: %s", namespace, st, string(body))
	}
	var list struct {
		Items []controlPlaneObject `json:"items"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("operator: decode trstctlcontrolplane list: %w", err)
	}
	actions := make(map[string]Action, len(list.Items))
	// Deterministic order so logs and tests are stable.
	sort.Slice(list.Items, func(i, j int) bool { return list.Items[i].Metadata.Name < list.Items[j].Metadata.Name })
	for _, cr := range list.Items {
		ns := cr.Metadata.Namespace
		if ns == "" {
			ns = namespace
		}
		action, err := r.Reconcile(ctx, ns, cr)
		if err != nil {
			return actions, fmt.Errorf("operator: reconcile %s/%s: %w", ns, cr.Metadata.Name, err)
		}
		actions[cr.Metadata.Name] = action
	}
	return actions, nil
}

// Reconcile converges one TrstctlControlPlane: it reads the live control-plane
// Deployment, decides the action via the pure decideAction diff, applies it
// (create or patch), and writes the resulting phase back to the CR status. It
// returns the action it took.
func (r *Reconciler) Reconcile(ctx context.Context, namespace string, cr controlPlaneObject) (Action, error) {
	live, err := r.observeDeployment(ctx, namespace, r.deploymentName(cr.Metadata.Name))
	if err != nil {
		return ActionNone, err
	}
	action := decideAction(cr.Spec, live)

	switch action {
	case ActionCreate:
		if err := r.createDeployment(ctx, namespace, cr); err != nil {
			return action, err
		}
	case ActionUpdate:
		if err := r.patchDeployment(ctx, namespace, r.deploymentName(cr.Metadata.Name), cr.Spec, live.resourceVersion); err != nil {
			return action, err
		}
	case ActionNone:
		// Already converged.
	}

	if err := r.updateStatus(ctx, namespace, cr.Metadata.Name, action); err != nil {
		// A status write failure must not mask a successful spec convergence: the
		// next poll will retry the status. Surface it so it is logged, but the
		// Deployment is already correct.
		return action, fmt.Errorf("operator: convergence applied (%s) but status update failed: %w", action, err)
	}
	return action, nil
}

// observeDeployment reads the live control-plane Deployment's replica count and
// image (the fields the operator owns), returning exists=false on 404.
func (r *Reconciler) observeDeployment(ctx context.Context, namespace, name string) (deploymentState, error) {
	st, body, err := r.client.do(ctx, http.MethodGet, deploymentItemPath(namespace, name), "", nil)
	if err != nil {
		return deploymentState{}, err
	}
	if st == http.StatusNotFound {
		return deploymentState{exists: false}, nil
	}
	if st/100 != 2 {
		return deploymentState{}, fmt.Errorf("operator: get deployment %s/%s: status %d: %s", namespace, name, st, string(body))
	}
	var dep struct {
		Metadata struct {
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
		Spec struct {
			Replicas int `json:"replicas"`
			Template struct {
				Spec struct {
					Containers []struct {
						Name  string `json:"name"`
						Image string `json:"image"`
					} `json:"containers"`
				} `json:"spec"`
			} `json:"template"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(body, &dep); err != nil {
		return deploymentState{}, fmt.Errorf("operator: decode deployment %s/%s: %w", namespace, name, err)
	}
	image := ""
	for _, c := range dep.Spec.Template.Spec.Containers {
		if c.Name == "control-plane" {
			image = c.Image
			break
		}
	}
	if image == "" && len(dep.Spec.Template.Spec.Containers) > 0 {
		image = dep.Spec.Template.Spec.Containers[0].Image
	}
	return deploymentState{
		exists:          true,
		replicas:        dep.Spec.Replicas,
		image:           image,
		resourceVersion: dep.Metadata.ResourceVersion,
	}, nil
}

// createDeployment POSTs a new control-plane Deployment matching the spec.
func (r *Reconciler) createDeployment(ctx context.Context, namespace string, cr controlPlaneObject) error {
	obj := r.deploymentObject(namespace, cr, "")
	st, body, err := r.client.do(ctx, http.MethodPost, deploymentCollectionPath(namespace), "", obj)
	if err != nil {
		return err
	}
	if st == http.StatusConflict {
		// Raced another writer/our own previous create: fall through to a patch on
		// the next reconcile rather than erroring.
		return nil
	}
	if st/100 != 2 {
		return fmt.Errorf("operator: create deployment in %s: status %d: %s", namespace, st, string(body))
	}
	return nil
}

// patchDeployment applies a strategic-merge patch that pins the replica count and
// the control-plane container image to the spec, leaving every other field the
// chart/operator set in place.
func (r *Reconciler) patchDeployment(ctx context.Context, namespace, name string, spec ControlPlaneSpec, _ string) error {
	patch := map[string]any{
		"spec": map[string]any{
			"replicas": spec.desiredReplicas(),
			"template": map[string]any{
				"spec": map[string]any{
					"containers": []map[string]any{
						{"name": "control-plane", "image": spec.desiredImage()},
					},
				},
			},
		},
	}
	st, body, err := r.client.do(ctx, http.MethodPatch, deploymentItemPath(namespace, name), "application/strategic-merge-patch+json", patch)
	if err != nil {
		return err
	}
	if st/100 != 2 {
		return fmt.Errorf("operator: patch deployment %s/%s: status %d: %s", namespace, name, st, string(body))
	}
	return nil
}

// updateStatus writes the observed phase to the CR's status subresource via a
// JSON-merge-patch, so the operator's view of the control plane is visible on
// `kubectl get trstctlcontrolplanes`.
func (r *Reconciler) updateStatus(ctx context.Context, namespace, name string, action Action) error {
	phase := "Reconciling"
	if action == ActionNone {
		phase = "Ready"
	}
	patch := map[string]any{"status": map[string]any{"phase": phase}}
	st, body, err := r.client.do(ctx, http.MethodPatch, tcpItemPath(namespace, name)+"/status", "application/merge-patch+json", patch)
	if err != nil {
		return err
	}
	if st/100 != 2 {
		return fmt.Errorf("operator: patch status %s/%s: status %d: %s", namespace, name, st, string(body))
	}
	return nil
}

// deploymentObject renders the control-plane Deployment the operator manages for
// a TrstctlControlPlane. It mirrors the shape of the Helm chart's deployment
// (the chart remains the richer install): a single unprivileged control-plane
// container running the built image, owner-referenced to the CR so deleting the
// CR garbage-collects the Deployment. It is deliberately minimal — the operator
// owns the replica count and image; Services/secrets/NetworkPolicy/the isolated
// signer remain the chart's responsibility (documented in deploy/operator/doc.go).
func (r *Reconciler) deploymentObject(namespace string, cr controlPlaneObject, _ string) map[string]any {
	name := r.deploymentName(cr.Metadata.Name)
	labels := map[string]any{
		"app.kubernetes.io/name":       "trstctl",
		"app.kubernetes.io/component":  "control-plane",
		"app.kubernetes.io/managed-by": "trstctl-operator",
		"trstctl.com/control-plane":    cr.Metadata.Name,
	}
	return map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]any{
			"name":      name,
			"namespace": namespace,
			"labels":    labels,
			// Owner reference so the Deployment is garbage-collected with the CR.
			"ownerReferences": []map[string]any{{
				"apiVersion":         tcpAPIGroupVersion,
				"kind":               "TrstctlControlPlane",
				"name":               cr.Metadata.Name,
				"controller":         true,
				"blockOwnerDeletion": true,
			}},
		},
		"spec": map[string]any{
			"replicas": cr.Spec.desiredReplicas(),
			"selector": map[string]any{"matchLabels": map[string]any{"trstctl.com/control-plane": cr.Metadata.Name}},
			"template": map[string]any{
				"metadata": map[string]any{"labels": labels},
				"spec": map[string]any{
					"securityContext": map[string]any{
						"runAsNonRoot":   true,
						"seccompProfile": map[string]any{"type": "RuntimeDefault"},
					},
					"containers": []map[string]any{{
						"name":  "control-plane",
						"image": cr.Spec.desiredImage(),
						"securityContext": map[string]any{
							"allowPrivilegeEscalation": false,
							"readOnlyRootFilesystem":   true,
							"runAsNonRoot":             true,
							"capabilities":             map[string]any{"drop": []string{"ALL"}},
						},
						"ports": []map[string]any{{"containerPort": 8443, "name": "https"}},
					}},
				},
			},
		},
	}
}
