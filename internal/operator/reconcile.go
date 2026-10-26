// SPDX-License-Identifier: BUSL-1.1

package operator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"net/http"
	"sort"
	"strings"
)

// API paths for the two resource kinds the operator drives.
const (
	tcpAPIGroupVersion = "trstctl.com/v1alpha1"
	tcpPlural          = "trstctlcontrolplanes"
	tssPlural          = "trstctlsecretsyncs"
	deploymentsGroup   = "apps/v1"
)

// defaultControlPlaneImage is used when a TrstctlControlPlane omits spec.image.
// It names the single multi-binary control-plane image the release pipeline
// builds (deploy/docker/Dockerfile, .github/workflows/release.yml); the operator
// runs from that same image via an entrypoint override.
const defaultControlPlaneImage = "ghcr.io/ctlplne/trstctl:latest"

// ControlPlaneSpec is the desired state declared on a TrstctlControlPlane.spec.
// Unknown fields are ignored, but every field modeled here is reconciled into
// the managed control-plane Deployment.
type ControlPlaneSpec struct {
	Replicas    int             `json:"replicas"`
	Image       string          `json:"image"`
	SignerMode  string          `json:"signerMode"`
	Postgres    PostgresSpec    `json:"postgres"`
	NATS        NATSSpec        `json:"nats"`
	ExternalKMS ExternalKMSSpec `json:"externalKMS"`
	Signer      SignerSpec      `json:"signer"`
	// The network surface (A133): see networking.go.
	Service       ServiceSpec       `json:"service"`
	Ingress       IngressSpec       `json:"ingress"`
	NetworkPolicy NetworkPolicySpec `json:"networkPolicy"`

	// signerMTLSFingerprint is set during a reconcile from the isolated
	// signer's mTLS Secrets (signer_mtls.go), never read from the resource.
	signerMTLSFingerprint string
}

type PostgresSpec struct {
	DSNSecret    string `json:"dsnSecret"`
	DSNSecretKey string `json:"dsnSecretKey"`
}

type NATSSpec struct {
	URL                 string `json:"url"`
	Replicas            int    `json:"replicas"`
	AllowSingleReplica  bool   `json:"allowSingleReplica"`
	SyncAlways          bool   `json:"syncAlways"`
	SyncIntervalSeconds int    `json:"syncIntervalSeconds"`
}

type ExternalKMSSpec struct {
	Enabled  bool   `json:"enabled"`
	Provider string `json:"provider"`
	KeyRef   string `json:"keyRef"`
}

type SignerSpec struct {
	AuthSecret    string         `json:"authSecret"`
	AuthSecretKey string         `json:"authSecretKey"`
	KekSecret     string         `json:"kekSecret"`
	KekSecretKey  string         `json:"kekSecretKey"`
	KeyStorePVC   string         `json:"keyStorePVC"`
	MTLS          SignerMTLSSpec `json:"mtls"`
	// AuthTokenCommand is the independent command the control plane asks for
	// each signer authorization token (required with production NATS).
	// AllowCoResidentAuthorizer is the evaluation-only alternative: the control
	// plane mounts the signer's verifier secret and mints tokens itself.
	AuthTokenCommand          string `json:"authTokenCommand"`
	AllowCoResidentAuthorizer bool   `json:"allowCoResidentAuthorizer"`
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

func (s ControlPlaneSpec) desiredSignerMode() string {
	switch strings.ToLower(strings.TrimSpace(s.SignerMode)) {
	case "sidecar":
		return "sidecar"
	case "isolated":
		return "isolated"
	default:
		return ""
	}
}

// signerAuthorizationError mirrors the Helm chart's guards. The control plane
// refuses these combinations at startup, so the operator reports them on the
// resource instead of rolling out pods that cannot start.
func (s ControlPlaneSpec) signerAuthorizationError() error {
	command := strings.TrimSpace(s.Signer.AuthTokenCommand)
	switch {
	case command != "" && s.Signer.AllowCoResidentAuthorizer:
		return errors.New("signer.authTokenCommand and signer.allowCoResidentAuthorizer are mutually exclusive: production uses the independent token command, evaluation may choose the co-resident authorizer")
	case s.Signer.AllowCoResidentAuthorizer && s.desiredSignerMode() == "isolated":
		return errors.New("signer.allowCoResidentAuthorizer keeps the signer's verifier secret beside the control plane, which an isolated signer exists to prevent; set signer.authTokenCommand")
	case strings.TrimSpace(s.NATS.URL) != "" && !s.NATS.AllowSingleReplica && s.Signer.AllowCoResidentAuthorizer:
		return errors.New("signer.allowCoResidentAuthorizer is evaluation-only; with production NATS (nats.allowSingleReplica false) set signer.authTokenCommand")
	case strings.TrimSpace(s.NATS.URL) != "" && !s.NATS.AllowSingleReplica && command == "":
		return errors.New("signer.authTokenCommand is required with production NATS (nats.allowSingleReplica false), so the signer's privileged keys answer to an independent token provider; for a single-node evaluation set nats.allowSingleReplica and signer.allowCoResidentAuthorizer")
	}
	return nil
}

func (s ControlPlaneSpec) postgresDSNSecretKey() string {
	if strings.TrimSpace(s.Postgres.DSNSecretKey) == "" {
		return "dsn"
	}
	return s.Postgres.DSNSecretKey
}

// podTemplateRevision changes when the operator's own pod template changes, so
// an upgraded operator rolls each control plane onto it once.
const podTemplateRevision = 2

func (s ControlPlaneSpec) desiredConfigHash() string {
	h := fnv.New64a()
	_ = json.NewEncoder(h).Encode(struct {
		Image       string
		SignerMode  string
		Postgres    PostgresSpec
		NATS        NATSSpec
		ExternalKMS ExternalKMSSpec
		Signer      SignerSpec
		PodTemplate int
		SignerMTLS  string `json:",omitempty"`
	}{
		Image:       s.desiredImage(),
		SignerMode:  s.desiredSignerMode(),
		Postgres:    s.Postgres,
		NATS:        s.NATS,
		ExternalKMS: s.ExternalKMS,
		Signer:      s.Signer,
		PodTemplate: podTemplateRevision,
		SignerMTLS:  s.signerMTLSFingerprint,
	})
	return fmt.Sprintf("%016x", h.Sum64())
}

// controlPlaneObject is a decoded TrstctlControlPlane custom resource.
type controlPlaneObject struct {
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
		UID       string `json:"uid"`
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
	configHash      string
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

// decideAction is the pure desired-vs-actual diff at the center of the
// reconcile. Given the spec and the live Deployment, it returns the action to
// take. Keeping it pure makes the controller's behavior unit-testable without a
// cluster: the reconcile test asserts decideAction returns the right action for
// each missing/drifted/in-sync case.
func decideAction(spec ControlPlaneSpec, live deploymentState) Action {
	if !live.exists {
		return ActionCreate
	}
	if live.replicas != spec.desiredReplicas() || live.image != spec.desiredImage() || live.configHash != spec.desiredConfigHash() {
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
	secretResolver   SecretResolver
}

// NewReconciler returns a Reconciler using client for all API access.
func NewReconciler(client *Client) *Reconciler {
	return &Reconciler{
		client:           client,
		deploymentSuffix: "-control-plane",
		secretResolver:   NewHTTPSecretResolver(client, nil),
	}
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
	surfaces := map[string]Action{}
	if err := cr.Spec.signerAuthorizationError(); err != nil {
		_ = r.updateStatus(ctx, namespace, cr.Metadata.Name, surfaces, err)
		return ActionNone, err
	}
	if cr.Spec.desiredSignerMode() == "isolated" {
		fingerprint, mtlsAction, err := r.ensureSignerMTLS(ctx, namespace, cr)
		surfaces["signerMTLS"] = mtlsAction
		if err != nil {
			_ = r.updateStatus(ctx, namespace, cr.Metadata.Name, surfaces, err)
			return mtlsAction, err
		}
		cr.Spec.signerMTLSFingerprint = fingerprint
	}
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
		if err := r.patchDeployment(ctx, namespace, r.deploymentName(cr.Metadata.Name), cr, live.resourceVersion); err != nil {
			return action, err
		}
	case ActionNone:
		// Already converged.
	}

	// The network surface converges after the Deployment, so a Service or
	// NetworkPolicy never selects pods that do not exist yet for long.
	network, networkErr := r.reconcileNetwork(ctx, namespace, cr)
	for surface, surfaceAction := range network {
		surfaces[surface] = surfaceAction
	}
	surfaces["deployment"] = action
	if networkErr != nil {
		_ = r.updateStatus(ctx, namespace, cr.Metadata.Name, surfaces, networkErr)
		return action, networkErr
	}
	if action == ActionNone {
		for _, surface := range surfaces {
			if surface != ActionNone {
				action = ActionUpdate
				break
			}
		}
	}
	if err := r.updateStatus(ctx, namespace, cr.Metadata.Name, surfaces, nil); err != nil {
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
			ResourceVersion string            `json:"resourceVersion"`
			Annotations     map[string]string `json:"annotations"`
		} `json:"metadata"`
		Spec struct {
			Replicas int `json:"replicas"`
			Template struct {
				Metadata struct {
					Annotations map[string]string `json:"annotations"`
				} `json:"metadata"`
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
		configHash:      firstNonEmpty(dep.Spec.Template.Metadata.Annotations["trstctl.com/config-hash"], dep.Metadata.Annotations["trstctl.com/config-hash"]),
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

// patchDeployment applies a merge patch that pins the replica count, pod
// template, and operator-owned config to the spec.
func (r *Reconciler) patchDeployment(ctx context.Context, namespace, name string, cr controlPlaneObject, _ string) error {
	patch := map[string]any{
		"metadata": map[string]any{"annotations": r.deploymentAnnotations(cr)},
		"spec": map[string]any{
			"replicas": cr.Spec.desiredReplicas(),
			"template": r.podTemplate(namespace, cr),
		},
	}
	st, body, err := r.client.do(ctx, http.MethodPatch, deploymentItemPath(namespace, name), "application/merge-patch+json", patch)
	if err != nil {
		return err
	}
	if st/100 != 2 {
		return fmt.Errorf("operator: patch deployment %s/%s: status %d: %s", namespace, name, st, string(body))
	}
	return nil
}

// managedSurfaces is every object kind the operator converges for one control
// plane, in status order.
var managedSurfaces = []string{"deployment", "service", "networkPolicy", "ingress", "signer", "signerService", "signerNetworkPolicy", "signerMTLS"}

// updateStatus writes the observed phase and what happened to each managed
// surface to the CR's status subresource via a JSON-merge-patch, so the
// operator's view of the control plane is visible on `kubectl get
// trstctlcontrolplanes`. A surface the operator could not converge sets phase
// Blocked with the reason.
func (r *Reconciler) updateStatus(ctx context.Context, namespace, name string, surfaces map[string]Action, failure error) error {
	phase, ready := "Ready", 0
	status := map[string]any{}
	// Every surface is reported on every pass, so a merge patch never leaves a
	// stale entry behind: one the spec does not ask for reads "absent".
	reported := map[string]any{}
	for _, surface := range managedSurfaces {
		action, managed := surfaces[surface]
		switch {
		case !managed:
			reported[surface] = "absent"
		case action == ActionNone:
			reported[surface] = string(action)
			ready++
		default:
			reported[surface] = string(action)
			phase = "Reconciling"
		}
	}
	message := ""
	if failure != nil {
		phase, message = "Blocked", failure.Error()
	}
	status["phase"] = phase
	status["readySurfaces"] = ready
	status["surfaces"] = reported
	status["message"] = message
	patch := map[string]any{"status": status}
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
// a TrstctlControlPlane. It carries the operator-owned runtime config into the
// pod template and owner-references the CR so deleting the CR garbage-collects
// the Deployment.
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
			"name":        name,
			"namespace":   namespace,
			"labels":      labels,
			"annotations": r.deploymentAnnotations(cr),
			// Owner reference so the Deployment is garbage-collected with the CR.
			"ownerReferences": ownerReferences(cr),
		},
		"spec": map[string]any{
			"replicas": cr.Spec.desiredReplicas(),
			"selector": map[string]any{"matchLabels": map[string]any{"trstctl.com/control-plane": cr.Metadata.Name}},
			"template": r.podTemplate(namespace, cr),
		},
	}
}

func (r *Reconciler) deploymentAnnotations(cr controlPlaneObject) map[string]any {
	annotations := map[string]any{
		"trstctl.com/config-hash": cr.Spec.desiredConfigHash(),
	}
	if strings.TrimSpace(cr.Spec.ExternalKMS.KeyRef) != "" {
		annotations["trstctl.com/external-kms-key-ref"] = cr.Spec.ExternalKMS.KeyRef
	}
	if cr.Spec.signerMTLSFingerprint != "" {
		annotations[signerMTLSFingerprintAnnotation] = cr.Spec.signerMTLSFingerprint
	}
	return annotations
}

func (r *Reconciler) podTemplate(namespace string, cr controlPlaneObject) map[string]any {
	labels := map[string]any{
		"app.kubernetes.io/name":       "trstctl",
		"app.kubernetes.io/component":  "control-plane",
		"app.kubernetes.io/managed-by": "trstctl-operator",
		"trstctl.com/control-plane":    cr.Metadata.Name,
	}
	return map[string]any{
		"metadata": map[string]any{
			"labels":      labels,
			"annotations": r.deploymentAnnotations(cr),
		},
		"spec": r.podSpec(namespace, cr),
	}
}

func (r *Reconciler) podSpec(namespace string, cr controlPlaneObject) map[string]any {
	containers := []map[string]any{}
	volumes := []map[string]any{
		{"name": "tmp", "emptyDir": map[string]any{}},
		{"name": "cp-data", "emptyDir": map[string]any{}},
	}
	if cr.Spec.desiredSignerMode() == "sidecar" {
		containers = append(containers, r.signerContainer(cr))
		volumes = append(volumes,
			map[string]any{"name": "signer-sock", "emptyDir": map[string]any{"medium": "Memory"}},
			r.signerKeysVolume(cr),
			map[string]any{"name": "signer-auth", "secret": map[string]any{"secretName": signerAuthSecret(cr), "defaultMode": 288}},
			map[string]any{"name": "kek", "secret": map[string]any{"secretName": signerKekSecret(cr), "defaultMode": 288}},
		)
	}
	if cr.Spec.desiredSignerMode() == "isolated" {
		// The signer runs as its own pod (networking.go); the control plane holds
		// only its side of the mutually pinned channel and the deployment KEK.
		volumes = append(volumes,
			map[string]any{"name": "signer-mtls", "secret": map[string]any{"secretName": controlPlaneMTLSSecret(cr), "defaultMode": 288}},
			map[string]any{"name": "kek", "secret": map[string]any{"secretName": signerKekSecret(cr), "defaultMode": 288}},
		)
	}
	containers = append(containers, r.controlPlaneContainer(namespace, cr))
	return map[string]any{
		"securityContext": podSecurityContext(),
		"containers":      containers,
		"volumes":         volumes,
	}
}

// podSecurityContext runs as the image's non-root user, with that group owning
// mounted Secrets, so the 0440 KEK, authorization and mTLS files are readable
// (the Helm chart's identity).
func podSecurityContext() map[string]any {
	return map[string]any{
		"runAsNonRoot":        true,
		"runAsUser":           65532,
		"runAsGroup":          65532,
		"fsGroup":             65532,
		"fsGroupChangePolicy": "OnRootMismatch",
		"seccompProfile":      map[string]any{"type": "RuntimeDefault"},
	}
}

// ownerReferences makes the CR the controller owner, so deleting it
// garbage-collects everything the operator created for it. The API server
// requires the owner's uid.
func ownerReferences(cr controlPlaneObject) []map[string]any {
	return []map[string]any{{
		"apiVersion":         tcpAPIGroupVersion,
		"kind":               "TrstctlControlPlane",
		"name":               cr.Metadata.Name,
		"uid":                cr.Metadata.UID,
		"controller":         true,
		"blockOwnerDeletion": true,
	}}
}

func (r *Reconciler) controlPlaneContainer(namespace string, cr controlPlaneObject) map[string]any {
	mounts := []map[string]any{
		{"name": "cp-data", "mountPath": "/data"},
		{"name": "tmp", "mountPath": "/tmp"},
	}
	if cr.Spec.desiredSignerMode() == "sidecar" {
		mounts = append(mounts,
			map[string]any{"name": "signer-sock", "mountPath": "/run/trstctl"},
			map[string]any{"name": "kek", "mountPath": "/etc/trstctl/kek", "readOnly": true},
		)
		if cr.Spec.Signer.AllowCoResidentAuthorizer {
			mounts = append(mounts, map[string]any{"name": "signer-auth", "mountPath": "/etc/trstctl/signer-auth", "readOnly": true})
		}
	}
	if cr.Spec.desiredSignerMode() == "isolated" {
		mounts = append(mounts,
			map[string]any{"name": "signer-mtls", "mountPath": "/etc/trstctl/signer-mtls", "readOnly": true},
			map[string]any{"name": "kek", "mountPath": "/etc/trstctl/kek", "readOnly": true},
		)
	}
	return map[string]any{
		"name":  "control-plane",
		"image": cr.Spec.desiredImage(),
		"securityContext": map[string]any{
			"allowPrivilegeEscalation": false,
			"readOnlyRootFilesystem":   true,
			"runAsNonRoot":             true,
			"capabilities":             map[string]any{"drop": []string{"ALL"}},
		},
		"ports":        []map[string]any{{"containerPort": 8443, "name": "https"}},
		"env":          r.controlPlaneEnv(namespace, cr),
		"volumeMounts": mounts,
	}
}

func (r *Reconciler) signerContainer(cr controlPlaneObject) map[string]any {
	return map[string]any{
		"name":    "signer",
		"image":   cr.Spec.desiredImage(),
		"command": []string{"/usr/local/bin/trstctl-signer"},
		"args": []string{
			"--socket=/run/trstctl/signer.sock",
			"--keystore=/data/signer/keys",
			"--kek=/etc/trstctl/kek/" + signerKekSecretKey(cr),
			"--auth-secret=/etc/trstctl/signer-auth/" + signerAuthSecretKey(cr),
		},
		"securityContext": map[string]any{
			"allowPrivilegeEscalation": false,
			"readOnlyRootFilesystem":   true,
			"runAsNonRoot":             true,
			"capabilities":             map[string]any{"drop": []string{"ALL"}},
		},
		"volumeMounts": []map[string]any{
			{"name": "signer-sock", "mountPath": "/run/trstctl"},
			{"name": "signer-keys", "mountPath": "/data/signer"},
			{"name": "kek", "mountPath": "/etc/trstctl/kek", "readOnly": true},
			{"name": "signer-auth", "mountPath": "/etc/trstctl/signer-auth", "readOnly": true},
		},
	}
}

func (r *Reconciler) controlPlaneEnv(namespace string, cr controlPlaneObject) []map[string]any {
	env := []map[string]any{}
	if strings.TrimSpace(cr.Spec.Postgres.DSNSecret) != "" {
		env = append(env,
			envValue("TRSTCTL_POSTGRES_MODE", "external"),
			envSecret("TRSTCTL_POSTGRES_DSN", cr.Spec.Postgres.DSNSecret, cr.Spec.postgresDSNSecretKey()),
		)
	}
	if strings.TrimSpace(cr.Spec.NATS.URL) != "" {
		env = append(env,
			envValue("TRSTCTL_NATS_MODE", "external"),
			envValue("TRSTCTL_NATS_URL", cr.Spec.NATS.URL),
		)
		if cr.Spec.NATS.Replicas > 0 {
			env = append(env, envValue("TRSTCTL_NATS_REPLICAS", fmt.Sprint(cr.Spec.NATS.Replicas)))
		}
		if cr.Spec.NATS.AllowSingleReplica {
			env = append(env, envValue("TRSTCTL_NATS_ALLOW_SINGLE_REPLICA", "true"))
		}
		if cr.Spec.NATS.SyncAlways {
			env = append(env, envValue("TRSTCTL_NATS_SYNC_ALWAYS", "true"))
		}
		if cr.Spec.NATS.SyncIntervalSeconds > 0 {
			env = append(env, envValue("TRSTCTL_NATS_SYNC_INTERVAL", fmt.Sprintf("%ds", cr.Spec.NATS.SyncIntervalSeconds)))
		}
	}
	if cr.Spec.desiredSignerMode() == "sidecar" {
		env = append(env,
			envValue("TRSTCTL_SIGNER_MODE", "external"),
			envValue("TRSTCTL_SIGNER_SOCKET", "/run/trstctl/signer.sock"),
			envValue("TRSTCTL_SECRETS_KEK_FILE", "/etc/trstctl/kek/"+signerKekSecretKey(cr)),
		)
	}
	if cr.Spec.desiredSignerMode() == "isolated" {
		env = append(env,
			envValue("TRSTCTL_SIGNER_MODE", "external"),
			envValue("TRSTCTL_SIGNER_MTLS_ADDRESS", fmt.Sprintf("%s:%d", r.signerName(cr.Metadata.Name), signerMTLSPort)),
			envValue("TRSTCTL_SIGNER_MTLS_SERVER_NAME", r.signerMTLSServerName(namespace, cr)),
			envValue("TRSTCTL_SIGNER_MTLS_CERT_FILE", "/etc/trstctl/signer-mtls/tls.crt"),
			envValue("TRSTCTL_SIGNER_MTLS_KEY_FILE", "/etc/trstctl/signer-mtls/tls.key"),
			envValue("TRSTCTL_SIGNER_MTLS_PEER_CA_FILE", "/etc/trstctl/signer-mtls/peer-ca.pem"),
			envSecret("TRSTCTL_SIGNER_MTLS_PEER_PIN", controlPlaneMTLSSecret(cr), "peer-pin"),
			envValue("TRSTCTL_SECRETS_KEK_FILE", "/etc/trstctl/kek/"+signerKekSecretKey(cr)),
		)
	}
	// Signer authorization, as the Helm chart sets it. The child signer
	// (signerMode unset) keeps the binary's own default unless a token command
	// is named.
	if command := strings.TrimSpace(cr.Spec.Signer.AuthTokenCommand); command != "" {
		env = append(env,
			envValue("TRSTCTL_SIGNER_AUTH_TOKEN_COMMAND", command),
			envValue("TRSTCTL_SIGNER_ALLOW_CO_RESIDENT_AUTHORIZER", "false"),
		)
	} else if cr.Spec.desiredSignerMode() != "" {
		env = append(env, envValue("TRSTCTL_SIGNER_ALLOW_CO_RESIDENT_AUTHORIZER", fmt.Sprint(cr.Spec.Signer.AllowCoResidentAuthorizer)))
		if cr.Spec.Signer.AllowCoResidentAuthorizer {
			env = append(env, envValue("TRSTCTL_SIGNER_AUTH_SECRET_FILE", "/etc/trstctl/signer-auth/"+signerAuthSecretKey(cr)))
		}
	}
	if cr.Spec.ExternalKMS.Enabled {
		env = append(env, envValue("TRSTCTL_MANAGED_KEYS_ENABLED", "true"))
		if strings.TrimSpace(cr.Spec.ExternalKMS.Provider) != "" {
			env = append(env, envValue("TRSTCTL_MANAGED_KEYS_PROVIDER", cr.Spec.ExternalKMS.Provider))
		}
	}
	return env
}

func envValue(name, value string) map[string]any {
	return map[string]any{"name": name, "value": value}
}

func envSecret(name, secret, key string) map[string]any {
	return map[string]any{
		"name": name,
		"valueFrom": map[string]any{"secretKeyRef": map[string]any{
			"name": secret,
			"key":  key,
		}},
	}
}

func (r *Reconciler) signerKeysVolume(cr controlPlaneObject) map[string]any {
	if strings.TrimSpace(cr.Spec.Signer.KeyStorePVC) != "" {
		return map[string]any{"name": "signer-keys", "persistentVolumeClaim": map[string]any{"claimName": cr.Spec.Signer.KeyStorePVC}}
	}
	return map[string]any{"name": "signer-keys", "emptyDir": map[string]any{}}
}

func signerAuthSecret(cr controlPlaneObject) string {
	if strings.TrimSpace(cr.Spec.Signer.AuthSecret) != "" {
		return cr.Spec.Signer.AuthSecret
	}
	return cr.Metadata.Name + "-signer-auth"
}

func signerAuthSecretKey(cr controlPlaneObject) string {
	if strings.TrimSpace(cr.Spec.Signer.AuthSecretKey) != "" {
		return cr.Spec.Signer.AuthSecretKey
	}
	return "sign-auth.bin"
}

func signerKekSecret(cr controlPlaneObject) string {
	if strings.TrimSpace(cr.Spec.Signer.KekSecret) != "" {
		return cr.Spec.Signer.KekSecret
	}
	return cr.Metadata.Name + "-kek"
}

func signerKekSecretKey(cr controlPlaneObject) string {
	if strings.TrimSpace(cr.Spec.Signer.KekSecretKey) != "" {
		return cr.Spec.Signer.KekSecretKey
	}
	return "kek.bin"
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
