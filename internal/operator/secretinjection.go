package operator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
)

const (
	tsiPlural = "trstctlsecretinjections"

	secretInjectionHashAnnotation   = "trstctl.com/secret-injection-hash"
	secretInjectionNameAnnotation   = "trstctl.com/secret-injection-name"
	secretInjectionSourceAnnotation = "trstctl.com/secret-injection-source"
	secretInjectionManagedLabel     = "trstctl.com/secret-injected"

	secretInjectionSourceVolume = "trstctl-secret-injection-source"
	secretInjectionTargetVolume = "trstctl-secret-injection"
	secretInjectionSidecarName  = "trstctl-secret-injector"
	secretInjectionSourceMount  = "/var/run/trstctl/source"
	secretInjectionTargetMount  = "/trstctl/secrets"
)

// SecretInjectionSpec declares no-code workload secret injection. The operator
// patches the selected workloads; it reads only Kubernetes Secret metadata and
// never reads Secret.data values.
type SecretInjectionSpec struct {
	SourceSecretName       string                       `json:"sourceSecretName"`
	Workloads              []SecretInjectionWorkloadRef `json:"workloads"`
	Items                  []SecretInjectionItem        `json:"items"`
	MountPath              string                       `json:"mountPath"`
	AgentImage             string                       `json:"agentImage"`
	RefreshIntervalSeconds int                          `json:"refreshIntervalSeconds"`
}

type SecretInjectionWorkloadRef struct {
	Kind       string   `json:"kind"`
	Name       string   `json:"name"`
	Containers []string `json:"containers"`
}

type SecretInjectionItem struct {
	Key  string `json:"key"`
	Path string `json:"path"`
	Env  string `json:"env"`
}

type secretInjectionObject struct {
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"metadata"`
	Spec SecretInjectionSpec `json:"spec"`
}

type sourceSecretState struct {
	contentHash string
}

type workloadTemplateState struct {
	Spec struct {
		Template struct {
			Metadata struct {
				Annotations map[string]string `json:"annotations"`
			} `json:"metadata"`
			Spec struct {
				Containers []map[string]any `json:"containers"`
				Volumes    []map[string]any `json:"volumes"`
			} `json:"spec"`
		} `json:"template"`
	} `json:"spec"`
}

func tsiCollectionPath(ns string) string {
	return fmt.Sprintf("/apis/trstctl.com/v1alpha1/namespaces/%s/%s", ns, tsiPlural)
}

func tsiItemPath(ns, name string) string {
	return fmt.Sprintf("/apis/trstctl.com/v1alpha1/namespaces/%s/%s/%s", ns, tsiPlural, name)
}

// ReconcileSecretInjectionNamespace reconciles every TrstctlSecretInjection in namespace.
func (r *Reconciler) ReconcileSecretInjectionNamespace(ctx context.Context, namespace string) (map[string]Action, error) {
	st, body, err := r.client.do(ctx, http.MethodGet, tsiCollectionPath(namespace), "", nil)
	if err != nil {
		return nil, err
	}
	if st == http.StatusNotFound {
		return map[string]Action{}, nil
	}
	if st/100 != 2 {
		return nil, fmt.Errorf("operator: list trstctlsecretinjections in %s: status %d: %s", namespace, st, string(body))
	}
	var list struct {
		Items []secretInjectionObject `json:"items"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("operator: decode trstctlsecretinjection list: %w", err)
	}
	actions := make(map[string]Action, len(list.Items))
	sort.Slice(list.Items, func(i, j int) bool { return list.Items[i].Metadata.Name < list.Items[j].Metadata.Name })
	for _, cr := range list.Items {
		ns := cr.Metadata.Namespace
		if ns == "" {
			ns = namespace
		}
		action, err := r.ReconcileSecretInjection(ctx, ns, cr)
		if err != nil {
			return actions, fmt.Errorf("operator: reconcile secret injection %s/%s: %w", ns, cr.Metadata.Name, err)
		}
		actions[cr.Metadata.Name] = action
	}
	return actions, nil
}

// ReconcileSecretInjection patches opted-in workload pod templates with the
// trstctl-agent secret-injection sidecar and app-container mounts/env references.
func (r *Reconciler) ReconcileSecretInjection(ctx context.Context, namespace string, cr secretInjectionObject) (Action, error) {
	if err := validateSecretInjectionSpec(cr.Spec); err != nil {
		_ = r.updateSecretInjectionStatus(ctx, namespace, cr.Metadata.Name, "Error", cr.Spec.SourceSecretName, "", nil, err.Error())
		return ActionNone, err
	}
	source, err := r.observeInjectionSourceSecret(ctx, namespace, cr.Spec.SourceSecretName)
	if err != nil {
		_ = r.updateSecretInjectionStatus(ctx, namespace, cr.Metadata.Name, "Error", cr.Spec.SourceSecretName, "", nil, err.Error())
		return ActionNone, err
	}
	contentHash := secretInjectionContentHash(cr.Spec, source.contentHash)
	injected, err := r.patchInjectionWorkloads(ctx, namespace, cr, contentHash)
	if err != nil {
		_ = r.updateSecretInjectionStatus(ctx, namespace, cr.Metadata.Name, "Error", cr.Spec.SourceSecretName, contentHash, injected, err.Error())
		return ActionNone, err
	}
	if err := r.updateSecretInjectionStatus(ctx, namespace, cr.Metadata.Name, "Ready", cr.Spec.SourceSecretName, contentHash, injected, ""); err != nil {
		return ActionNone, err
	}
	if len(injected) == 0 {
		return ActionNone, nil
	}
	return ActionUpdate, nil
}

func validateSecretInjectionSpec(spec SecretInjectionSpec) error {
	if strings.TrimSpace(spec.SourceSecretName) == "" {
		return fmt.Errorf("operator: TrstctlSecretInjection sourceSecretName is required")
	}
	if len(spec.Workloads) == 0 {
		return fmt.Errorf("operator: TrstctlSecretInjection workloads must name at least one workload")
	}
	if len(spec.Items) == 0 {
		return fmt.Errorf("operator: TrstctlSecretInjection items must name at least one secret key")
	}
	for _, item := range spec.Items {
		if strings.TrimSpace(item.Key) == "" {
			return fmt.Errorf("operator: TrstctlSecretInjection items require key")
		}
		if strings.ContainsAny(item.Key, ",=") {
			return fmt.Errorf("operator: TrstctlSecretInjection key %q cannot contain ',' or '='", item.Key)
		}
		if _, err := injectionItemPath(item); err != nil {
			return err
		}
	}
	for _, ref := range spec.Workloads {
		if strings.TrimSpace(ref.Name) == "" {
			return fmt.Errorf("operator: injection workload name is required")
		}
		if _, err := injectionWorkloadItemPath(namespacePlaceholder, ref); err != nil {
			return err
		}
	}
	return nil
}

const namespacePlaceholder = "namespace"

func injectionWorkloadItemPath(ns string, ref SecretInjectionWorkloadRef) (string, error) {
	return workloadItemPath(ns, WorkloadRef{Kind: ref.Kind, Name: ref.Name})
}

func (r *Reconciler) observeInjectionSourceSecret(ctx context.Context, namespace, name string) (sourceSecretState, error) {
	st, body, err := r.client.do(ctx, http.MethodGet, secretItemPath(namespace, name), "", nil)
	if err != nil {
		return sourceSecretState{}, err
	}
	if st == http.StatusNotFound {
		return sourceSecretState{}, fmt.Errorf("operator: source Secret %s/%s not found", namespace, name)
	}
	if st/100 != 2 {
		return sourceSecretState{}, fmt.Errorf("operator: get injection source Secret %s/%s: status %d: %s", namespace, name, st, string(body))
	}
	var obj struct {
		Metadata struct {
			ResourceVersion string            `json:"resourceVersion"`
			Annotations     map[string]string `json:"annotations"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(body, &obj); err != nil {
		return sourceSecretState{}, fmt.Errorf("operator: decode injection source Secret %s/%s: %w", namespace, name, err)
	}
	hash := strings.TrimSpace(obj.Metadata.Annotations[kubernetesSecretHashAnnotation])
	if hash == "" {
		hash = "rv:" + strings.TrimSpace(obj.Metadata.ResourceVersion)
	}
	if hash == "rv:" {
		hash = "present"
	}
	return sourceSecretState{contentHash: hash}, nil
}

func secretInjectionContentHash(spec SecretInjectionSpec, sourceHash string) string {
	var b bytes.Buffer
	_ = json.NewEncoder(&b).Encode(struct {
		SourceHash string
		Spec       SecretInjectionSpec
	}{SourceHash: sourceHash, Spec: spec})
	return crypto.SHA256Hex(b.Bytes())
}

func (r *Reconciler) patchInjectionWorkloads(ctx context.Context, namespace string, cr secretInjectionObject, hash string) ([]string, error) {
	injected := []string{}
	for _, ref := range cr.Spec.Workloads {
		path, err := injectionWorkloadItemPath(namespace, ref)
		if err != nil {
			return injected, err
		}
		patch, needsPatch, err := r.injectionWorkloadPatch(ctx, path, cr, ref, hash)
		if err != nil {
			return injected, err
		}
		if !needsPatch {
			continue
		}
		st, body, err := r.client.do(ctx, http.MethodPatch, path, "application/merge-patch+json", patch)
		if err != nil {
			return injected, err
		}
		if st/100 != 2 {
			return injected, fmt.Errorf("operator: patch injected workload %s/%s: status %d: %s", namespace, ref.Name, st, string(body))
		}
		injected = append(injected, strings.TrimSpace(ref.Kind)+"/"+ref.Name)
	}
	return injected, nil
}

func (r *Reconciler) injectionWorkloadPatch(ctx context.Context, path string, cr secretInjectionObject, ref SecretInjectionWorkloadRef, hash string) (map[string]any, bool, error) {
	st, body, err := r.client.do(ctx, http.MethodGet, path, "", nil)
	if err != nil {
		return nil, false, err
	}
	if st/100 != 2 {
		return nil, false, fmt.Errorf("operator: get injected workload %s: status %d: %s", path, st, string(body))
	}
	var live workloadTemplateState
	if err := json.Unmarshal(body, &live); err != nil {
		return nil, false, fmt.Errorf("operator: decode injected workload %s: %w", path, err)
	}
	if live.Spec.Template.Metadata.Annotations[secretInjectionHashAnnotation] == hash {
		return nil, false, nil
	}
	if len(live.Spec.Template.Spec.Containers) == 0 {
		return nil, false, fmt.Errorf("operator: injected workload %s has no containers", path)
	}
	volumes := upsertNamedObject(cloneNamedObjects(live.Spec.Template.Spec.Volumes), map[string]any{
		"name": secretInjectionSourceVolume,
		"secret": map[string]any{
			"secretName": cr.Spec.SourceSecretName,
		},
	})
	volumes = upsertNamedObject(volumes, map[string]any{
		"name":     secretInjectionTargetVolume,
		"emptyDir": map[string]any{"medium": "Memory"},
	})

	containers, err := injectedContainers(live.Spec.Template.Spec.Containers, cr.Spec, ref)
	if err != nil {
		return nil, false, err
	}
	return map[string]any{
		"spec": map[string]any{
			"template": map[string]any{
				"metadata": map[string]any{
					"labels": map[string]any{
						secretInjectionManagedLabel: "true",
					},
					"annotations": map[string]any{
						secretInjectionHashAnnotation:   hash,
						secretInjectionNameAnnotation:   cr.Metadata.Name,
						secretInjectionSourceAnnotation: cr.Spec.SourceSecretName,
					},
				},
				"spec": map[string]any{
					"volumes":    volumes,
					"containers": containers,
				},
			},
		},
	}, true, nil
}

func injectedContainers(existing []map[string]any, spec SecretInjectionSpec, ref SecretInjectionWorkloadRef) ([]map[string]any, error) {
	containers := cloneNamedObjects(existing)
	selected := map[string]bool{}
	for _, name := range ref.Containers {
		name = strings.TrimSpace(name)
		if name != "" {
			selected[name] = true
		}
	}
	mountPath := strings.TrimSpace(spec.MountPath)
	if mountPath == "" {
		mountPath = secretInjectionTargetMount
	}
	for i := range containers {
		name, _ := containers[i]["name"].(string)
		if name == secretInjectionSidecarName {
			continue
		}
		if len(selected) > 0 && !selected[name] {
			continue
		}
		containers[i] = addVolumeMount(containers[i], map[string]any{
			"name":      secretInjectionTargetVolume,
			"mountPath": mountPath,
			"readOnly":  true,
		})
		for _, item := range spec.Items {
			if strings.TrimSpace(item.Env) == "" {
				continue
			}
			containers[i] = addSecretEnv(containers[i], strings.TrimSpace(item.Env), spec.SourceSecretName, strings.TrimSpace(item.Key))
		}
	}
	sidecar, err := secretInjectionSidecar(spec)
	if err != nil {
		return nil, err
	}
	return upsertNamedObject(containers, sidecar), nil
}

func secretInjectionSidecar(spec SecretInjectionSpec) (map[string]any, error) {
	image := strings.TrimSpace(spec.AgentImage)
	if image == "" {
		image = defaultControlPlaneImage
	}
	interval := spec.RefreshIntervalSeconds
	if interval <= 0 {
		interval = 30
	}
	mapArg, err := secretInjectionMapArg(spec.Items)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"name":            secretInjectionSidecarName,
		"image":           image,
		"imagePullPolicy": "IfNotPresent",
		"command":         []any{"/usr/local/bin/trstctl-agent"},
		"args": []any{
			"--secret-inject",
			"--secret-inject-source-dir=" + secretInjectionSourceMount,
			"--secret-inject-target-dir=" + secretInjectionTargetMount,
			"--secret-inject-map=" + mapArg,
			"--secret-inject-interval=" + strconv.Itoa(interval) + "s",
		},
		"volumeMounts": []any{
			map[string]any{"name": secretInjectionSourceVolume, "mountPath": secretInjectionSourceMount, "readOnly": true},
			map[string]any{"name": secretInjectionTargetVolume, "mountPath": secretInjectionTargetMount},
		},
		"securityContext": map[string]any{
			"allowPrivilegeEscalation": false,
			"readOnlyRootFilesystem":   true,
			"runAsNonRoot":             true,
			"capabilities":             map[string]any{"drop": []any{"ALL"}},
		},
		"resources": map[string]any{
			"requests": map[string]any{"cpu": "5m", "memory": "16Mi"},
			"limits":   map[string]any{"cpu": "50m", "memory": "64Mi"},
		},
	}, nil
}

func secretInjectionMapArg(items []SecretInjectionItem) (string, error) {
	parts := make([]string, 0, len(items))
	for _, item := range items {
		target, err := injectionItemPath(item)
		if err != nil {
			return "", err
		}
		parts = append(parts, strings.TrimSpace(item.Key)+"="+target)
	}
	sort.Strings(parts)
	return strings.Join(parts, ","), nil
}

func injectionItemPath(item SecretInjectionItem) (string, error) {
	target := strings.TrimSpace(item.Path)
	if target == "" {
		target = strings.TrimSpace(item.Key)
	}
	if strings.ContainsAny(target, ",=") {
		return "", fmt.Errorf("operator: TrstctlSecretInjection path %q cannot contain ',' or '='", item.Path)
	}
	if path.IsAbs(target) {
		return "", fmt.Errorf("operator: TrstctlSecretInjection path %q must be relative", item.Path)
	}
	clean := path.Clean(target)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("operator: TrstctlSecretInjection path %q escapes mount", item.Path)
	}
	return clean, nil
}

func cloneNamedObjects(in []map[string]any) []map[string]any {
	out := make([]map[string]any, 0, len(in))
	for _, obj := range in {
		clone := make(map[string]any, len(obj))
		for k, v := range obj {
			clone[k] = v
		}
		out = append(out, clone)
	}
	return out
}

func upsertNamedObject(objects []map[string]any, desired map[string]any) []map[string]any {
	name, _ := desired["name"].(string)
	for i, obj := range objects {
		if got, _ := obj["name"].(string); got == name {
			objects[i] = desired
			return objects
		}
	}
	return append(objects, desired)
}

func addVolumeMount(container map[string]any, mount map[string]any) map[string]any {
	mounts, _ := container["volumeMounts"].([]any)
	name, _ := mount["name"].(string)
	out := make([]any, 0, len(mounts)+1)
	for _, existing := range mounts {
		obj, ok := existing.(map[string]any)
		if !ok {
			out = append(out, existing)
			continue
		}
		if got, _ := obj["name"].(string); got == name {
			continue
		}
		out = append(out, existing)
	}
	out = append(out, mount)
	container["volumeMounts"] = out
	return container
}

func addSecretEnv(container map[string]any, envName, secretName, key string) map[string]any {
	env, _ := container["env"].([]any)
	out := make([]any, 0, len(env)+1)
	for _, existing := range env {
		obj, ok := existing.(map[string]any)
		if !ok {
			out = append(out, existing)
			continue
		}
		if got, _ := obj["name"].(string); got == envName {
			continue
		}
		out = append(out, existing)
	}
	out = append(out, map[string]any{
		"name": envName,
		"valueFrom": map[string]any{
			"secretKeyRef": map[string]any{
				"name": secretName,
				"key":  key,
			},
		},
	})
	container["env"] = out
	return container
}

func (r *Reconciler) updateSecretInjectionStatus(ctx context.Context, namespace, name, phase, source, hash string, injected []string, message string) error {
	status := map[string]any{
		"phase":        phase,
		"sourceSecret": source,
	}
	if hash != "" {
		status["contentHash"] = hash
	}
	if len(injected) > 0 {
		status["injectedWorkloads"] = injected
	}
	if message != "" {
		status["message"] = message
	}
	st, body, err := r.client.do(ctx, http.MethodPatch, tsiItemPath(namespace, name)+"/status", "application/merge-patch+json", map[string]any{"status": status})
	if err != nil {
		return err
	}
	if st == http.StatusNotFound {
		return nil
	}
	if st/100 != 2 {
		return fmt.Errorf("operator: patch secret injection status %s/%s: status %d: %s", namespace, name, st, string(body))
	}
	return nil
}
