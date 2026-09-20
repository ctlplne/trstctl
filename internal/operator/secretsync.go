// SPDX-License-Identifier: BUSL-1.1

package operator

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secrettext"
)

const (
	kubernetesSecretHashAnnotation = "trstctl.com/secret-sync-hash" // #nosec G101 -- identifier/constant matching the secret-name heuristic; no credential value present (CWE-798)
	kubernetesSecretNameAnnotation = "trstctl.com/secret-sync-name" // #nosec G101 -- identifier/constant matching the secret-name heuristic; no credential value present (CWE-798)
	kubernetesSecretManagedLabel   = "trstctl.com/managed-by"       // #nosec G101 -- identifier/constant matching the secret-name heuristic; no credential value present (CWE-798)
)

// SecretResolver resolves one remote trstctl secret reference into wipeable bytes.
// Implementations must return a fresh byte slice owned by the caller.
type SecretResolver interface {
	ResolveSecret(ctx context.Context, namespace string, spec SecretSyncSpec, remoteName string) ([]byte, error)
}

// SecretSyncSpec is the desired state declared on TrstctlSecretSync.spec.
type SecretSyncSpec struct {
	ControlPlane ControlPlaneAccessSpec `json:"controlPlane"`
	Target       SecretSyncTargetSpec   `json:"target"`
	Data         []SecretSyncDataRef    `json:"data"`
	Reload       SecretReloadSpec       `json:"reload"`
}

type ControlPlaneAccessSpec struct {
	URL            string       `json:"url"`
	TenantID       string       `json:"tenantID"`
	TokenSecretRef SecretKeyRef `json:"tokenSecretRef"`
}

type SecretKeyRef struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

type SecretSyncTargetSpec struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type SecretSyncDataRef struct {
	Key       string          `json:"key"`
	RemoteRef RemoteSecretRef `json:"remoteRef"`
}

type RemoteSecretRef struct {
	Name string `json:"name"`
}

type SecretReloadSpec struct {
	Workloads []WorkloadRef `json:"workloads"`
}

type WorkloadRef struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

type secretSyncObject struct {
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"metadata"`
	Spec SecretSyncSpec `json:"spec"`
}

type secretState struct {
	exists      bool
	contentHash string
}

func tssCollectionPath(ns string) string {
	return fmt.Sprintf("/apis/trstctl.com/v1alpha1/namespaces/%s/%s", ns, tssPlural)
}

func tssItemPath(ns, name string) string {
	return fmt.Sprintf("/apis/trstctl.com/v1alpha1/namespaces/%s/%s/%s", ns, tssPlural, name)
}

func secretItemPath(ns, name string) string {
	return fmt.Sprintf("/api/v1/namespaces/%s/secrets/%s", ns, name)
}

func secretCollectionPath(ns string) string {
	return fmt.Sprintf("/api/v1/namespaces/%s/secrets", ns)
}

func workloadItemPath(ns string, ref WorkloadRef) (string, error) {
	switch strings.ToLower(strings.TrimSpace(ref.Kind)) {
	case "deployment", "deployments", "":
		return fmt.Sprintf("/apis/apps/v1/namespaces/%s/deployments/%s", ns, ref.Name), nil
	case "statefulset", "statefulsets":
		return fmt.Sprintf("/apis/apps/v1/namespaces/%s/statefulsets/%s", ns, ref.Name), nil
	case "daemonset", "daemonsets":
		return fmt.Sprintf("/apis/apps/v1/namespaces/%s/daemonsets/%s", ns, ref.Name), nil
	default:
		return "", fmt.Errorf("operator: unsupported reload workload kind %q", ref.Kind)
	}
}

// ReconcileSecretSyncNamespace reconciles every TrstctlSecretSync in namespace.
func (r *Reconciler) ReconcileSecretSyncNamespace(ctx context.Context, namespace string) (map[string]Action, error) {
	st, body, err := r.client.do(ctx, http.MethodGet, tssCollectionPath(namespace), "", nil)
	if err != nil {
		return nil, err
	}
	if st == http.StatusNotFound {
		return map[string]Action{}, nil
	}
	if st/100 != 2 {
		return nil, fmt.Errorf("operator: list trstctlsecretsyncs in %s: status %d: %s", namespace, st, string(body))
	}
	var list struct {
		Items []secretSyncObject `json:"items"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("operator: decode trstctlsecretsync list: %w", err)
	}
	actions := make(map[string]Action, len(list.Items))
	sort.Slice(list.Items, func(i, j int) bool { return list.Items[i].Metadata.Name < list.Items[j].Metadata.Name })
	for _, cr := range list.Items {
		ns := cr.Metadata.Namespace
		if ns == "" {
			ns = namespace
		}
		action, err := r.ReconcileSecretSync(ctx, ns, cr)
		if err != nil {
			return actions, fmt.Errorf("operator: reconcile secret sync %s/%s: %w", ns, cr.Metadata.Name, err)
		}
		actions[cr.Metadata.Name] = action
	}
	return actions, nil
}

// ReconcileSecretSync converges one TrstctlSecretSync into a Kubernetes Secret and
// patches opted-in workloads with a content hash annotation to trigger reload.
func (r *Reconciler) ReconcileSecretSync(ctx context.Context, namespace string, cr secretSyncObject) (Action, error) {
	target := cr.Spec.targetName(cr.Metadata.Name)
	if target == "" {
		return ActionNone, fmt.Errorf("operator: TrstctlSecretSync %s has no target secret", cr.Metadata.Name)
	}
	values, contentHash, err := r.resolveSecretData(ctx, namespace, cr.Spec)
	if err != nil {
		_ = r.updateSecretSyncStatus(ctx, namespace, cr.Metadata.Name, "Error", target, 0, "", nil, err.Error())
		return ActionNone, err
	}
	defer wipeSecretData(values)

	live, err := r.observeSecret(ctx, namespace, target)
	if err != nil {
		return ActionNone, err
	}
	action := ActionNone
	switch {
	case !live.exists:
		if err := r.createSecret(ctx, namespace, cr, values, contentHash); err != nil {
			return ActionCreate, err
		}
		action = ActionCreate
	case live.contentHash != contentHash:
		if err := r.patchSecret(ctx, namespace, cr, values, contentHash); err != nil {
			return ActionUpdate, err
		}
		action = ActionUpdate
	}

	reloaded, err := r.patchReloadWorkloads(ctx, namespace, cr, contentHash)
	if err != nil {
		_ = r.updateSecretSyncStatus(ctx, namespace, cr.Metadata.Name, "Error", target, len(values), contentHash, reloaded, err.Error())
		return action, err
	}
	if action == ActionNone && len(reloaded) > 0 {
		action = ActionUpdate
	}
	if err := r.updateSecretSyncStatus(ctx, namespace, cr.Metadata.Name, "Ready", target, len(values), contentHash, reloaded, ""); err != nil {
		return action, err
	}
	return action, nil
}

func (s SecretSyncSpec) targetName(fallback string) string {
	if strings.TrimSpace(s.Target.Name) != "" {
		return strings.TrimSpace(s.Target.Name)
	}
	return strings.TrimSpace(fallback)
}

func (r *Reconciler) resolveSecretData(ctx context.Context, namespace string, spec SecretSyncSpec) (map[string][]byte, string, error) {
	if len(spec.Data) == 0 {
		return nil, "", fmt.Errorf("operator: TrstctlSecretSync data must name at least one key")
	}
	if r.secretResolver == nil {
		return nil, "", fmt.Errorf("operator: no trstctl secret resolver configured")
	}
	values := make(map[string][]byte, len(spec.Data))
	hashParts := make([]string, 0, len(spec.Data))
	for _, ref := range spec.Data {
		key := strings.TrimSpace(ref.Key)
		remote := strings.TrimSpace(ref.RemoteRef.Name)
		if key == "" || remote == "" {
			wipeSecretData(values)
			return nil, "", fmt.Errorf("operator: TrstctlSecretSync data entries require key and remoteRef.name")
		}
		value, err := r.secretResolver.ResolveSecret(ctx, namespace, spec, remote)
		if err != nil {
			wipeSecretData(values)
			return nil, "", err
		}
		values[key] = value
		hashParts = append(hashParts, key+"="+crypto.SHA256Hex(value))
	}
	sort.Strings(hashParts)
	return values, crypto.SHA256Hex([]byte(strings.Join(hashParts, "\n"))), nil
}

func (r *Reconciler) observeSecret(ctx context.Context, namespace, name string) (secretState, error) {
	st, body, err := r.client.do(ctx, http.MethodGet, secretItemPath(namespace, name), "", nil)
	if err != nil {
		return secretState{}, err
	}
	if st == http.StatusNotFound {
		return secretState{exists: false}, nil
	}
	if st/100 != 2 {
		return secretState{}, fmt.Errorf("operator: get secret %s/%s: status %d: %s", namespace, name, st, string(body))
	}
	var obj struct {
		Metadata struct {
			Annotations map[string]string `json:"annotations"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(body, &obj); err != nil {
		return secretState{}, fmt.Errorf("operator: decode secret %s/%s: %w", namespace, name, err)
	}
	return secretState{exists: true, contentHash: obj.Metadata.Annotations[kubernetesSecretHashAnnotation]}, nil
}

func (r *Reconciler) createSecret(ctx context.Context, namespace string, cr secretSyncObject, values map[string][]byte, hash string) error {
	st, body, err := r.client.do(ctx, http.MethodPost, secretCollectionPath(namespace), "", r.secretObject(namespace, cr, values, hash))
	if err != nil {
		return err
	}
	if st == http.StatusConflict {
		return r.patchSecret(ctx, namespace, cr, values, hash)
	}
	if st/100 != 2 {
		return fmt.Errorf("operator: create secret %s/%s: status %d: %s", namespace, cr.Spec.targetName(cr.Metadata.Name), st, string(body))
	}
	return nil
}

func (r *Reconciler) patchSecret(ctx context.Context, namespace string, cr secretSyncObject, values map[string][]byte, hash string) error {
	st, body, err := r.client.do(ctx, http.MethodPatch, secretItemPath(namespace, cr.Spec.targetName(cr.Metadata.Name)), "application/merge-patch+json", r.secretObject(namespace, cr, values, hash))
	if err != nil {
		return err
	}
	if st/100 != 2 {
		return fmt.Errorf("operator: patch secret %s/%s: status %d: %s", namespace, cr.Spec.targetName(cr.Metadata.Name), st, string(body))
	}
	return nil
}

func (r *Reconciler) secretObject(namespace string, cr secretSyncObject, values map[string][]byte, hash string) map[string]any {
	data := make(map[string]string, len(values))
	for key, value := range values {
		data[key] = base64.StdEncoding.EncodeToString(value)
	}
	typ := strings.TrimSpace(cr.Spec.Target.Type)
	if typ == "" {
		typ = "Opaque"
	}
	return map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata": map[string]any{
			"name":      cr.Spec.targetName(cr.Metadata.Name),
			"namespace": namespace,
			"labels": map[string]any{
				kubernetesSecretManagedLabel: "trstctl-operator",
			},
			"annotations": map[string]any{
				kubernetesSecretHashAnnotation: hash,
				kubernetesSecretNameAnnotation: cr.Metadata.Name,
			},
		},
		"type": typ,
		"data": data,
	}
}

func (r *Reconciler) patchReloadWorkloads(ctx context.Context, namespace string, cr secretSyncObject, hash string) ([]string, error) {
	reloaded := []string{}
	for _, ref := range cr.Spec.Reload.Workloads {
		if strings.TrimSpace(ref.Name) == "" {
			return reloaded, fmt.Errorf("operator: reload workload name is required")
		}
		path, err := workloadItemPath(namespace, ref)
		if err != nil {
			return reloaded, err
		}
		needsPatch, err := r.workloadNeedsReloadPatch(ctx, path, hash)
		if err != nil {
			return reloaded, err
		}
		if !needsPatch {
			continue
		}
		patch := map[string]any{"spec": map[string]any{"template": map[string]any{"metadata": map[string]any{"annotations": map[string]any{
			kubernetesSecretHashAnnotation: hash,
			kubernetesSecretNameAnnotation: cr.Metadata.Name,
		}}}}}
		st, body, err := r.client.do(ctx, http.MethodPatch, path, "application/merge-patch+json", patch)
		if err != nil {
			return reloaded, err
		}
		if st/100 != 2 {
			return reloaded, fmt.Errorf("operator: patch reload workload %s/%s: status %d: %s", namespace, ref.Name, st, string(body))
		}
		reloaded = append(reloaded, strings.TrimSpace(ref.Kind)+"/"+ref.Name)
	}
	return reloaded, nil
}

func (r *Reconciler) workloadNeedsReloadPatch(ctx context.Context, path, hash string) (bool, error) {
	st, body, err := r.client.do(ctx, http.MethodGet, path, "", nil)
	if err != nil {
		return false, err
	}
	if st/100 != 2 {
		return false, fmt.Errorf("operator: get reload workload %s: status %d: %s", path, st, string(body))
	}
	var obj struct {
		Spec struct {
			Template struct {
				Metadata struct {
					Annotations map[string]string `json:"annotations"`
				} `json:"metadata"`
			} `json:"template"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(body, &obj); err != nil {
		return false, fmt.Errorf("operator: decode reload workload %s: %w", path, err)
	}
	return obj.Spec.Template.Metadata.Annotations[kubernetesSecretHashAnnotation] != hash, nil
}

func (r *Reconciler) updateSecretSyncStatus(ctx context.Context, namespace, name, phase, target string, keys int, hash string, reloaded []string, message string) error {
	status := map[string]any{
		"phase":        phase,
		"targetSecret": target,
		"syncedKeys":   keys,
	}
	if hash != "" {
		status["contentHash"] = hash
	}
	if len(reloaded) > 0 {
		status["reloadedWorkloads"] = reloaded
	}
	if message != "" {
		status["message"] = message
	}
	st, body, err := r.client.do(ctx, http.MethodPatch, tssItemPath(namespace, name)+"/status", "application/merge-patch+json", map[string]any{"status": status})
	if err != nil {
		return err
	}
	if st == http.StatusNotFound {
		return nil
	}
	if st/100 != 2 {
		return fmt.Errorf("operator: patch secret sync status %s/%s: status %d: %s", namespace, name, st, string(body))
	}
	return nil
}

// HTTPSecretResolver resolves trstctl secrets through the served control-plane API.
type HTTPSecretResolver struct {
	k8s        *Client
	httpClient *http.Client
}

func NewHTTPSecretResolver(k8s *Client, httpClient *http.Client) *HTTPSecretResolver {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &HTTPSecretResolver{k8s: k8s, httpClient: httpClient}
}

func (r *HTTPSecretResolver) ResolveSecret(ctx context.Context, namespace string, spec SecretSyncSpec, remoteName string) ([]byte, error) {
	cpURL := strings.TrimRight(strings.TrimSpace(spec.ControlPlane.URL), "/")
	if cpURL == "" {
		return nil, fmt.Errorf("operator: TrstctlSecretSync controlPlane.url is required")
	}
	token, err := r.readToken(ctx, namespace, spec.ControlPlane.TokenSecretRef)
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(token)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cpURL+"/api/v1/secrets/store/"+secretPath(remoteName)+"?resolve=true", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json, application/problem+json")
	req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", token))
	if tenant := strings.TrimSpace(spec.ControlPlane.TenantID); tenant != "" {
		req.Header.Set("X-Tenant-ID", tenant)
	}
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAPIBody))
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(body)
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("operator: resolve trstctl secret %q: status %d: %s", remoteName, resp.StatusCode, string(body))
	}
	var out struct {
		Value secretWireBytes `json:"value"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("operator: decode trstctl secret %q: %w", remoteName, err)
	}
	value := append([]byte(nil), out.Value...)
	secret.Wipe(out.Value)
	return value, nil
}

func (r *HTTPSecretResolver) readToken(ctx context.Context, namespace string, ref SecretKeyRef) ([]byte, error) {
	name := strings.TrimSpace(ref.Name)
	key := strings.TrimSpace(ref.Key)
	if key == "" {
		key = "token"
	}
	if name == "" {
		return nil, fmt.Errorf("operator: controlPlane.tokenSecretRef.name is required")
	}
	st, body, err := r.k8s.do(ctx, http.MethodGet, secretItemPath(namespace, name), "", nil)
	if err != nil {
		return nil, err
	}
	if st/100 != 2 {
		return nil, fmt.Errorf("operator: read token Secret %s/%s: status %d: %s", namespace, name, st, string(body))
	}
	defer secret.Wipe(body)
	var obj struct {
		Data map[string][]byte `json:"data"`
	}
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil, fmt.Errorf("operator: decode token Secret %s/%s: %w", namespace, name, err)
	}
	token, ok := obj.Data[key]
	if !ok {
		return nil, fmt.Errorf("operator: token Secret %s/%s missing key %q", namespace, name, key)
	}
	return token, nil
}

func secretPath(name string) string {
	parts := strings.Split(name, "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	return strings.Join(parts, "/")
}

func wipeSecretData(values map[string][]byte) {
	for key, value := range values {
		secret.Wipe(value)
		delete(values, key)
	}
}

type secretWireBytes []byte

func (b *secretWireBytes) UnmarshalJSON(data []byte) error {
	if bytes.Equal(data, []byte("null")) {
		*b = nil
		return nil
	}
	out, err := decodeJSONSecretString(data)
	if err != nil {
		return err
	}
	*b = out
	return nil
}

func decodeJSONSecretString(data []byte) ([]byte, error) {
	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		return nil, fmt.Errorf("expected JSON string")
	}
	out := make([]byte, 0, len(data)-2)
	for i := 1; i < len(data)-1; i++ {
		c := data[i]
		if c == '"' || c < 0x20 {
			return nil, fmt.Errorf("invalid JSON string")
		}
		if c != '\\' {
			out = append(out, c)
			continue
		}
		i++
		if i >= len(data)-1 {
			return nil, fmt.Errorf("invalid JSON escape")
		}
		switch esc := data[i]; esc {
		case '"', '\\', '/':
			out = append(out, esc)
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'u':
			r, ni, err := decodeUnicodeEscape(data, i+1)
			if err != nil {
				return nil, err
			}
			i = ni
			out = utf8.AppendRune(out, r)
		default:
			return nil, fmt.Errorf("invalid JSON escape")
		}
	}
	return out, nil
}

func decodeUnicodeEscape(data []byte, pos int) (rune, int, error) {
	if pos+4 > len(data)-1 {
		return 0, pos, fmt.Errorf("short unicode escape")
	}
	r, ok := hex4(data[pos : pos+4])
	if !ok {
		return 0, pos, fmt.Errorf("invalid unicode escape")
	}
	pos += 4
	if utf16.IsSurrogate(r) {
		if pos+6 > len(data)-1 || data[pos] != '\\' || data[pos+1] != 'u' {
			return 0, pos, fmt.Errorf("missing low surrogate")
		}
		lo, ok := hex4(data[pos+2 : pos+6])
		if !ok {
			return 0, pos, fmt.Errorf("invalid low surrogate")
		}
		pos += 6
		r = utf16.DecodeRune(r, lo)
		if r == utf8.RuneError {
			return 0, pos, fmt.Errorf("invalid surrogate pair")
		}
	}
	return r, pos - 1, nil
}

func hex4(data []byte) (rune, bool) {
	var v rune
	for _, c := range data {
		v <<= 4
		switch {
		case '0' <= c && c <= '9':
			v += rune(c - '0')
		case 'a' <= c && c <= 'f':
			v += rune(c-'a') + 10
		case 'A' <= c && c <= 'F':
			v += rune(c-'A') + 10
		default:
			return 0, false
		}
	}
	return v, true
}
