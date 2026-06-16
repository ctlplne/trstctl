package k8s

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"trstctl.com/trstctl/internal/agent/destination"
)

// SecretDestination installs a credential into a Kubernetes Secret of type
// kubernetes.io/tls (data keys tls.crt and tls.key), creating the Secret or
// updating it in place. It satisfies destination.Destination.
type SecretDestination struct {
	client    *Client
	namespace string
	name      string
}

var _ destination.Destination = (*SecretDestination)(nil)

// NewSecretDestination returns a destination writing to the Secret name in
// namespace.
func NewSecretDestination(client *Client, namespace, name string) *SecretDestination {
	return &SecretDestination{client: client, namespace: namespace, name: name}
}

func (d *SecretDestination) collectionPath() string {
	return fmt.Sprintf("/api/v1/namespaces/%s/secrets", d.namespace)
}

func (d *SecretDestination) itemPath() string {
	return d.collectionPath() + "/" + d.name
}

// Install writes the credential into the Secret. It is idempotent: if the
// Secret exists it is updated (carrying the resourceVersion for optimistic
// concurrency), otherwise it is created.
func (d *SecretDestination) Install(ctx context.Context, cred destination.Credential) error {
	if len(cred.CertPEM) == 0 {
		return errors.New("k8s: nothing to install (empty certificate)")
	}
	data := map[string]string{"tls.crt": base64.StdEncoding.EncodeToString(cred.CertPEM)}
	if cred.HasKey() {
		data["tls.key"] = base64.StdEncoding.EncodeToString(cred.KeyPEM)
	}
	meta := map[string]any{"name": d.name, "namespace": d.namespace}

	status, body, err := d.client.request(ctx, http.MethodGet, d.itemPath(), nil)
	if err != nil {
		return err
	}
	if status == http.StatusOK {
		if rv := resourceVersion(body); rv != "" {
			meta["resourceVersion"] = rv
		}
		return d.put(ctx, secretObject(meta, data))
	}
	// Create; fall back to update if we raced another writer.
	st, rb, err := d.client.request(ctx, http.MethodPost, d.collectionPath(), secretObject(meta, data))
	if err != nil {
		return err
	}
	if st == http.StatusConflict {
		return d.put(ctx, secretObject(meta, data))
	}
	if st/100 != 2 {
		return fmt.Errorf("k8s: create secret %s/%s: status %d: %s", d.namespace, d.name, st, string(rb))
	}
	return nil
}

func (d *SecretDestination) put(ctx context.Context, obj map[string]any) error {
	st, rb, err := d.client.request(ctx, http.MethodPut, d.itemPath(), obj)
	if err != nil {
		return err
	}
	if st/100 != 2 {
		return fmt.Errorf("k8s: update secret %s/%s: status %d: %s", d.namespace, d.name, st, string(rb))
	}
	return nil
}

// Describe returns a short identifier for the destination.
func (d *SecretDestination) Describe() string {
	return fmt.Sprintf("k8s-secret(%s/%s)", d.namespace, d.name)
}

func secretObject(meta map[string]any, data map[string]string) map[string]any {
	return map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"type":       "kubernetes.io/tls",
		"metadata":   meta,
		"data":       data,
	}
}

func resourceVersion(body []byte) string {
	var obj struct {
		Metadata struct {
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(body, &obj); err != nil {
		return ""
	}
	return obj.Metadata.ResourceVersion
}
