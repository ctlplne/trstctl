// SPDX-License-Identifier: BUSL-1.1

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

// SecretReadback is what the cluster holds after a write: the Secret's
// identity and the certificate in its tls.crt. It carries no key bytes.
type SecretReadback struct {
	Namespace       string
	Name            string
	UID             string
	ResourceVersion string
	CertPEM         []byte
}

// Install writes the credential into the Secret. It is idempotent: if the
// Secret exists its certificate and key are patched in place (conditional on
// the resourceVersion read with it, and keeping everything else other
// controllers set on it), otherwise it is created.
func (d *SecretDestination) Install(ctx context.Context, cred destination.Credential) error {
	return d.write(ctx, cred)
}

// InstallAndRead writes the credential as Install does and then reads the
// Secret back, so the caller can compare what the cluster stores with what it
// wrote instead of trusting that an accepted write took effect.
func (d *SecretDestination) InstallAndRead(ctx context.Context, cred destination.Credential) (SecretReadback, error) {
	if err := d.write(ctx, cred); err != nil {
		return SecretReadback{}, err
	}
	status, body, err := d.client.request(ctx, http.MethodGet, d.itemPath(), nil)
	if err != nil {
		return SecretReadback{}, err
	}
	if status != http.StatusOK {
		return SecretReadback{}, fmt.Errorf("k8s: read back secret %s/%s: status %d", d.namespace, d.name, status)
	}
	var obj struct {
		Metadata struct {
			UID             string `json:"uid"`
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(body, &obj); err != nil {
		return SecretReadback{}, fmt.Errorf("k8s: decode secret %s/%s: %w", d.namespace, d.name, err)
	}
	certPEM, err := base64.StdEncoding.DecodeString(obj.Data["tls.crt"])
	if err != nil {
		return SecretReadback{}, fmt.Errorf("k8s: secret %s/%s tls.crt is not base64", d.namespace, d.name)
	}
	return SecretReadback{Namespace: d.namespace, Name: d.name, UID: obj.Metadata.UID,
		ResourceVersion: obj.Metadata.ResourceVersion, CertPEM: certPEM}, nil
}

func (d *SecretDestination) write(ctx context.Context, cred destination.Credential) error {
	if len(cred.CertPEM) == 0 {
		return errors.New("k8s: nothing to install (empty certificate)")
	}
	data := map[string]string{"tls.crt": base64.StdEncoding.EncodeToString(cred.CertPEM)}
	if cred.HasKey() {
		data["tls.key"] = base64.StdEncoding.EncodeToString(cred.KeyPEM)
	}

	status, body, err := d.client.request(ctx, http.MethodGet, d.itemPath(), nil)
	if err != nil {
		return err
	}
	if status == http.StatusOK {
		return d.patch(ctx, existingResourceVersion(body), data)
	}
	// Create; fall back to a patch if we raced another writer.
	meta := map[string]any{"name": d.name, "namespace": d.namespace}
	st, rb, err := d.client.request(ctx, http.MethodPost, d.collectionPath(), secretObject(meta, data))
	if err != nil {
		return err
	}
	if st == http.StatusConflict {
		return d.patch(ctx, "", data)
	}
	if st/100 != 2 {
		return fmt.Errorf("k8s: create secret %s/%s: status %d: %s", d.namespace, d.name, st, string(rb))
	}
	return nil
}

// patch writes the certificate, and the key when the credential carries one,
// into the existing Secret with a JSON merge patch (K8S-O2). A Secret an
// Ingress or Gateway names is often owned and guarded by other controllers: a
// full-object replace dropped the ownerReferences that tie it to its owner's
// garbage collection, the finalizers that hold its deletion for a cleanup
// hook, and data keys such as ca.crt. The patch names only the type and the
// data keys it writes, so the API server keeps every other field as it holds
// it, and a credential without a key leaves the key the Secret already holds.
// The resourceVersion read with the Secret makes the patch conditional: a
// concurrent writer's change fails it with a conflict instead of being
// overwritten. The type is sent as written so a Secret of another type still
// refuses the write, as the replace did.
func (d *SecretDestination) patch(ctx context.Context, resourceVersion string, data map[string]string) error {
	obj := map[string]any{"type": "kubernetes.io/tls", "data": data}
	if resourceVersion != "" {
		obj["metadata"] = map[string]any{"resourceVersion": resourceVersion}
	}
	st, rb, err := d.client.requestAs(ctx, http.MethodPatch, d.itemPath(), mergePatchContentType, obj)
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

// existingResourceVersion is the resourceVersion of the Secret a GET read.
func existingResourceVersion(body []byte) string {
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

// Status reads the Secret without changing it and returns the API server's
// HTTP status: 200 when it exists, 404 when a write would create it.
func (d *SecretDestination) Status(ctx context.Context) (int, error) {
	status, _, err := d.client.request(ctx, http.MethodGet, d.itemPath(), nil)
	return status, err
}
