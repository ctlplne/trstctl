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
// Secret exists it is updated (carrying the resourceVersion for optimistic
// concurrency, and keeping its labels and annotations), otherwise it is created.
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
	meta := map[string]any{"name": d.name, "namespace": d.namespace}

	status, body, err := d.client.request(ctx, http.MethodGet, d.itemPath(), nil)
	if err != nil {
		return err
	}
	if status == http.StatusOK {
		existing := existingMetadata(body)
		if existing.ResourceVersion != "" {
			meta["resourceVersion"] = existing.ResourceVersion
		}
		// Other tools label and annotate the Secret an Ingress names; an update
		// replaces the object, so carry those forward instead of dropping them.
		if len(existing.Labels) > 0 {
			meta["labels"] = existing.Labels
		}
		if len(existing.Annotations) > 0 {
			meta["annotations"] = existing.Annotations
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

type secretMetadata struct {
	ResourceVersion string            `json:"resourceVersion"`
	Labels          map[string]string `json:"labels"`
	Annotations     map[string]string `json:"annotations"`
}

func existingMetadata(body []byte) secretMetadata {
	var obj struct {
		Metadata secretMetadata `json:"metadata"`
	}
	if err := json.Unmarshal(body, &obj); err != nil {
		return secretMetadata{}
	}
	return obj.Metadata
}

// Status reads the Secret without changing it and returns the API server's
// HTTP status: 200 when it exists, 404 when a write would create it.
func (d *SecretDestination) Status(ctx context.Context) (int, error) {
	status, _, err := d.client.request(ctx, http.MethodGet, d.itemPath(), nil)
	return status, err
}
