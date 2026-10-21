// SPDX-License-Identifier: BUSL-1.1

package k8s

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
)

// EnumerateCertificates lists the TLS Secrets in the client's namespace and
// returns each Secret's certificate (its tls.crt) as PEM, keyed by Secret name —
// the read side used by agent discovery (S6.2). Non-TLS Secrets and Secrets
// without a tls.crt are skipped. Secret data values are base64-encoded on the
// wire; they are decoded here.
func (c *Client) EnumerateCertificates(ctx context.Context) (map[string][]byte, error) {
	return c.EnumerateCertificatesIn(ctx, c.namespace)
}

// NamespaceEnumerator is one namespace's view of EnumerateCertificates, so a
// cross-namespace inventory can hand each namespace its own discovery source.
type NamespaceEnumerator struct {
	client    *Client
	namespace string
}

// EnumerateCertificates lists the TLS Secrets of the bound namespace.
func (n NamespaceEnumerator) EnumerateCertificates(ctx context.Context) (map[string][]byte, error) {
	return n.client.EnumerateCertificatesIn(ctx, n.namespace)
}

// InNamespace binds the enumeration to one namespace.
func (c *Client) InNamespace(namespace string) NamespaceEnumerator {
	return NamespaceEnumerator{client: c, namespace: namespace}
}

// ListNamespaces returns every namespace the service account may list, sorted.
// It needs cluster-scoped list access to namespaces; a forbidden answer is an
// error, never an empty cluster.
func (c *Client) ListNamespaces(ctx context.Context) ([]string, error) {
	status, body, err := c.request(ctx, http.MethodGet, "/api/v1/namespaces", nil)
	if err != nil {
		return nil, err
	}
	if status/100 != 2 {
		return nil, fmt.Errorf("k8s: list namespaces: status %d: %s", status, string(body))
	}
	var list struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("k8s: decode namespace list: %w", err)
	}
	out := make([]string, 0, len(list.Items))
	for _, it := range list.Items {
		if it.Metadata.Name != "" {
			out = append(out, it.Metadata.Name)
		}
	}
	sort.Strings(out)
	return out, nil
}

// EnumerateCertificatesIn lists the kubernetes.io/tls Secrets of one namespace
// and returns their certificates (tls.crt only; tls.key is never read).
func (c *Client) EnumerateCertificatesIn(ctx context.Context, namespace string) (map[string][]byte, error) {
	status, body, err := c.request(ctx, http.MethodGet, fmt.Sprintf("/api/v1/namespaces/%s/secrets", namespace), nil)
	if err != nil {
		return nil, err
	}
	if status/100 != 2 {
		return nil, fmt.Errorf("k8s: list secrets in %s: status %d: %s", namespace, status, string(body))
	}

	var list struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Type string            `json:"type"`
			Data map[string]string `json:"data"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("k8s: decode secret list: %w", err)
	}

	out := make(map[string][]byte)
	for _, it := range list.Items {
		if it.Type != "kubernetes.io/tls" {
			continue
		}
		encoded, ok := it.Data["tls.crt"]
		if !ok || encoded == "" {
			continue
		}
		pem, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			continue
		}
		out[it.Metadata.Name] = pem
	}
	return out, nil
}
