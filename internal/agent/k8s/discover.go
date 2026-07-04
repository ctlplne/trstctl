// SPDX-License-Identifier: MPL-2.0

package k8s

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
)

// EnumerateCertificates lists the TLS Secrets in the client's namespace and
// returns each Secret's certificate (its tls.crt) as PEM, keyed by Secret name —
// the read side used by agent discovery (S6.2). Non-TLS Secrets and Secrets
// without a tls.crt are skipped. Secret data values are base64-encoded on the
// wire; they are decoded here.
func (c *Client) EnumerateCertificates(ctx context.Context) (map[string][]byte, error) {
	status, body, err := c.request(ctx, http.MethodGet, fmt.Sprintf("/api/v1/namespaces/%s/secrets", c.namespace), nil)
	if err != nil {
		return nil, err
	}
	if status/100 != 2 {
		return nil, fmt.Errorf("k8s: list secrets in %s: status %d: %s", c.namespace, status, string(body))
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
