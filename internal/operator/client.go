// Package operator is the trstctl Kubernetes Operator's reconcile core: it
// watches TrstctlControlPlane custom resources (group trstctl.com,
// deploy/operator/crd.yaml) and drives the cluster's control-plane Deployment to
// match each resource's declared desired state — the replica count and image —
// then writes the observed result back to the resource's status subresource.
//
// Like the agent's Kubernetes mode (internal/agent/k8s), it speaks the
// Kubernetes API server's JSON-over-HTTPS wire protocol DIRECTLY, with no
// client-go / controller-runtime dependency (none is in go.mod, and adding one
// is out of scope here). TLS trust to the API server is built through the crypto
// boundary (internal/crypto/mtls), so this package imports no crypto/* (AN-3).
//
// Scope and maturity are documented honestly in deploy/operator/doc.go: this is
// a small, level-based reconcile loop (poll → diff → act), not a full
// informer/work-queue controller. It reconciles the Deployment shape the Helm
// chart also renders; it does not yet manage Services, secrets, NetworkPolicy,
// or the isolated signer topology (those remain the Helm chart's job).
package operator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto/mtls"
)

const (
	saTokenPath     = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	saCAPath        = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	saNamespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
	maxAPIBody      = 4 << 20
)

// Client is a minimal authenticated client for the Kubernetes REST API, scoped
// to exactly the verbs the operator needs (list/get/create/patch Deployments and
// get/patch TrstctlControlPlane status). It deliberately mirrors
// internal/agent/k8s.Client rather than depending on it, so the operator carries
// no cert-manager bridge surface and the two stay independently testable.
type Client struct {
	base       string
	token      string
	httpClient *http.Client
}

// NewClient returns a client for base (the API server URL) authenticating with
// token. httpClient carries the cluster trust; in tests it is the httptest
// server's client.
func NewClient(base, token string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{base: strings.TrimRight(base, "/"), token: token, httpClient: httpClient}
}

// InCluster builds a client from the standard in-cluster service-account mount
// and the KUBERNETES_SERVICE_* environment. TLS trust comes from the crypto
// boundary (AN-3). The returned namespace is the operator pod's own namespace,
// used as the default scope when the operator is configured namespaced.
func InCluster() (client *Client, namespace string, err error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, "", fmt.Errorf("operator: not running in a cluster (KUBERNETES_SERVICE_HOST/PORT unset)")
	}
	token, err := os.ReadFile(saTokenPath)
	if err != nil {
		return nil, "", fmt.Errorf("operator: read service-account token: %w", err)
	}
	caPEM, err := os.ReadFile(saCAPath)
	if err != nil {
		return nil, "", fmt.Errorf("operator: read cluster CA: %w", err)
	}
	transport, err := mtls.HTTPTransport(caPEM)
	if err != nil {
		return nil, "", err
	}
	ns, _ := os.ReadFile(saNamespacePath)
	c := NewClient(
		fmt.Sprintf("https://%s:%s", host, port),
		strings.TrimSpace(string(token)),
		&http.Client{Transport: transport, Timeout: 30 * time.Second},
	)
	return c, strings.TrimSpace(string(ns)), nil
}

// do performs an authenticated request and returns the status code and response
// body. Non-2xx is not a transport error here — callers interpret the code (for
// example 404 during get-or-create, 409 on a stale resourceVersion). contentType
// selects the request body media type; for JSON-merge-patch it is set to
// application/merge-patch+json.
func (c *Client) do(ctx context.Context, method, path, contentType string, body any) (int, []byte, error) {
	var reader io.Reader
	if body != nil {
		var buf []byte
		switch b := body.(type) {
		case []byte:
			buf = b
		default:
			var err error
			buf, err = json.Marshal(body)
			if err != nil {
				return 0, nil, err
			}
		}
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return 0, nil, err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		if contentType == "" {
			contentType = "application/json"
		}
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxAPIBody))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, data, nil
}
