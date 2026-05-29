// Package k8s lets the agent run as a Kubernetes DaemonSet: it installs
// certificates into Kubernetes Secrets and bridges cert-manager
// CertificateRequests to certctl issuance.
//
// It speaks the Kubernetes API server's JSON-over-HTTPS wire protocol directly
// (no client-go), authenticating with the pod's service-account token. TLS
// trust is built through the crypto boundary, so this package imports no
// crypto/* (AN-3); credentials are carried as []byte (AN-8).
package k8s

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

	"certctl.io/certctl/internal/crypto/mtls"
)

const (
	saTokenPath     = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	saCAPath        = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	saNamespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
	maxAPIBody      = 4 << 20
)

// Client is a minimal authenticated client for the Kubernetes REST API.
type Client struct {
	base       string
	token      string
	namespace  string
	httpClient *http.Client
}

// New returns a client for base (the API server URL) authenticating with token,
// defaulting to namespace. httpClient carries the cluster trust; in tests it is
// the httptest server's client.
func New(base, token, namespace string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{base: strings.TrimRight(base, "/"), token: token, namespace: namespace, httpClient: httpClient}
}

// InCluster builds a client from the standard in-cluster service-account mount
// and the KUBERNETES_SERVICE_* environment. TLS trust comes from the crypto
// boundary (AN-3).
func InCluster() (*Client, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, fmt.Errorf("k8s: not running in a cluster (KUBERNETES_SERVICE_HOST/PORT unset)")
	}
	token, err := os.ReadFile(saTokenPath)
	if err != nil {
		return nil, fmt.Errorf("k8s: read service-account token: %w", err)
	}
	caPEM, err := os.ReadFile(saCAPath)
	if err != nil {
		return nil, fmt.Errorf("k8s: read cluster CA: %w", err)
	}
	transport, err := mtls.HTTPTransport(caPEM)
	if err != nil {
		return nil, err
	}
	ns, _ := os.ReadFile(saNamespacePath)
	return New(
		fmt.Sprintf("https://%s:%s", host, port),
		strings.TrimSpace(string(token)),
		strings.TrimSpace(string(ns)),
		&http.Client{Transport: transport, Timeout: 30 * time.Second},
	), nil
}

// Namespace returns the client's default namespace (the pod's namespace
// in-cluster).
func (c *Client) Namespace() string { return c.namespace }

// request performs an authenticated JSON request and returns the status code
// and response body. Non-2xx is not an error here — callers interpret the code
// (for example 404/409 during create-or-update).
func (c *Client) request(ctx context.Context, method, path string, body any) (int, []byte, error) {
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
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
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxAPIBody))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, data, nil
}
