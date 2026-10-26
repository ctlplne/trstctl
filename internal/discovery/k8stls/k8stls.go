// SPDX-License-Identifier: BUSL-1.1

// Package k8stls normalizes Kubernetes Ingress and Gateway API TLS resources
// into metadata-only auto-issuance requests. It never accepts TLS private keys,
// certificates, kubeconfigs, service-account tokens, or Kubernetes Secret bodies.
package k8stls

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

const (
	// SourceKind is the served discovery source kind for CAP-K8S-03.
	SourceKind = "k8s_ingress_gateway"
	// FindingKind is the read-model kind emitted for Kubernetes TLS auto-issuance.
	FindingKind = "k8s_tls_auto_issuance"
	// MaxResources caps a single served source config so one run cannot exhaust the
	// discovery worker lane.
	MaxResources = 10000
)

// Config is the persisted source configuration for Kubernetes TLS auto-issuance.
// Resources are metadata-only references exported from a Kubernetes API watch,
// admission path, or manifest inventory.
type Config struct {
	Resources []Resource `json:"resources"`
	// ClusterAgentID binds the source to the host-role agent running inside the
	// cluster. Without it a run records the resources and delivers nothing; with
	// it each resource is delivered the cert-manager way: the agent generates
	// the key in the cluster, sends only a CSR and writes the Secret itself.
	ClusterAgentID string `json:"cluster_agent_id,omitempty"`
	// OwnerID owns the identities a bound source requests. Required with
	// ClusterAgentID.
	OwnerID string `json:"owner_id,omitempty"`
	// VerifyAddress is the optional in-cluster listener (host:port) the agent
	// handshakes after writing a Secret, with the resource's first host as the
	// server name, such as the ingress controller's service.
	VerifyAddress string `json:"verify_address,omitempty"`
}

// Delivery is how a bound source delivers: the cluster agent, the owner of the
// identities it requests and the optional verification listener. A zero
// ClusterAgentID means the source binds no agent.
type Delivery struct {
	ClusterAgentID string
	OwnerID        string
	VerifyAddress  string
}

// DeliverySettings decodes and checks a source's delivery binding.
func DeliverySettings(raw json.RawMessage) (Delivery, error) {
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return Delivery{}, fmt.Errorf("decode Kubernetes ingress/gateway discovery config: %w", err)
	}
	return deliveryOf(cfg)
}

func deliveryOf(cfg Config) (Delivery, error) {
	out := Delivery{
		ClusterAgentID: strings.TrimSpace(cfg.ClusterAgentID),
		OwnerID:        strings.TrimSpace(cfg.OwnerID),
		VerifyAddress:  strings.TrimSpace(cfg.VerifyAddress),
	}
	if out.ClusterAgentID == "" {
		if out.OwnerID != "" || out.VerifyAddress != "" {
			return Delivery{}, errors.New("owner_id and verify_address apply only with cluster_agent_id")
		}
		return out, nil
	}
	if _, err := uuid.Parse(out.ClusterAgentID); err != nil {
		return Delivery{}, errors.New("cluster_agent_id must be the UUID of an enrolled host-role agent")
	}
	if _, err := uuid.Parse(out.OwnerID); err != nil {
		return Delivery{}, errors.New("owner_id must name the owner of the certificates this source requests")
	}
	if out.VerifyAddress != "" {
		host, port, err := net.SplitHostPort(out.VerifyAddress)
		if number, convErr := strconv.Atoi(port); err != nil || strings.TrimSpace(host) == "" || convErr != nil || number < 1 || number > 65535 {
			return Delivery{}, errors.New("verify_address must be host:port")
		}
	}
	return out, nil
}

// Resource describes one Ingress or Gateway API object that needs a served TLS
// certificate minted for its referenced Kubernetes TLS Secret.
type Resource struct {
	Kind          string   `json:"kind"`
	APIVersion    string   `json:"api_version,omitempty"`
	Namespace     string   `json:"namespace"`
	Name          string   `json:"name"`
	TLSSecretName string   `json:"tls_secret_name"`
	Hosts         []string `json:"hosts"`
	AutoIssue     *bool    `json:"auto_issue,omitempty"`
}

// Finding is the normalized discovery finding material emitted by the server.
type Finding struct {
	// The resource and the TLS Secret it names, for delivery.
	ResourceKind  string
	Namespace     string
	ResourceName  string
	TLSSecretName string

	Ref                    string
	Provenance             string
	Fingerprint            string
	RiskScore              int
	Metadata               map[string]any
	CommonName             string
	DNSNames               []string
	DeploymentLocation     string
	IssuanceIdempotencyKey string
}

// Findings decodes, validates, and normalizes a source config into Kubernetes TLS
// auto-issuance findings. A normal run records each finding and reports the
// resource not delivered until the in-cluster agent delivers it; discovery
// dry-run is the planning mode, so resource-level auto_issue must be true when
// present.
func Findings(raw json.RawMessage) ([]Finding, error) {
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("decode Kubernetes ingress/gateway discovery config: %w", err)
	}
	if len(cfg.Resources) == 0 {
		return nil, errors.New("kubernetes ingress/gateway discovery requires resources")
	}
	if len(cfg.Resources) > MaxResources {
		return nil, fmt.Errorf("kubernetes ingress/gateway discovery source has %d resources; maximum is %d", len(cfg.Resources), MaxResources)
	}
	if _, err := deliveryOf(cfg); err != nil {
		return nil, fmt.Errorf("kubernetes ingress/gateway delivery: %w", err)
	}

	out := make([]Finding, 0, len(cfg.Resources))
	for i, resource := range cfg.Resources {
		finding, err := normalizeResource(resource)
		if err != nil {
			return nil, fmt.Errorf("kubernetes ingress/gateway resource %d: %w", i, err)
		}
		out = append(out, finding)
	}
	return out, nil
}

// ValidateConfig checks the source config without returning normalized findings.
func ValidateConfig(raw json.RawMessage) error {
	_, err := Findings(raw)
	return err
}

func normalizeResource(resource Resource) (Finding, error) {
	kind, err := normalizeKind(resource.Kind)
	if err != nil {
		return Finding{}, err
	}
	namespace := strings.TrimSpace(resource.Namespace)
	name := strings.TrimSpace(resource.Name)
	tlsSecret := strings.TrimSpace(resource.TLSSecretName)
	if namespace == "" || name == "" || tlsSecret == "" {
		return Finding{}, errors.New("namespace, name, and tls_secret_name are required")
	}
	if !validKubernetesName(namespace) {
		return Finding{}, fmt.Errorf("namespace %q is not a valid Kubernetes DNS label", namespace)
	}
	if !validKubernetesName(name) {
		return Finding{}, fmt.Errorf("name %q is not a valid Kubernetes DNS label", name)
	}
	if !validKubernetesName(tlsSecret) {
		return Finding{}, fmt.Errorf("tls_secret_name %q is not a valid Kubernetes DNS label", tlsSecret)
	}
	if resource.AutoIssue != nil && !*resource.AutoIssue {
		return Finding{}, errors.New("auto_issue must be true; use discovery dry_run to plan without recording the resources")
	}
	hosts, err := normalizeHosts(resource.Hosts)
	if err != nil {
		return Finding{}, err
	}

	apiVersion := strings.TrimSpace(resource.APIVersion)
	if apiVersion == "" {
		apiVersion = defaultAPIVersion(kind)
	}
	ref := kind + ":" + namespace + "/" + name
	location := "k8s:" + kind + ":" + namespace + "/" + name + ":secret/" + tlsSecret
	provenance := SourceKind + ":" + kind + ":" + namespace + "/" + name + ":" + tlsSecret
	meta := map[string]any{
		"api_version":     apiVersion,
		"resource_kind":   kind,
		"namespace":       namespace,
		"name":            name,
		"tls_secret_name": tlsSecret,
		"hosts":           hosts,
		"auto_issue":      true,
	}
	return Finding{
		ResourceKind:       kind,
		Namespace:          namespace,
		ResourceName:       name,
		TLSSecretName:      tlsSecret,
		Ref:                ref,
		Provenance:         provenance,
		Fingerprint:        provenance,
		RiskScore:          riskScore(hosts),
		Metadata:           meta,
		CommonName:         hosts[0],
		DNSNames:           hosts,
		DeploymentLocation: location,
	}, nil
}

func normalizeKind(kind string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "ingress":
		return "Ingress", nil
	case "gateway":
		return "Gateway", nil
	default:
		return "", errors.New("kind must be Ingress or Gateway")
	}
}

func defaultAPIVersion(kind string) string {
	if kind == "Gateway" {
		return "gateway.networking.k8s.io/v1"
	}
	return "networking.k8s.io/v1"
}

// NormalizeHosts lowercases, validates and de-duplicates TLS hosts the way a
// source's resources are normalized, keeping their order.
func NormalizeHosts(values []string) ([]string, error) { return normalizeHosts(values) }

func normalizeHosts(values []string) ([]string, error) {
	out := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
		if host == "" {
			continue
		}
		if err := validateHost(host); err != nil {
			return nil, err
		}
		if seen[host] {
			continue
		}
		seen[host] = true
		out = append(out, host)
	}
	if len(out) == 0 {
		return nil, errors.New("at least one host is required")
	}
	return out, nil
}

func validateHost(host string) error {
	if len(host) > 253 {
		return fmt.Errorf("host %q is longer than 253 characters", host)
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return fmt.Errorf("host %q must be a DNS name", host)
	}
	for i, label := range labels {
		if i == 0 && label == "*" {
			continue
		}
		if !validKubernetesName(label) {
			return fmt.Errorf("host %q has invalid label %q", host, label)
		}
	}
	return nil
}

func validKubernetesName(value string) bool {
	if value == "" || len(value) > 63 {
		return false
	}
	if value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' {
			continue
		}
		if r >= '0' && r <= '9' {
			continue
		}
		if r == '-' {
			continue
		}
		return false
	}
	return true
}

func riskScore(hosts []string) int {
	score := 30
	if len(hosts) > 1 {
		score += 10
	}
	for _, host := range hosts {
		if strings.HasPrefix(host, "*.") {
			score += 20
			break
		}
	}
	if score > 100 {
		return 100
	}
	return score
}
