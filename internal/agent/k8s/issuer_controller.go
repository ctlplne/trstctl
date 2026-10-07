// SPDX-License-Identifier: BUSL-1.1

package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// DefaultIssuerGroup is the Kubernetes API group used by the trstctl
	// cert-manager external issuer CRDs.
	DefaultIssuerGroup = "trstctl.com"

	trstctlAPIVersion  = "trstctl.com/v1alpha1"
	issuersPlural      = "issuers"
	clusterPlural      = "clusterissuers"
	certificatesPlural = "certificates"
	trustBundlesPlural = "trustbundles"
)

// IssuerReconcileResult summarizes one external-issuer controller reconcile.
type IssuerReconcileResult struct {
	ClusterIssuersReady           int
	IssuersReady                  int
	SignedRequests                int
	CertificateRequestComplete    bool
	CertificateRequestFailureCode string
	CertificateRequestPosture     []PostureResource
	NativeCertificatesIssued      int
	KubernetesCSRsSigned          int
	TrustBundlesDistributed       int
	KubernetesCSRComplete         bool
	KubernetesCSRFailureCode      string
	KubernetesCSRPosture          []PostureResource
	TrustBundleComplete           bool
	TrustBundleFailureCode        string
	TrustBundlePosture            []PostureResource
}

// IssuerController is the trstctl Kubernetes CRD controller. It marks trstctl
// Issuer and ClusterIssuer resources Ready, signs cert-manager CertificateRequests,
// and fulfills trstctl-native Certificate resources into TLS Secrets. It
// intentionally follows the repository's dependency-free Kubernetes pattern:
// direct JSON/HTTPS API calls with the service-account token instead of
// client-go/controller-runtime.
type IssuerController struct {
	client    *Client
	signer    Signer
	group     string
	signerURL string
}

type issuerConfig struct {
	ttlCap time.Duration
}

func (config issuerConfig) limitTTL(requested time.Duration) time.Duration {
	if config.ttlCap > 0 && requested > config.ttlCap {
		return config.ttlCap
	}
	return requested
}

// NewIssuerController returns a controller for trstctl Issuer and ClusterIssuer
// resources in group. signerURL is the operator-configured, TLS-authenticated
// CA endpoint. A resource that names any other endpoint is never usable.
func NewIssuerController(client *Client, signer Signer, group, signerURL string) (*IssuerController, error) {
	if group == "" {
		group = DefaultIssuerGroup
	}
	parsed, err := url.Parse(signerURL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("k8s: issuer controller requires a configured HTTPS signer URL without credentials, query, or fragment")
	}
	return &IssuerController{client: client, signer: signer, group: group, signerURL: signerURL}, nil
}

func issuerCollectionPath(namespace string) string {
	if namespace == "" {
		return fmt.Sprintf("/apis/%s/%s", trstctlAPIVersion, issuersPlural)
	}
	return fmt.Sprintf("/apis/%s/namespaces/%s/%s", trstctlAPIVersion, namespace, issuersPlural)
}

func clusterIssuerCollectionPath() string {
	return fmt.Sprintf("/apis/%s/%s", trstctlAPIVersion, clusterPlural)
}

func nativeCertificateCollectionPath(namespace string) string {
	if namespace == "" {
		return fmt.Sprintf("/apis/%s/%s", trstctlAPIVersion, certificatesPlural)
	}
	return fmt.Sprintf("/apis/%s/namespaces/%s/%s", trstctlAPIVersion, namespace, certificatesPlural)
}

func trustBundleCollectionPath() string {
	return fmt.Sprintf("/apis/%s/%s", trstctlAPIVersion, trustBundlesPlural)
}

// Reconcile checks trstctl Issuer/ClusterIssuer configuration, signs approved
// cert-manager CertificateRequests in their own namespaces, issues trstctl-native
// Certificates into Secrets in their own namespaces, signs approved Kubernetes
// CertificateSigningRequests whose signerName maps to a trstctl issuer, and
// distributes cluster-scoped public trust bundles into namespace ConfigMaps.
func (c *IssuerController) Reconcile(ctx context.Context, namespace string) (IssuerReconcileResult, error) {
	var result IssuerReconcileResult

	clusterIssuers, err := c.reconcileIssuerResources(ctx, clusterIssuerCollectionPath(), "ClusterIssuer")
	if err != nil {
		return result, err
	}
	result.ClusterIssuersReady = len(clusterIssuers)

	issuers, err := c.reconcileIssuerResources(ctx, issuerCollectionPath(""), "Issuer")
	if err != nil {
		return result, err
	}
	result.IssuersReady = len(issuers)

	result.CertificateRequestFailureCode = "reconcile_failed"
	signed, requestPosture, err := c.reconcileCertificateRequests(ctx, issuers, clusterIssuers)
	result.CertificateRequestPosture = requestPosture
	if err != nil {
		return result, err
	}
	result.SignedRequests = signed
	result.CertificateRequestComplete = true
	result.CertificateRequestFailureCode = ""

	nativeIssued, err := c.reconcileNativeCertificates(ctx, issuers, clusterIssuers)
	if err != nil {
		return result, err
	}
	result.NativeCertificatesIssued = nativeIssued

	result.KubernetesCSRFailureCode = "reconcile_failed"
	kubernetesCSRs, csrPosture, err := c.reconcileKubernetesCSRs(ctx, issuers, clusterIssuers)
	result.KubernetesCSRPosture = csrPosture
	if err != nil {
		return result, err
	}
	result.KubernetesCSRsSigned = kubernetesCSRs
	result.KubernetesCSRComplete = true
	result.KubernetesCSRFailureCode = ""

	result.TrustBundleFailureCode = "reconcile_failed"
	bundles, bundlePosture, err := c.reconcileTrustBundles(ctx)
	result.TrustBundlePosture = bundlePosture
	if err != nil {
		return result, err
	}
	result.TrustBundlesDistributed = bundles
	result.TrustBundleComplete = true
	result.TrustBundleFailureCode = ""
	return result, nil
}

func (c *IssuerController) reconcileIssuerResources(ctx context.Context, collectionPath, kind string) (map[string]issuerConfig, error) {
	st, body, err := c.client.request(ctx, http.MethodGet, collectionPath, nil)
	if err != nil {
		return nil, err
	}
	if st/100 != 2 {
		return nil, fmt.Errorf("k8s: list trstctl %s resources: status %d: %s", kind, st, string(body))
	}
	var list struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("k8s: decode trstctl %s list: %w", kind, err)
	}
	out := make(map[string]issuerConfig, len(list.Items))
	for _, obj := range list.Items {
		name := objectName(obj)
		if name == "" {
			continue
		}
		statusCollectionPath := collectionPath
		key := name
		if kind == "Issuer" {
			namespace := objectNamespace(obj)
			if namespace == "" {
				continue
			}
			key = namespace + "/" + name
			statusCollectionPath = issuerCollectionPath(namespace)
		}
		config, reason := c.issuerConfig(obj)
		if reason == "" {
			out[key] = config
		}
		if (reason == "" && isReady(obj)) || (reason != "" && isIssuerNotReadyFor(obj, reason)) {
			continue
		}
		if err := c.markIssuerStatus(ctx, statusCollectionPath, kind, obj, reason); err != nil {
			return out, err
		}
	}
	return out, nil
}

func (c *IssuerController) markIssuerStatus(ctx context.Context, collectionPath, kind string, obj map[string]any, reason string) error {
	name := objectName(obj)
	status, _ := obj["status"].(map[string]any)
	if status == nil {
		status = map[string]any{}
	}
	status["conditions"] = upsertIssuerCondition(status["conditions"], kind, reason)
	obj["status"] = status

	st, body, err := c.client.request(ctx, http.MethodPut, collectionPath+"/"+name+"/status", obj)
	if err != nil {
		return err
	}
	if st/100 != 2 {
		return fmt.Errorf("k8s: update trstctl %s %s status: %d: %s", kind, name, st, string(body))
	}
	return nil
}

func (c *IssuerController) issuerConfig(obj map[string]any) (issuerConfig, string) {
	spec, _ := obj["spec"].(map[string]any)
	endpoint, _ := spec["signerURL"].(string)
	if endpoint != c.signerURL {
		return issuerConfig{}, "SignerURLMismatch"
	}
	if profile, _ := spec["profileName"].(string); strings.TrimSpace(profile) != "" {
		return issuerConfig{}, "UnsupportedProfile"
	}
	if caID, _ := spec["caAuthorityID"].(string); caID != "" && caID != caAuthorityIDFromSignerURL(c.signerURL) {
		return issuerConfig{}, "CAAuthorityMismatch"
	}
	var config issuerConfig
	if raw, exists := spec["ttlSeconds"]; exists {
		seconds, ok := raw.(float64)
		if !ok || seconds < 1 || seconds != math.Trunc(seconds) || seconds > float64(math.MaxInt64/int64(time.Second)) {
			return issuerConfig{}, "InvalidTTLSeconds"
		}
		config.ttlCap = time.Duration(int64(seconds)) * time.Second
	}
	return config, ""
}

func caAuthorityIDFromSignerURL(endpoint string) string {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return ""
	}
	parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	if len(parts) == 6 && parts[0] == "api" && parts[1] == "v1" && parts[2] == "ca" && parts[3] == "authorities" && parts[5] == "issue" {
		return parts[4]
	}
	return ""
}

func (c *IssuerController) reconcileCertificateRequests(ctx context.Context, issuers, clusterIssuers map[string]issuerConfig) (int, []PostureResource, error) {
	// ClusterIssuer is cluster-scoped: a CertificateRequest may live in any
	// namespace, including one other than the agent pod's namespace.
	st, body, err := c.client.request(ctx, http.MethodGet, "/apis/cert-manager.io/v1/certificaterequests", nil)
	if err != nil {
		return 0, nil, err
	}
	if st/100 != 2 {
		return 0, nil, fmt.Errorf("k8s: list certificaterequests: status %d: %s", st, string(body))
	}
	var list struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return 0, nil, fmt.Errorf("k8s: decode certificaterequest list: %w", err)
	}

	bridge := &Bridge{client: c.client, signer: c.signer, issuerGroup: c.group}
	signed := 0
	posture := make([]PostureResource, 0, len(list.Items))
	for _, cr := range list.Items {
		requestNamespace := objectNamespace(cr)
		if requestNamespace == "" {
			continue // refuse an object with no namespace instead of misrouting its status
		}
		config, backed := c.requestIssuerConfig(cr, issuers, clusterIssuers)
		current := certManagerRequestPosture(cr, backed, c.group)
		if isFinished(cr) || !isApproved(cr) || !backed {
			if current.Name != "" {
				posture = append(posture, current)
			}
			continue
		}
		updated, err := bridge.fulfilWithCapResult(ctx, requestNamespace, cr, config.ttlCap)
		if err != nil {
			posture = append(posture, failedPosture(current))
			return signed, posture, err
		}
		posture = append(posture, certManagerRequestPosture(updated, true, c.group))
		signed++
	}
	return signed, posture, nil
}

func (c *IssuerController) requestIssuerConfig(cr map[string]any, issuers, clusterIssuers map[string]issuerConfig) (issuerConfig, bool) {
	spec, _ := cr["spec"].(map[string]any)
	ref, _ := spec["issuerRef"].(map[string]any)
	if ref == nil {
		return issuerConfig{}, false
	}
	name, _ := ref["name"].(string)
	group, _ := ref["group"].(string)
	kind, _ := ref["kind"].(string)
	if name == "" || group != c.group {
		return issuerConfig{}, false
	}
	switch kind {
	case "", "Issuer":
		config, ok := issuers[objectNamespace(cr)+"/"+name]
		return config, ok
	case "ClusterIssuer":
		config, ok := clusterIssuers[name]
		return config, ok
	default:
		return issuerConfig{}, false
	}
}

func objectName(obj map[string]any) string {
	meta, _ := obj["metadata"].(map[string]any)
	name, _ := meta["name"].(string)
	return name
}

func objectNamespace(obj map[string]any) string {
	meta, _ := obj["metadata"].(map[string]any)
	namespace, _ := meta["namespace"].(string)
	return namespace
}

func isReady(obj map[string]any) bool {
	status, _ := obj["status"].(map[string]any)
	conds, _ := status["conditions"].([]any)
	for _, c := range conds {
		m, _ := c.(map[string]any)
		if m["type"] == "Ready" && m["status"] == "True" {
			return true
		}
	}
	return false
}

func isIssuerNotReadyFor(obj map[string]any, reason string) bool {
	status, _ := obj["status"].(map[string]any)
	conds, _ := status["conditions"].([]any)
	for _, condition := range conds {
		item, _ := condition.(map[string]any)
		if item["type"] == "Ready" && item["status"] == "False" && item["reason"] == reason {
			return true
		}
	}
	return false
}

func upsertIssuerCondition(existing any, kind, reason string) []any {
	ready := map[string]any{
		"type":    "Ready",
		"status":  "True",
		"reason":  "Ready",
		"message": "trstctl " + kind + " is ready to sign cert-manager CertificateRequests",
	}
	if reason != "" {
		ready["status"] = "False"
		ready["reason"] = reason
		messages := map[string]string{
			"SignerURLMismatch":   "signerURL differs from the operator-configured issuance endpoint",
			"UnsupportedProfile":  "profileName is unsupported by this CA issuance endpoint",
			"CAAuthorityMismatch": "caAuthorityID differs from the authority in signerURL",
			"InvalidTTLSeconds":   "ttlSeconds must be a positive whole number within the supported lifetime range",
		}
		ready["message"] = "trstctl " + kind + " cannot sign: " + messages[reason]
	}
	conds, _ := existing.([]any)
	for i, c := range conds {
		if m, ok := c.(map[string]any); ok && m["type"] == "Ready" {
			conds[i] = ready
			return conds
		}
	}
	return append(conds, ready)
}
