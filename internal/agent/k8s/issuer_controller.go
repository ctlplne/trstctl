package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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
	ClusterIssuersReady      int
	IssuersReady             int
	SignedRequests           int
	NativeCertificatesIssued int
	KubernetesCSRsSigned     int
	TrustBundlesDistributed  int
}

// IssuerController is the trstctl Kubernetes CRD controller. It marks trstctl
// Issuer and ClusterIssuer resources Ready, signs cert-manager CertificateRequests,
// and fulfils trstctl-native Certificate resources into TLS Secrets. It
// intentionally follows the repository's dependency-free Kubernetes pattern:
// direct JSON/HTTPS API calls with the service-account token instead of
// client-go/controller-runtime.
type IssuerController struct {
	client *Client
	signer Signer
	group  string
}

// NewIssuerController returns a controller for trstctl Issuer and ClusterIssuer
// resources in group. Empty group defaults to trstctl.com.
func NewIssuerController(client *Client, signer Signer, group string) *IssuerController {
	if group == "" {
		group = DefaultIssuerGroup
	}
	return &IssuerController{client: client, signer: signer, group: group}
}

func issuerCollectionPath(namespace string) string {
	return fmt.Sprintf("/apis/%s/namespaces/%s/%s", trstctlAPIVersion, namespace, issuersPlural)
}

func clusterIssuerCollectionPath() string {
	return fmt.Sprintf("/apis/%s/%s", trstctlAPIVersion, clusterPlural)
}

func nativeCertificateCollectionPath(namespace string) string {
	return fmt.Sprintf("/apis/%s/namespaces/%s/%s", trstctlAPIVersion, namespace, certificatesPlural)
}

func trustBundleCollectionPath() string {
	return fmt.Sprintf("/apis/%s/%s", trstctlAPIVersion, trustBundlesPlural)
}

// Reconcile makes trstctl Issuer/ClusterIssuer resources Ready, signs every
// pending cert-manager CertificateRequest in namespace whose issuerRef points at
// one of those resources, issues every pending trstctl-native Certificate in
// namespace into its requested TLS Secret, signs approved native Kubernetes
// CertificateSigningRequests whose signerName maps to a trstctl issuer, and
// distributes cluster-scoped public trust bundles into namespace ConfigMaps.
func (c *IssuerController) Reconcile(ctx context.Context, namespace string) (IssuerReconcileResult, error) {
	var result IssuerReconcileResult

	clusterIssuers, err := c.reconcileIssuerResources(ctx, clusterIssuerCollectionPath(), "ClusterIssuer")
	if err != nil {
		return result, err
	}
	result.ClusterIssuersReady = len(clusterIssuers)

	issuers, err := c.reconcileIssuerResources(ctx, issuerCollectionPath(namespace), "Issuer")
	if err != nil {
		return result, err
	}
	result.IssuersReady = len(issuers)

	signed, err := c.reconcileCertificateRequests(ctx, namespace, issuers, clusterIssuers)
	if err != nil {
		return result, err
	}
	result.SignedRequests = signed

	nativeIssued, err := c.reconcileNativeCertificates(ctx, namespace, issuers, clusterIssuers)
	if err != nil {
		return result, err
	}
	result.NativeCertificatesIssued = nativeIssued

	kubernetesCSRs, err := c.reconcileKubernetesCSRs(ctx, issuers, clusterIssuers)
	if err != nil {
		return result, err
	}
	result.KubernetesCSRsSigned = kubernetesCSRs

	bundles, err := c.reconcileTrustBundles(ctx)
	if err != nil {
		return result, err
	}
	result.TrustBundlesDistributed = bundles
	return result, nil
}

func (c *IssuerController) reconcileIssuerResources(ctx context.Context, collectionPath, kind string) (map[string]bool, error) {
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
	out := make(map[string]bool, len(list.Items))
	for _, obj := range list.Items {
		name := objectName(obj)
		if name == "" {
			continue
		}
		out[name] = true
		if isReady(obj) {
			continue
		}
		if err := c.markIssuerReady(ctx, collectionPath, kind, obj); err != nil {
			return out, err
		}
	}
	return out, nil
}

func (c *IssuerController) markIssuerReady(ctx context.Context, collectionPath, kind string, obj map[string]any) error {
	name := objectName(obj)
	status, _ := obj["status"].(map[string]any)
	if status == nil {
		status = map[string]any{}
	}
	status["conditions"] = upsertIssuerReady(status["conditions"], kind)
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

func (c *IssuerController) reconcileCertificateRequests(ctx context.Context, namespace string, issuers, clusterIssuers map[string]bool) (int, error) {
	st, body, err := c.client.request(ctx, http.MethodGet, certificateRequestsPath(namespace), nil)
	if err != nil {
		return 0, err
	}
	if st/100 != 2 {
		return 0, fmt.Errorf("k8s: list certificaterequests: status %d: %s", st, string(body))
	}
	var list struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return 0, fmt.Errorf("k8s: decode certificaterequest list: %w", err)
	}

	bridge := &Bridge{client: c.client, signer: c.signer, issuerGroup: c.group}
	signed := 0
	for _, cr := range list.Items {
		if isFinished(cr) || !c.requestBackedByIssuer(cr, issuers, clusterIssuers) {
			continue
		}
		if err := bridge.fulfil(ctx, namespace, cr); err != nil {
			return signed, err
		}
		signed++
	}
	return signed, nil
}

func (c *IssuerController) requestBackedByIssuer(cr map[string]any, issuers, clusterIssuers map[string]bool) bool {
	spec, _ := cr["spec"].(map[string]any)
	ref, _ := spec["issuerRef"].(map[string]any)
	if ref == nil {
		return false
	}
	name, _ := ref["name"].(string)
	group, _ := ref["group"].(string)
	kind, _ := ref["kind"].(string)
	if name == "" || group != c.group {
		return false
	}
	switch kind {
	case "", "Issuer":
		return issuers[name]
	case "ClusterIssuer":
		return clusterIssuers[name]
	default:
		return false
	}
}

func objectName(obj map[string]any) string {
	meta, _ := obj["metadata"].(map[string]any)
	name, _ := meta["name"].(string)
	return name
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

func upsertIssuerReady(existing any, kind string) []any {
	ready := map[string]any{
		"type":    "Ready",
		"status":  "True",
		"reason":  "Ready",
		"message": "trstctl " + kind + " is ready to sign cert-manager CertificateRequests",
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
