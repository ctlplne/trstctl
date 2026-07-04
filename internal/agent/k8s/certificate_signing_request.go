// SPDX-License-Identifier: MPL-2.0

package k8s

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
)

const (
	kubernetesCSRAPIVersion = "certificates.k8s.io/v1"

	kubernetesCSRAnnotationIssuerName  = "trstctl.com/issuer-name"
	kubernetesCSRAnnotationIssuerKind  = "trstctl.com/issuer-kind"
	kubernetesCSRAnnotationIssuerGroup = "trstctl.com/issuer-group"
)

func certificateSigningRequestsPath() string {
	return "/apis/" + kubernetesCSRAPIVersion + "/certificatesigningrequests"
}

func (c *IssuerController) reconcileKubernetesCSRs(ctx context.Context, issuers, clusterIssuers map[string]bool) (int, error) {
	st, body, err := c.client.request(ctx, http.MethodGet, certificateSigningRequestsPath(), nil)
	if err != nil {
		return 0, err
	}
	if st/100 != 2 {
		return 0, fmt.Errorf("k8s: list certificatesigningrequests: status %d: %s", st, string(body))
	}
	var list struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return 0, fmt.Errorf("k8s: decode certificatesigningrequest list: %w", err)
	}

	signed := 0
	for _, csr := range list.Items {
		if isKubernetesCSRFinished(csr) || !isKubernetesCSRApproved(csr) || !c.csrBackedByIssuer(csr, issuers, clusterIssuers) {
			continue
		}
		if err := c.signKubernetesCSR(ctx, csr); err != nil {
			return signed, err
		}
		signed++
	}
	return signed, nil
}

func (c *IssuerController) csrBackedByIssuer(csr map[string]any, issuers, clusterIssuers map[string]bool) bool {
	spec, _ := csr["spec"].(map[string]any)
	signerName, _ := spec["signerName"].(string)
	issuerName := signerNameIssuer(signerName, c.group)
	if issuerName == "" {
		return false
	}

	meta, _ := csr["metadata"].(map[string]any)
	annotations, _ := meta["annotations"].(map[string]any)
	if annotations != nil {
		annotatedGroup, _ := annotations[kubernetesCSRAnnotationIssuerGroup].(string)
		if annotatedGroup != "" && annotatedGroup != c.group {
			return false
		}
		annotatedName, _ := annotations[kubernetesCSRAnnotationIssuerName].(string)
		if annotatedName != "" {
			issuerName = annotatedName
		}
		kind, _ := annotations[kubernetesCSRAnnotationIssuerKind].(string)
		switch kind {
		case "", "ClusterIssuer":
			return clusterIssuers[issuerName]
		case "Issuer":
			return issuers[issuerName]
		default:
			return false
		}
	}

	return clusterIssuers[issuerName] || issuers[issuerName]
}

func signerNameIssuer(signerName, group string) string {
	prefix := group + "/"
	if group == "" {
		prefix = DefaultIssuerGroup + "/"
	}
	if !strings.HasPrefix(signerName, prefix) {
		return ""
	}
	name := strings.Trim(strings.TrimPrefix(signerName, prefix), "/")
	if name == "" {
		return ""
	}
	if strings.Contains(name, "/") {
		parts := strings.Split(name, "/")
		name = parts[len(parts)-1]
	}
	return name
}

func (c *IssuerController) signKubernetesCSR(ctx context.Context, csr map[string]any) error {
	spec, _ := csr["spec"].(map[string]any)
	reqB64, _ := spec["request"].(string)
	csrDER, err := decodeKubernetesCSRRequest(reqB64)
	if err != nil {
		return err
	}
	chainPEM, err := c.signer.Sign(ctx, csrDER)
	if err != nil {
		return fmt.Errorf("k8s: sign CertificateSigningRequest: %w", err)
	}
	if strings.TrimSpace(string(chainPEM)) == "" {
		return fmt.Errorf("k8s: sign CertificateSigningRequest: empty certificate chain")
	}

	meta, _ := csr["metadata"].(map[string]any)
	name, _ := meta["name"].(string)
	status, _ := csr["status"].(map[string]any)
	if status == nil {
		status = map[string]any{}
	}
	status["certificate"] = base64.StdEncoding.EncodeToString(chainPEM)
	status["conditions"] = upsertReady(status["conditions"])
	csr["status"] = status

	st, body, err := c.client.request(ctx, http.MethodPut, certificateSigningRequestsPath()+"/"+name+"/status", csr)
	if err != nil {
		return err
	}
	if st/100 != 2 {
		return fmt.Errorf("k8s: update CertificateSigningRequest %s status: %d: %s", name, st, string(body))
	}
	return nil
}

func decodeKubernetesCSRRequest(reqB64 string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(reqB64)
	if err != nil {
		return nil, fmt.Errorf("k8s: decode CertificateSigningRequest.spec.request: %w", err)
	}
	if block, _ := pem.Decode(raw); block != nil {
		if block.Type != "CERTIFICATE REQUEST" {
			return nil, fmt.Errorf("k8s: CertificateSigningRequest.spec.request is not a certificate request")
		}
		return block.Bytes, nil
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("k8s: CertificateSigningRequest.spec.request is empty")
	}
	return raw, nil
}

func isKubernetesCSRApproved(csr map[string]any) bool {
	return kubernetesCSRConditionStatus(csr, "Approved") == "True"
}

func isKubernetesCSRFinished(csr map[string]any) bool {
	status, _ := csr["status"].(map[string]any)
	if cert, _ := status["certificate"].(string); strings.TrimSpace(cert) != "" {
		return true
	}
	for _, conditionType := range []string{"Ready", "Denied", "Failed"} {
		if kubernetesCSRConditionStatus(csr, conditionType) == "True" {
			return true
		}
	}
	return false
}

func kubernetesCSRConditionStatus(csr map[string]any, conditionType string) string {
	status, _ := csr["status"].(map[string]any)
	conds, _ := status["conditions"].([]any)
	for _, raw := range conds {
		cond, _ := raw.(map[string]any)
		if cond["type"] == conditionType {
			out, _ := cond["status"].(string)
			return out
		}
	}
	return ""
}
