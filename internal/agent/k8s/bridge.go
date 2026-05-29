package k8s

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
)

// Signer signs a CSR (DER) and returns the issued certificate chain (PEM). The
// cert-manager bridge uses it to fulfil CertificateRequests; in production it is
// backed by the control plane's issuance, and in tests by the crypto boundary's
// CA.
type Signer interface {
	Sign(ctx context.Context, csrDER []byte) (chainPEM []byte, err error)
}

// SignerFunc adapts a function to the Signer interface.
type SignerFunc func(ctx context.Context, csrDER []byte) ([]byte, error)

// Sign calls f.
func (f SignerFunc) Sign(ctx context.Context, csrDER []byte) ([]byte, error) { return f(ctx, csrDER) }

// Bridge is a cert-manager external issuer: it signs CertificateRequests that
// name certctl as their issuer and writes the issued certificate back to each
// request's status.
type Bridge struct {
	client      *Client
	signer      Signer
	issuerName  string
	issuerGroup string
}

// NewBridge returns a bridge that fulfils CertificateRequests whose issuerRef
// names issuerName in issuerGroup, signing them with signer.
func NewBridge(client *Client, signer Signer, issuerName, issuerGroup string) *Bridge {
	return &Bridge{client: client, signer: signer, issuerName: issuerName, issuerGroup: issuerGroup}
}

func certificateRequestsPath(namespace string) string {
	return fmt.Sprintf("/apis/cert-manager.io/v1/namespaces/%s/certificaterequests", namespace)
}

// Reconcile signs every pending CertificateRequest in namespace that names our
// issuer and is not already finished, returning how many it signed.
func (b *Bridge) Reconcile(ctx context.Context, namespace string) (int, error) {
	st, body, err := b.client.request(ctx, http.MethodGet, certificateRequestsPath(namespace), nil)
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

	signed := 0
	for _, cr := range list.Items {
		if !b.isOurs(cr) || isFinished(cr) {
			continue
		}
		if err := b.fulfil(ctx, namespace, cr); err != nil {
			return signed, err
		}
		signed++
	}
	return signed, nil
}

func (b *Bridge) isOurs(cr map[string]any) bool {
	spec, _ := cr["spec"].(map[string]any)
	ref, _ := spec["issuerRef"].(map[string]any)
	if ref == nil {
		return false
	}
	name, _ := ref["name"].(string)
	group, _ := ref["group"].(string)
	if b.issuerGroup != "" && group != b.issuerGroup {
		return false
	}
	return name == b.issuerName
}

// isFinished reports whether a request already carries a true Ready or Denied
// condition, so the bridge does not sign it twice.
func isFinished(cr map[string]any) bool {
	status, _ := cr["status"].(map[string]any)
	conds, _ := status["conditions"].([]any)
	for _, c := range conds {
		m, _ := c.(map[string]any)
		t, _ := m["type"].(string)
		s, _ := m["status"].(string)
		if (t == "Ready" || t == "Denied") && s == "True" {
			return true
		}
	}
	return false
}

func (b *Bridge) fulfil(ctx context.Context, namespace string, cr map[string]any) error {
	spec, _ := cr["spec"].(map[string]any)
	reqB64, _ := spec["request"].(string)
	pemCSR, err := base64.StdEncoding.DecodeString(reqB64)
	if err != nil {
		return fmt.Errorf("k8s: decode CertificateRequest.spec.request: %w", err)
	}
	block, _ := pem.Decode(pemCSR)
	if block == nil {
		return fmt.Errorf("k8s: CertificateRequest.spec.request is not a PEM CSR")
	}
	chainPEM, err := b.signer.Sign(ctx, block.Bytes)
	if err != nil {
		return fmt.Errorf("k8s: sign CertificateRequest: %w", err)
	}

	meta, _ := cr["metadata"].(map[string]any)
	name, _ := meta["name"].(string)
	cr["status"] = map[string]any{
		"certificate": string(chainPEM),
		"conditions": []any{
			map[string]any{
				"type":    "Ready",
				"status":  "True",
				"reason":  "Issued",
				"message": "certctl signed the request",
			},
		},
	}
	st, rb, err := b.client.request(ctx, http.MethodPut, certificateRequestsPath(namespace)+"/"+name+"/status", cr)
	if err != nil {
		return err
	}
	if st/100 != 2 {
		return fmt.Errorf("k8s: update CertificateRequest %s/%s status: %d: %s", namespace, name, st, string(rb))
	}
	return nil
}
