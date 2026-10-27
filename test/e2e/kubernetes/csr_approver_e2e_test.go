// SPDX-License-Identifier: BUSL-1.1

//go:build e2e

package kubernetes_e2e

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/k8s"
	"trstctl.com/trstctl/internal/crypto"
)

// TestCSRApproverDecidesPendingRequestsByTheIssuingCA (A195): with the opt-in
// approver, the agent's own least-privilege identity decides pending native
// CSRs for a trstctl signer by the issuing CA's profile. Without the shipped
// approver grant Kubernetes refuses the decision and the requests stay
// pending; with it, a request the profile allows is approved under the
// trstctl reason and signed, and one it refuses is denied with the profile's
// reason and never signed.
func TestCSRApproverDecidesPendingRequestsByTheIssuingCA(t *testing.T) {
	requireIndependentApprover(t)
	client, _, ns := cluster(t)
	k := newKubeAPI(t)
	applyCRDFile(k, filepath.Join("..", "..", "..", "deploy", "kubernetes", "certmanager-issuer-crds.yaml"))

	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(caKey.Destroy)
	caDER, err := crypto.SelfSignedCACert(caKey, "trstctl approver e2e CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	profile := crypto.LeafProfile{PermittedDNSSuffixes: []string{ns + ".svc"}, MaxValidity: 2 * time.Hour}
	signerURL := "https://trstctl.trstctl.svc/api/v1/ca/authorities/e2e/issue"
	controller, err := k8s.NewIssuerController(client, k8s.SignerFunc(func(_ context.Context, csrDER []byte, ttl time.Duration) ([]byte, error) {
		der, err := crypto.SignLeafFromCSRWithProfile(caDER, caKey, csrDER, ttl, profile)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
	}), "trstctl.com", signerURL)
	if err != nil {
		t.Fatal(err)
	}
	// The CA's answer, as the control plane's evaluate route gives it: the
	// checks issuance makes, without signing.
	controller.WithCSRApprover(k8s.ApproverFunc(func(_ context.Context, csrDER []byte, ttl time.Duration) (k8s.ApprovalDecision, error) {
		if _, err := crypto.EvaluateLeafRequest(caDER, csrDER, ttl, profile); err != nil {
			if crypto.IsLeafProfileViolation(err) {
				return k8s.ApprovalDecision{Reason: err.Error()}, nil
			}
			return k8s.ApprovalDecision{}, err
		}
		return k8s.ApprovalDecision{Allowed: true}, nil
	}))

	clusterIssuers := "/apis/trstctl.com/v1alpha1/clusterissuers/"
	if st, _ := k.do(http.MethodGet, clusterIssuers+"trstctl", "", nil); st == http.StatusNotFound {
		k.must(http.MethodPost, "/apis/trstctl.com/v1alpha1/clusterissuers", "", map[string]any{
			"apiVersion": "trstctl.com/v1alpha1", "kind": "ClusterIssuer",
			"metadata": map[string]any{"name": "trstctl"}, "spec": map[string]any{"signerURL": signerURL},
		})
		t.Cleanup(func() { k.do(http.MethodDelete, clusterIssuers+"trstctl", "", nil) })
	}

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	request := func(name, dnsName string) string {
		t.Helper()
		key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(key.Destroy)
		der, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: dnsName, DNSNames: []string{dnsName}}, key)
		if err != nil {
			t.Fatal(err)
		}
		path := "/apis/certificates.k8s.io/v1/certificatesigningrequests/" + name
		k.must(http.MethodPost, "/apis/certificates.k8s.io/v1/certificatesigningrequests", "", map[string]any{
			"apiVersion": "certificates.k8s.io/v1", "kind": "CertificateSigningRequest", "metadata": map[string]any{"name": name},
			"spec": map[string]any{
				"request":    base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})),
				"signerName": "trstctl.com/trstctl", "usages": []any{"digital signature", "client auth"},
				"expirationSeconds": 3600,
			},
		})
		t.Cleanup(func() { k.do(http.MethodDelete, path, "", nil) })
		return path
	}
	inside := request("trstctl-approve-in-"+suffix, "approve-"+suffix+"."+ns+".svc")
	outside := request("trstctl-approve-out-"+suffix, "approve-"+suffix+".example.net")
	decision := func(path string) (kind, reason, message string) {
		conditions, _ := at(k.get(path), "status", "conditions").([]any)
		for _, condition := range conditions {
			if kind, _ := at(condition, "type").(string); kind == "Approved" || kind == "Denied" {
				reason, _ = at(condition, "reason").(string)
				message, _ = at(condition, "message").(string)
				return kind, reason, message
			}
		}
		return "", "", ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// The grant is opt-in: until it is applied, Kubernetes refuses the
	// agent's decision and nothing is decided.
	grantPath := "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/trstctl-agent-csr-approver"
	if st, _ := k.do(http.MethodGet, grantPath, "", nil); st == http.StatusNotFound {
		if _, err := controller.Reconcile(ctx, ns); err == nil || !strings.Contains(err.Error(), "403") {
			t.Fatalf("reconcile without the approver grant = %v; want Kubernetes to refuse the approval", err)
		}
		if kind, _, _ := decision(inside); kind != "" {
			t.Fatalf("a request was %s without the approver grant", kind)
		}
	}
	applyClusterRBAC(k, filepath.Join("..", "..", "..", "deploy", "kubernetes", "rbac-csr-approver.yaml"))

	// RBAC reaches the authorizer within moments; retry until it has.
	waitUntil(t, "the agent decided both requests and signed the approved one", 60*time.Second, func() bool {
		if _, err := controller.Reconcile(ctx, ns); err != nil {
			t.Logf("reconcile: %v", err)
		}
		in, _, _ := decision(inside)
		out, _, _ := decision(outside)
		return in != "" && out != "" && at(k.get(inside), "status", "certificate") != nil
	})
	if kind, reason, _ := decision(inside); kind != "Approved" || reason != "TrstctlProfilePolicy" {
		t.Fatalf("in-profile request = %s (%s); want Approved by TrstctlProfilePolicy", kind, reason)
	}
	issued, _ := at(k.get(inside), "status", "certificate").(string)
	chain, err := base64.StdEncoding.DecodeString(issued)
	if block, _ := pem.Decode(chain); err != nil || block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("the approved request carries no PEM certificate: %q", issued)
	}
	kind, reason, message := decision(outside)
	if kind != "Denied" || reason != "TrstctlProfilePolicy" || !strings.Contains(message, "permitted DNS suffixes") {
		t.Fatalf("out-of-profile request = %s (%s): %s; want Denied with the profile's reason", kind, reason, message)
	}
	if _, err := controller.Reconcile(ctx, ns); err != nil {
		t.Fatalf("reconcile after the decisions: %v", err)
	}
	if at(k.get(outside), "status", "certificate") != nil {
		t.Fatal("a denied request was signed")
	}
}

// applyClusterRBAC creates or replaces every ClusterRole and ClusterRoleBinding
// in path, and removes at cleanup the ones it created.
func applyClusterRBAC(k kubeAPI, path string) {
	k.t.Helper()
	for _, doc := range manifestDocuments(k.t, path) {
		var collection string
		switch doc["kind"] {
		case "ClusterRole":
			collection = "/apis/rbac.authorization.k8s.io/v1/clusterroles"
		case "ClusterRoleBinding":
			collection = "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"
		default:
			continue
		}
		name, _ := at(doc, "metadata", "name").(string)
		st, existing := k.do(http.MethodGet, collection+"/"+name, "", nil)
		if st == http.StatusNotFound {
			k.must(http.MethodPost, collection, "", doc)
			k.t.Cleanup(func() { k.do(http.MethodDelete, collection+"/"+name, "", nil) })
			continue
		}
		doc["metadata"].(map[string]any)["resourceVersion"] = at(existing, "metadata", "resourceVersion")
		k.must(http.MethodPut, collection+"/"+name, "", doc)
	}
}
