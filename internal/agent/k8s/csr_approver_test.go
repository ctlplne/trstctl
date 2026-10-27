// SPDX-License-Identifier: BUSL-1.1

package k8s_test

import (
	"context"
	"encoding/base64"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/k8s"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// A195: with the approver on, a pending CSR addressed to a trstctl signer is
// decided by the issuing CA. One inside its profile is approved, with the
// reason naming trstctl, and signed in the same pass; one outside is denied
// with the CA's reason and never signed. Without the approver nothing is
// approved, as before: a Kubernetes approver decides.
func TestIssuerControllerApprovesOrDeniesPendingCSRsByTheCAsDecision(t *testing.T) {
	signer, _ := caSigner(t)
	requestFor := func(cn string) string {
		t.Helper()
		id, err := mtls.GenerateAgentKey(cn)
		if err != nil {
			t.Fatal(err)
		}
		der, err := id.CSR()
		if err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(der)
	}
	pending := func(name, cn string) map[string]any {
		csr := kubernetesCSR(name, "trstctl.com/trstctl", false)
		csr["spec"].(map[string]any)["request"] = requestFor(cn)
		return csr
	}
	var asked []time.Duration
	approver := k8s.ApproverFunc(func(_ context.Context, csrDER []byte, ttl time.Duration) (k8s.ApprovalDecision, error) {
		asked = append(asked, ttl)
		cn, err := mtls.CSRCommonName(csrDER)
		if err != nil {
			return k8s.ApprovalDecision{}, err
		}
		if strings.HasSuffix(cn, ".apps.example.test") {
			return k8s.ApprovalDecision{Allowed: true}, nil
		}
		return k8s.ApprovalDecision{Reason: `leaf profile violation: DNS SAN "` + cn + `" is outside the permitted DNS suffixes [apps.example.test]`}, nil
	})

	api := newFakeIssuerAPI()
	api.clusterIssuers = []map[string]any{trstctlClusterIssuer("trstctl")}
	api.kubernetesCSRs = []map[string]any{pending("inside", "web.apps.example.test"), pending("outside", "web.other.example.net")}
	server := httptestServer(t, api)
	controller := testIssuerController(t, k8s.New(server.URL, "tok", "apps", server.Client()), signer, "trstctl.com").WithCSRApprover(approver)
	result, err := controller.Reconcile(context.Background(), "apps")
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(asked) != 2 || asked[0] != 24*time.Hour {
		t.Fatalf("the CA was asked %v; want both requests at the default 24h", asked)
	}
	approval := func(name string) (string, string, string) {
		obj := api.kubernetesCSRApproval[name]
		if obj == nil {
			return "", "", ""
		}
		conditions, _ := obj["status"].(map[string]any)["conditions"].([]any)
		last, _ := conditions[len(conditions)-1].(map[string]any)
		kind, _ := last["type"].(string)
		reason, _ := last["reason"].(string)
		message, _ := last["message"].(string)
		return kind, reason, message
	}
	if kind, reason, _ := approval("inside"); kind != "Approved" || reason != "TrstctlProfilePolicy" {
		t.Fatalf("inside approval = %s %s", kind, reason)
	}
	if result.KubernetesCSRsSigned != 1 || api.kubernetesCSRStatus["inside"] == nil || api.kubernetesCSRStatus["outside"] != nil {
		t.Fatalf("signed %d; statuses %v; want the approved request signed in the same pass and nothing else", result.KubernetesCSRsSigned, api.kubernetesCSRStatus)
	}
	if kind, reason, message := approval("outside"); kind != "Denied" || reason != "TrstctlProfilePolicy" || !strings.Contains(message, "outside the permitted DNS suffixes") {
		t.Fatalf("outside decision = %s %s %q; want Denied with the CA's reason", kind, reason, message)
	}

	plain := newFakeIssuerAPI()
	plain.clusterIssuers = []map[string]any{trstctlClusterIssuer("trstctl")}
	plain.kubernetesCSRs = []map[string]any{pending("waiting", "web.apps.example.test")}
	plainServer := httptestServer(t, plain)
	unchanged := testIssuerController(t, k8s.New(plainServer.URL, "tok", "apps", plainServer.Client()), signer, "trstctl.com")
	if result, err := unchanged.Reconcile(context.Background(), "apps"); err != nil || result.KubernetesCSRsSigned != 0 ||
		len(plain.kubernetesCSRApproval) != 0 {
		t.Fatalf("without the approver: %v signed %d approvals %v; want a Kubernetes approver to decide", err, result.KubernetesCSRsSigned, plain.kubernetesCSRApproval)
	}
}

func httptestServer(t *testing.T, api *fakeIssuerAPI) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(api.handler())
	t.Cleanup(server.Close)
	return server
}
