// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

// M4 against a real Kubernetes API server: a pod's service-account token —
// minted by the API server bound to the pod, exactly as kubelet projects it —
// is exchanged for a five-minute JWT-SVID, and the same token again is
// refused. trstctl trusts the cluster through its own OIDC discovery document
// and JWKS. Run by runners/m4-kind-lab-proof.sh (TRSTCTL_M4_LAB_KUBECONFIG);
// skipped otherwise.
func TestTokenExchangeWithAKubernetesPodTokenM4(t *testing.T) {
	kubeconfig := os.Getenv("TRSTCTL_M4_LAB_KUBECONFIG")
	if kubeconfig == "" {
		t.Skip("run runners/m4-kind-lab-proof.sh (a kind cluster)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	kubectl := func(stdin string, args ...string) []byte {
		t.Helper()
		cmd := exec.CommandContext(ctx, "kubectl", append([]string{"--kubeconfig", kubeconfig}, args...)...) // #nosec G204 G702 -- the runner's own lab cluster (CWE-78)
		if stdin != "" {
			cmd.Stdin = strings.NewReader(stdin)
		}
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("kubectl %v: %v", args, err)
		}
		return out
	}
	var discovery struct {
		Issuer string `json:"issuer"`
	}
	if err := json.Unmarshal(kubectl("", "get", "--raw", "/.well-known/openid-configuration"), &discovery); err != nil || discovery.Issuer == "" {
		t.Fatalf("cluster OIDC discovery: %v", err)
	}
	jwks := kubectl("", "get", "--raw", "/openid/v1/jwks")
	kubectl(`apiVersion: v1
kind: Namespace
metadata: {name: m4-payments}
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: api, namespace: m4-payments}
---
apiVersion: v1
kind: Pod
metadata: {name: m4-api, namespace: m4-payments}
spec:
  serviceAccountName: api
  containers:
  - {name: pause, image: "registry.k8s.io/pause:3.10", imagePullPolicy: Never}
`, "apply", "-f", "-")
	t.Cleanup(func() {
		_ = exec.Command("kubectl", "--kubeconfig", kubeconfig, "delete", "namespace", "m4-payments", "--wait=false").Run() // #nosec G204 G702 -- the runner's own lab cluster (CWE-78)
	})
	podToken := strings.TrimSpace(string(kubectl("", "-n", "m4-payments", "create", "token", "api",
		"--audience", "trstctl", "--duration", "10m", "--bound-object-kind", "Pod", "--bound-object-name", "m4-api")))

	methods, err := machineAuthMethodsFromConfig([]config.MachineAuthMethod{{
		Name: "kubernetes", TenantID: servedTestTenant, Issuer: discovery.Issuer, Audience: "trstctl",
		JWKSJSON: string(jwks), AllowedNamespaces: []string{"m4-payments"}, Scopes: []string{"secrets:read"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	h := newOperatingServedHarness(t, config.Protocols{SPIFFE: config.SPIFFEProtocol{
		Enabled: true, TenantID: servedTestTenant, TrustDomain: "lab.test", SocketPath: filepath.Join(t.TempDir(), "cp.sock"),
	}}, func(d *Deps) {
		d.MachineAuthMethods = withMachineCredentialReplayGuard(methods, d.Store)
	})
	exchange := func() (int, map[string]any) {
		t.Helper()
		form := url.Values{"grant_type": {tokenExchangeGrant}, "subject_token": {podToken},
			"subject_token_type": {tokenTypeJWT}, "audience": {"https://payments.lab.test"}}
		req, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/oauth2/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Tenant-ID", h.tenant)
		resp, err := h.ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	status, out := exchange()
	if status != http.StatusOK || out["expires_in"] != float64(300) {
		t.Fatalf("exchange of the pod's token: HTTP %d %v", status, out)
	}
	var published crypto.JWKS
	resp, err := h.ts.Client().Get(h.ts.URL + "/oauth2/jwks")
	if err != nil {
		t.Fatal(err)
	}
	_ = json.NewDecoder(resp.Body).Decode(&published)
	_ = resp.Body.Close()
	raw, err := crypto.VerifyJWTBytes([]byte(out["access_token"].(string)), published)
	if err != nil {
		t.Fatalf("the JWT-SVID does not verify: %v", err)
	}
	var claims struct {
		Sub string `json:"sub"`
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
	}
	if json.Unmarshal(raw, &claims) != nil || claims.Sub != "spiffe://lab.test/ns/m4-payments/sa/api" || claims.Exp-claims.Iat != 300 {
		t.Fatalf("JWT-SVID claims = %+v", claims)
	}
	if status, out := exchange(); status != http.StatusBadRequest || out["error"] != "invalid_grant" {
		t.Fatalf("replaying the pod's token: HTTP %d %v", status, out)
	}
	t.Logf("M4_KIND_OK issuer=%s sub=%s", discovery.Issuer, claims.Sub)
}
