// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
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
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// A238 against a real cluster: the shipped CSI secrets driver
// (deploy/kubernetes/csi-secrets.yaml, image TRSTCTL_A238_CSI_IMAGE) serves a
// secret from a restricted environment to a pod as an inline volume. The pod's
// own service-account token logs in; the files sit in a tmpfs with the pod's
// fsGroup and no Secret object exists; a new version reaches the running pod
// and is reported injected; a pod whose identity may not read the secret gets
// no volume; through a control-plane outage the file serves until its
// freshness bound, then goes, and returns with the control plane; deleting the
// pod leaves no value on the node. The control plane runs here, reached from
// the cluster over TLS at host.docker.internal. Run by
// runners/a238-csi-kind-lab-proof.sh (TRSTCTL_A238_CSI_KUBECONFIG, a kind
// cluster of this build's own); skipped otherwise.
func TestServedSecretCSIVolumeOnKindA238(t *testing.T) {
	kubeconfig, image, node := os.Getenv("TRSTCTL_A238_CSI_KUBECONFIG"), os.Getenv("TRSTCTL_A238_CSI_IMAGE"), os.Getenv("TRSTCTL_A238_CSI_NODE")
	if kubeconfig == "" || image == "" || node == "" {
		t.Skip("run runners/a238-csi-kind-lab-proof.sh (a kind cluster and an agent image loaded into it)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()
	run := func(stdin string, name string, args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 G702 -- the runner's own lab cluster and node (CWE-78)
		if stdin != "" {
			cmd.Stdin = strings.NewReader(stdin)
		}
		return cmd.Output()
	}
	kubectl := func(stdin string, args ...string) []byte {
		t.Helper()
		out, err := run(stdin, "kubectl", append([]string{"--kubeconfig", kubeconfig}, args...)...)
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
	methods, err := machineAuthMethodsFromConfig([]config.MachineAuthMethod{{
		Name: "kubernetes", TenantID: servedTestTenant, Issuer: discovery.Issuer, Audience: "trstctl",
		JWKSJSON: string(jwks), AllowedNamespaces: []string{"a238-csi"}, Scopes: []string{"secrets:read"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.MachineAuthMethods = withMachineCredentialReplayGuard(methods, d.Store)
	})
	operator := seedScopedTokenSubject(t, h.store, h.tenant, "a238-csi-operator", "secrets:read", "secrets:write", "access:write")
	reader := "system:serviceaccount:a238-csi:app"
	for _, call := range []struct {
		method, path string
		body         any
		want         int
	}{
		{http.MethodPost, "/api/v1/secrets/projects", map[string]any{"slug": "csi238", "name": "CSI proof",
			"environments": []any{map[string]any{"slug": "prod", "restricted": true}}}, http.StatusCreated},
		{http.MethodPut, "/api/v1/secrets/projects/csi238/members/a238-csi-operator", map[string]any{"role": "admin"}, http.StatusOK},
		{http.MethodPut, "/api/v1/secrets/projects/csi238/members/" + url.PathEscape(reader),
			map[string]any{"role": "viewer", "environments": []string{"prod"}}, http.StatusOK},
		{http.MethodPost, "/api/v1/secrets/store", map[string]any{"name": "csi238/prod/db-password", "value": "csi-value-one"}, http.StatusCreated},
	} {
		if status, raw := secretsReq(t, h, call.method, call.path, operator, call.body); status != call.want {
			t.Fatalf("%s %s: HTTP %d %s", call.method, call.path, status, raw)
		}
	}

	// The control plane over TLS for the cluster: the driver pins this
	// certificate (ca_file) and reaches it at host.docker.internal.
	serving, err := mtls.SelfSignedServerCert([]string{"host.docker.internal"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	front := func(ln net.Listener) *http.Server {
		srv := &http.Server{Handler: h.ts.Config.Handler, ReadHeaderTimeout: 10 * time.Second}
		go func() { _ = serving.ServeHTTPS(srv, ln) }()
		return srv
	}
	frontServer := front(listener)
	t.Cleanup(func() { _ = frontServer.Close() })
	_, port, _ := net.SplitHostPort(address)

	manifest, err := os.ReadFile(filepath.Join("..", "..", "deploy", "kubernetes", "csi-secrets.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	caLines := strings.Split(strings.TrimSpace(string(serving.TrustPEM)), "\n")
	rendered := strings.NewReplacer(
		"image: ghcr.io/ctlplne/trstctl@sha256:RELEASE_DIGEST_REQUIRED", "image: "+image+"\n          imagePullPolicy: Never",
		"server: https://trstctl.example.internal:8443", "server: https://host.docker.internal:"+port,
		"tenant: REPLACE_WITH_THE_TENANT_ID", "tenant: "+h.tenant,
		"REPLACE_WITH_THE_CONTROL_PLANE_CA_CERTIFICATE_PEM", strings.Join(caLines, "\n    "),
	).Replace(string(manifest))
	kubectl("", "apply", "-f", filepath.Join("..", "..", "deploy", "kubernetes", "namespace.yaml"))
	kubectl(rendered, "apply", "-f", "-")
	// The driver reads its configuration at start: restart it on this run's.
	kubectl("", "-n", "trstctl", "rollout", "restart", "daemonset/trstctl-secrets-csi")
	// Cleanups run after ctx is cancelled, so they use commands of their own.
	t.Cleanup(func() {
		cmd := exec.Command("kubectl", "--kubeconfig", kubeconfig, "delete", "--ignore-not-found", "--wait=false", "-f", "-") // #nosec G204 G702 -- the runner's own lab cluster (CWE-78)
		cmd.Stdin = strings.NewReader(rendered)
		_ = cmd.Run()
	})
	kubectl("", "-n", "trstctl", "rollout", "status", "daemonset/trstctl-secrets-csi", "--timeout=180s")

	digest := func(value string) string { return crypto.SHA256Hex([]byte(value)) }
	workload := func(name, account string) string {
		return fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata: {name: %s, namespace: a238-csi}
spec:
  serviceAccountName: %s
  restartPolicy: Never
  securityContext: {runAsUser: 1000, runAsGroup: 1000, fsGroup: 2000}
  containers:
  - name: app
    image: registry.k8s.io/e2e-test-images/busybox:1.29-4
    imagePullPolicy: Never
    command: ["sh", "-c", "while true; do echo \"probe digest=$(sha256sum /secrets/password 2>/dev/null | cut -c1-64) mode=$(stat -c %%a:%%g /secrets/password 2>/dev/null) fs=$(awk '$2==\"/secrets\"{print $3}' /proc/mounts)\"; sleep 3; done"]
    volumeMounts: [{name: secrets, mountPath: /secrets, readOnly: true}]
  volumes:
  - name: secrets
    csi:
      driver: secrets.csi.trstctl.com
      readOnly: true
      volumeAttributes: {secrets: "password=csi238/prod/db-password", freshness: "2m"}
`, name, account)
	}
	kubectl(`apiVersion: v1
kind: Namespace
metadata: {name: a238-csi}
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: app, namespace: a238-csi}
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: other, namespace: a238-csi}
---
`+workload("reader", "app")+"---\n"+workload("intruder", "other"), "apply", "-f", "-")
	t.Cleanup(func() {
		_ = exec.Command("kubectl", "--kubeconfig", kubeconfig, "delete", "namespace", "a238-csi", "--wait=false").Run() // #nosec G204 G702 -- the runner's own lab cluster (CWE-78)
	})
	lastProbe := func() string {
		out, err := run("", "kubectl", "--kubeconfig", kubeconfig, "-n", "a238-csi", "logs", "reader", "--tail=1")
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(out))
	}
	waitFor := func(what string, within time.Duration, cond func() bool) {
		t.Helper()
		start := time.Now()
		for !cond() {
			if time.Since(start) > within {
				t.Fatalf("not within %s: %s (last probe %q)", within, what, lastProbe())
			}
			time.Sleep(3 * time.Second)
		}
		t.Logf("A238_CSI %s after %s", what, time.Since(start).Round(time.Second))
	}
	deliveries := func() string {
		_, raw := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/deliveries?name="+url.QueryEscape("csi238/prod/db-password"), operator, nil)
		return string(raw)
	}

	waitFor("the pod reads the secret from a tmpfs volume, 0440 with its fsGroup", 3*time.Minute, func() bool {
		return lastProbe() == "probe digest="+digest("csi-value-one")+" mode=440:2000 fs=tmpfs"
	})
	if secrets := kubectl("", "-n", "a238-csi", "get", "secrets", "-o", "name"); strings.TrimSpace(string(secrets)) != "" {
		t.Fatalf("the namespace holds Secret objects: %s", secrets)
	}
	waitFor("the control plane lists the pod as injected at version 1", time.Minute, func() bool {
		return strings.Contains(deliveries(), `"consumer":"pod:a238-csi/reader","injected_version":1`)
	})
	mounts, err := run("", "docker", "exec", node, "sh", "-c", "grep kubernetes.io~csi/secrets/mount /proc/mounts")
	if err != nil || !strings.HasPrefix(string(mounts), "tmpfs ") {
		t.Fatalf("the node's mount table: %q %v", mounts, err)
	}

	if status, raw := secretsReq(t, h, http.MethodPut, "/api/v1/secrets/store/csi238/prod/db-password", operator,
		map[string]any{"value": "csi-value-two"}); status != http.StatusOK {
		t.Fatalf("rotate: HTTP %d %s", status, raw)
	}
	waitFor("the republished volume carries version 2 in the running pod", 4*time.Minute, func() bool {
		return strings.HasPrefix(lastProbe(), "probe digest="+digest("csi-value-two")+" ")
	})
	waitFor("the control plane lists the pod as injected at version 2", 2*time.Minute, func() bool {
		return strings.Contains(deliveries(), `"consumer":"pod:a238-csi/reader","injected_version":2`)
	})
	waitFor("a pod whose identity may not read the secret gets no volume", 3*time.Minute, func() bool {
		events := kubectl("", "-n", "a238-csi", "get", "events", "--field-selector", "involvedObject.name=intruder", "-o", "jsonpath={.items[*].message}")
		phase := kubectl("", "-n", "a238-csi", "get", "pod", "intruder", "-o", "jsonpath={.status.phase}")
		return strings.Contains(string(events), "may not read csi238/prod/db-password") && string(phase) == "Pending"
	})

	// Outage: the last value serves inside the freshness bound (2m), is
	// removed past it, and comes back with the control plane.
	_ = frontServer.Close()
	outage := time.Now()
	waitFor("past the freshness bound without the control plane, the file is removed", 6*time.Minute, func() bool {
		return strings.HasPrefix(lastProbe(), "probe digest= ")
	})
	if served := time.Since(outage); served < 2*time.Minute {
		t.Fatalf("the file went %s into the outage, inside its 2m bound", served.Round(time.Second))
	}
	again, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	frontServer = front(again)
	waitFor("with the control plane back, the file is written again", 4*time.Minute, func() bool {
		return strings.HasPrefix(lastProbe(), "probe digest="+digest("csi-value-two")+" ")
	})

	logs := kubectl("", "-n", "trstctl", "logs", "daemonset/trstctl-secrets-csi", "-c", "secrets-csi")
	for _, value := range []string{"csi-value-one", "csi-value-two"} {
		if strings.Contains(string(logs), value) {
			t.Fatalf("a value reached the driver's log")
		}
	}
	kubectl("", "-n", "a238-csi", "delete", "pod", "reader", "intruder", "--wait=true", "--timeout=120s")
	if out, _ := run("", "docker", "exec", node, "sh", "-c",
		"grep -c kubernetes.io~csi/secrets/mount /proc/mounts; grep -rlF -e csi-value-one -e csi-value-two /var/lib/kubelet | wc -l"); strings.Fields(string(out))[0] != "0" || strings.Fields(string(out))[1] != "0" {
		t.Fatalf("after the pod went, the node still holds a mount or a value: %q", out)
	}
	t.Logf("A238_CSI_KIND_OK issuer=%s", discovery.Issuer)
}
