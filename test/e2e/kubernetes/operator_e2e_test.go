// SPDX-License-Identifier: BUSL-1.1

//go:build e2e

package kubernetes_e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/operator"
)

// kubeAPI is an admin client for fixtures and read-back; the operator under
// test gets its own least-privilege token.
type kubeAPI struct {
	t          *testing.T
	server     string
	token      string
	httpClient *http.Client
}

func newKubeAPI(t *testing.T) kubeAPI {
	t.Helper()
	server := env(t, "K8S_SERVER")
	caPEM, err := os.ReadFile(env(t, "K8S_CA_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	token := os.Getenv("K8S_ADMIN_TOKEN")
	if token == "" {
		token = env(t, "K8S_TOKEN")
	}
	transport, err := mtls.HTTPTransport(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	return kubeAPI{t: t, server: server, token: token, httpClient: &http.Client{Transport: transport, Timeout: 30 * time.Second}}
}

func (k kubeAPI) do(method, path, contentType string, body any) (int, map[string]any) {
	k.t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			k.t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, k.server+path, reader)
	if err != nil {
		k.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+k.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		if contentType == "" {
			contentType = "application/json"
		}
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := k.httpClient.Do(req)
	if err != nil {
		k.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(data, &out)
	return resp.StatusCode, out
}

func (k kubeAPI) must(method, path, contentType string, body any) map[string]any {
	k.t.Helper()
	st, out := k.do(method, path, contentType, body)
	if st/100 != 2 {
		k.t.Fatalf("%s %s: status %d: %v", method, path, st, out["message"])
	}
	return out
}

func (k kubeAPI) get(path string) map[string]any { return k.must(http.MethodGet, path, "", nil) }

// waitGone polls until path reads 404.
func (k kubeAPI) waitGone(path string) {
	k.t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		st, _ := k.do(http.MethodGet, path, "", nil)
		if st == http.StatusNotFound {
			return
		}
		if time.Now().After(deadline) {
			k.t.Fatalf("%s still exists (status %d)", path, st)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// at walks decoded JSON by map keys and slice indexes; a missing step is nil.
func at(value any, path ...any) any {
	for _, step := range path {
		switch key := step.(type) {
		case string:
			m, _ := value.(map[string]any)
			value = m[key]
		case int:
			s, _ := value.([]any)
			if key >= len(s) {
				return nil
			}
			value = s[key]
		}
	}
	return value
}

func manifestDocuments(t *testing.T, path string) []map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path) // #nosec G304 -- test reads the repository's own manifests (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	var docs []map[string]any
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	for {
		var doc map[string]any
		if err := dec.Decode(&doc); errors.Is(err, io.EOF) {
			return docs
		} else if err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
		if doc != nil {
			docs = append(docs, doc)
		}
	}
}

// applyOperatorCRDs installs or updates deploy/operator/crd.yaml and waits for
// each definition to be established.
func applyOperatorCRDs(k kubeAPI) {
	k.t.Helper()
	applyCRDFile(k, filepath.Join("..", "..", "..", "deploy", "operator", "crd.yaml"))
}

// applyCRDFile installs or updates every CustomResourceDefinition in path and
// waits for each to be established.
func applyCRDFile(k kubeAPI, path string) {
	k.t.Helper()
	for _, crd := range manifestDocuments(k.t, path) {
		if crd["kind"] != "CustomResourceDefinition" {
			continue
		}
		name, _ := at(crd, "metadata", "name").(string)
		path := "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/" + name
		if st, _ := k.do(http.MethodGet, path, "", nil); st == http.StatusNotFound {
			k.must(http.MethodPost, "/apis/apiextensions.k8s.io/v1/customresourcedefinitions", "", crd)
		} else {
			k.must(http.MethodPatch, path, "application/merge-patch+json", map[string]any{"spec": crd["spec"]})
		}
		deadline := time.Now().Add(60 * time.Second)
		for established := false; !established; {
			conditions, _ := at(k.get(path), "status", "conditions").([]any)
			for _, condition := range conditions {
				established = established || (at(condition, "type") == "Established" && at(condition, "status") == "True")
			}
			if !established {
				if time.Now().After(deadline) {
					k.t.Fatalf("CRD %s not established", name)
				}
				time.Sleep(500 * time.Millisecond)
			}
		}
	}
}

// operatorToken provisions the operator's service account in namespace with
// exactly the rules deploy/operator/operator.yaml grants it (the ClusterRole's
// custom-resource rules and the namespaced Role's), and returns a token for it.
func operatorToken(k kubeAPI, namespace string) string {
	k.t.Helper()
	var rules []any
	for _, doc := range manifestDocuments(k.t, filepath.Join("..", "..", "..", "deploy", "operator", "operator.yaml")) {
		if (doc["kind"] == "Role" || doc["kind"] == "ClusterRole") && at(doc, "metadata", "name") == "trstctl-operator" {
			docRules, _ := doc["rules"].([]any)
			rules = append(rules, docRules...)
		}
	}
	if len(rules) == 0 {
		k.t.Fatal("operator.yaml grants the operator no rules")
	}
	base := "/api/v1/namespaces/" + namespace
	rbac := "/apis/rbac.authorization.k8s.io/v1/namespaces/" + namespace
	k.must(http.MethodPost, base+"/serviceaccounts", "", map[string]any{
		"apiVersion": "v1", "kind": "ServiceAccount", "metadata": map[string]any{"name": "trstctl-operator"},
	})
	k.must(http.MethodPost, rbac+"/roles", "", map[string]any{
		"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
		"metadata": map[string]any{"name": "trstctl-operator"}, "rules": rules,
	})
	k.must(http.MethodPost, rbac+"/rolebindings", "", map[string]any{
		"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
		"metadata": map[string]any{"name": "trstctl-operator"},
		"roleRef":  map[string]any{"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "trstctl-operator"},
		"subjects": []any{map[string]any{"kind": "ServiceAccount", "name": "trstctl-operator", "namespace": namespace}},
	})
	request := k.must(http.MethodPost, base+"/serviceaccounts/trstctl-operator/token", "", map[string]any{
		"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest",
		"spec": map[string]any{"expirationSeconds": 3600},
	})
	token, _ := at(request, "status", "token").(string)
	if token == "" {
		k.t.Fatal("token request returned no token")
	}
	return token
}

// createControlPlane creates the resource and reads it back, retrying while a
// just-updated CRD schema still prunes fields the test sent.
func createControlPlane(k kubeAPI, namespace string, cr map[string]any) map[string]any {
	k.t.Helper()
	collection := "/apis/trstctl.com/v1alpha1/namespaces/" + namespace + "/trstctlcontrolplanes"
	name, _ := at(cr, "metadata", "name").(string)
	want := normalizeJSON(k.t, cr["spec"])
	deadline := time.Now().Add(60 * time.Second)
	for {
		k.must(http.MethodPost, collection, "", cr)
		stored := k.get(collection + "/" + name)
		if reflect.DeepEqual(normalizeJSON(k.t, stored["spec"]), want) {
			return stored
		}
		k.must(http.MethodDelete, collection+"/"+name, "", nil)
		k.waitGone(collection + "/" + name)
		if time.Now().After(deadline) {
			k.t.Fatalf("the API server keeps pruning the spec: stored %v", stored["spec"])
		}
		time.Sleep(time.Second)
	}
}

func normalizeJSON(t *testing.T, value any) any {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// reconcileAsOperator runs one reconcile pass with the operator's own token,
// retrying briefly while a just-created RoleBinding reaches the authorizer.
func reconcileAsOperator(t *testing.T, reconciler *operator.Reconciler, namespace string) (map[string]operator.Action, error) {
	t.Helper()
	for attempt := 0; ; attempt++ {
		actions, err := reconciler.ReconcileNamespace(context.Background(), namespace)
		if err == nil || !strings.Contains(err.Error(), "status 403") || attempt == 20 {
			return actions, err
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func controlPlaneEnvByName(deployment map[string]any) map[string]any {
	out := map[string]any{}
	containers, _ := at(deployment, "spec", "template", "spec", "containers").([]any)
	for _, container := range containers {
		if at(container, "name") != "control-plane" {
			continue
		}
		items, _ := at(container, "env").([]any)
		for _, item := range items {
			name, _ := at(item, "name").(string)
			if value := at(item, "value"); value != nil {
				out[name] = value
			} else {
				out[name] = at(item, "valueFrom", "secretKeyRef", "name")
			}
		}
	}
	return out
}

// signerMTLSEnds reads the two generated Secrets and proves they are a working
// pair: the signer end serves, the control-plane end completes the pinned
// handshake against it.
func requireWorkingSignerMTLSPair(k kubeAPI, namespace, signerSecret, cpSecret, serverName string) {
	k.t.Helper()
	mount := func(name string) mtls.SignerPeerConfig {
		obj := k.get("/api/v1/namespaces/" + namespace + "/secrets/" + name)
		if at(obj, "type") != "Opaque" || at(obj, "metadata", "labels", "app.kubernetes.io/managed-by") != "trstctl-operator" {
			k.t.Fatalf("Secret %s = type %v labels %v", name, at(obj, "type"), at(obj, "metadata", "labels"))
		}
		var data map[string][]byte
		raw, _ := json.Marshal(obj["data"])
		if err := json.Unmarshal(raw, &data); err != nil {
			k.t.Fatal(err)
		}
		dir := k.t.TempDir()
		for _, key := range []string{"tls.crt", "tls.key", "peer-ca.pem"} {
			if len(data[key]) == 0 {
				k.t.Fatalf("Secret %s has no %s", name, key)
			}
			if err := os.WriteFile(filepath.Join(dir, key), data[key], 0o600); err != nil {
				k.t.Fatal(err)
			}
		}
		return mtls.SignerPeerConfig{
			CertFile: filepath.Join(dir, "tls.crt"), KeyFile: filepath.Join(dir, "tls.key"),
			PeerCAFile: filepath.Join(dir, "peer-ca.pem"), PeerPinHex: string(data["peer-pin"]),
		}
	}
	signerEnd, cpEnd := mount(signerSecret), mount(cpSecret)
	serverCreds, err := mtls.SignerServerCredentials(signerEnd)
	if err != nil {
		k.t.Fatalf("signer end from %s: %v", signerSecret, err)
	}
	clientCreds, err := mtls.SignerClientCredentials(cpEnd, serverName)
	if err != nil {
		k.t.Fatalf("control-plane end from %s: %v", cpSecret, err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		k.t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	serverDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		wrapped, _, err := serverCreds.ServerHandshake(conn)
		if err == nil {
			_ = wrapped.Close()
		}
		serverDone <- err
	}()
	raw, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		k.t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	if _, _, err := clientCreds.ClientHandshake(context.Background(), serverName, raw); err != nil {
		k.t.Fatalf("the control-plane end did not accept the signer end: %v", err)
	}
	select {
	case err := <-serverDone:
		if err != nil {
			k.t.Fatalf("the signer end refused the control-plane end: %v", err)
		}
	case <-time.After(10 * time.Second):
		k.t.Fatal("the signer end never finished its handshake")
	}
}

// TestOperatorManagesTheControlPlaneNetworkSurface drives the operator's
// reconciler against a real API server with only the permissions
// deploy/operator/operator.yaml grants it. Kubernetes itself validates every
// object the operator renders — the control plane's Deployment, Service,
// NetworkPolicy and Ingress and, with an isolated signer, the generated mTLS
// pair and the signer's Deployment, Service and NetworkPolicy — and the test
// reads each one back: the generated pair completes the pinned handshake, a
// second pass writes nothing, a spec change patches in place and removes what
// the spec dropped, and an object at a managed name the operator does not own
// is refused, not taken over.
func TestOperatorManagesTheControlPlaneNetworkSurface(t *testing.T) {
	k := newKubeAPI(t)
	applyOperatorCRDs(k)
	ns := fmt.Sprintf("trstctl-operator-e2e-%d", time.Now().UnixNano())
	k.must(http.MethodPost, "/api/v1/namespaces", "", map[string]any{
		"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": ns},
	})
	t.Cleanup(func() { k.do(http.MethodDelete, "/api/v1/namespaces/"+ns, "", nil) })
	reconciler := operator.NewReconciler(operator.NewClient(k.server, operatorToken(k, ns), k.httpClient))

	base := "/apis/trstctl.com/v1alpha1/namespaces/" + ns + "/trstctlcontrolplanes/edge"
	deployments := "/apis/apps/v1/namespaces/" + ns + "/deployments/"
	services := "/api/v1/namespaces/" + ns + "/services/"
	policies := "/apis/networking.k8s.io/v1/namespaces/" + ns + "/networkpolicies/"
	ingresses := "/apis/networking.k8s.io/v1/namespaces/" + ns + "/ingresses/"
	secrets := "/api/v1/namespaces/" + ns + "/secrets/"
	cr := createControlPlane(k, ns, map[string]any{
		"apiVersion": "trstctl.com/v1alpha1", "kind": "TrstctlControlPlane",
		"metadata": map[string]any{"name": "edge"},
		"spec": map[string]any{
			"replicas": 1, "image": "registry.invalid/trstctl:e2e", "signerMode": "isolated",
			"nats":   map[string]any{"url": "nats://nats.invalid:4222", "allowSingleReplica": false},
			"signer": map[string]any{"authTokenCommand": "/usr/local/bin/trstctl-sign-approve"}, // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
			"service": map[string]any{
				"type": "ClusterIP", "port": 443, "annotations": map[string]any{"example.com/team": "pki"},
			},
			"ingress": map[string]any{ // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
				"enabled": true, "className": "nginx", "host": "trstctl.e2e.test", "tlsSecret": "trstctl-e2e-tls",
				"annotations": map[string]any{"nginx.ingress.kubernetes.io/backend-protocol": "HTTPS"},
			},
			"networkPolicy": map[string]any{"allowedNamespaces": []any{"monitoring"}, "egressCIDRs": []any{"10.96.0.0/12"}},
		},
	})
	uid := at(cr, "metadata", "uid")

	actions, err := reconcileAsOperator(t, reconciler, ns)
	if err != nil || actions["edge"] != operator.ActionCreate {
		t.Fatalf("first reconcile = %v, %v", actions, err)
	}
	status := at(k.get(base), "status")
	for _, surface := range []string{"deployment", "service", "networkPolicy", "ingress", "signer", "signerService", "signerNetworkPolicy", "signerMTLS"} {
		if at(status, "surfaces", surface) != "create" {
			t.Fatalf("status after the first pass = %v", status)
		}
	}
	t.Logf("first pass as the operator's service account: phase %v, surfaces %v", at(status, "phase"), at(status, "surfaces"))

	controlPlane := k.get(deployments + "edge-control-plane")
	envs := controlPlaneEnvByName(controlPlane)
	if at(controlPlane, "metadata", "ownerReferences", 0, "uid") != uid ||
		at(controlPlane, "spec", "template", "spec", "securityContext", "fsGroup") != float64(65532) ||
		envs["TRSTCTL_SIGNER_MTLS_ADDRESS"] != "edge-signer:9443" ||
		envs["TRSTCTL_SIGNER_MTLS_SERVER_NAME"] != "edge-signer."+ns+".svc" ||
		envs["TRSTCTL_SIGNER_MTLS_PEER_PIN"] != "edge-cp-signer-mtls" ||
		envs["TRSTCTL_SIGNER_AUTH_TOKEN_COMMAND"] != "/usr/local/bin/trstctl-sign-approve" {
		t.Fatalf("control-plane deployment owner %v, security %v, env %v", at(controlPlane, "metadata", "ownerReferences"),
			at(controlPlane, "spec", "template", "spec", "securityContext"), envs)
	}
	signer := k.get(deployments + "edge-signer")
	fingerprint := at(signer, "spec", "template", "metadata", "annotations", "trstctl.com/signer-mtls")
	if fingerprint == nil || fingerprint == "" || at(controlPlane, "spec", "template", "metadata", "annotations", "trstctl.com/signer-mtls") != fingerprint {
		t.Fatalf("pin fingerprints: signer %v, control plane %v", fingerprint, at(controlPlane, "spec", "template", "metadata", "annotations"))
	}
	if at(signer, "spec", "template", "spec", "automountServiceAccountToken") != false ||
		at(signer, "spec", "template", "spec", "containers", 0, "args", 0) != "--mtls-listen=:9443" ||
		at(signer, "metadata", "ownerReferences", 0, "uid") != uid {
		t.Fatalf("signer deployment = %v", at(signer, "spec", "template", "spec"))
	}
	requireWorkingSignerMTLSPair(k, ns, "edge-signer-mtls", "edge-cp-signer-mtls", "edge-signer."+ns+".svc")
	t.Logf("generated signer mTLS pair completes the pinned handshake; both pods carry fingerprint %v", fingerprint)

	service := k.get(services + "edge-control-plane")
	if at(service, "spec", "ports", 0, "port") != float64(443) || at(service, "spec", "ports", 0, "targetPort") != "https" ||
		at(service, "spec", "selector", "trstctl.com/control-plane") != "edge" ||
		at(service, "metadata", "annotations", "example.com/team") != "pki" {
		t.Fatalf("service = %v", service)
	}
	if at(k.get(services+"edge-signer"), "spec", "ports", 0, "port") != float64(9443) {
		t.Fatal("no signer service on 9443")
	}
	policy := k.get(policies + "edge-control-plane")
	egress, _ := at(policy, "spec", "egress").([]any)
	if len(egress) != 3 || at(egress[2], "to", 0, "podSelector", "matchLabels", "trstctl.com/signer") != "edge" ||
		at(policy, "spec", "ingress", 0, "from", 1, "namespaceSelector", "matchLabels", "kubernetes.io/metadata.name") != "monitoring" {
		t.Fatalf("control-plane network policy = %v", at(policy, "spec"))
	}
	if at(k.get(policies+"edge-signer"), "spec", "ingress", 0, "from", 0, "podSelector", "matchLabels", "trstctl.com/control-plane") != "edge" {
		t.Fatal("the signer's network policy does not admit only this control plane")
	}
	ingress := k.get(ingresses + "edge-control-plane")
	if at(ingress, "spec", "ingressClassName") != "nginx" || at(ingress, "spec", "tls", 0, "secretName") != "trstctl-e2e-tls" ||
		at(ingress, "spec", "rules", 0, "http", "paths", 0, "backend", "service", "port", "name") != "https" {
		t.Fatalf("ingress = %v", at(ingress, "spec"))
	}

	// A converged pass writes nothing.
	versions := map[string]any{}
	for _, path := range []string{services + "edge-control-plane", services + "edge-signer", policies + "edge-control-plane",
		policies + "edge-signer", ingresses + "edge-control-plane", secrets + "edge-signer-mtls", secrets + "edge-cp-signer-mtls"} {
		versions[path] = at(k.get(path), "metadata", "resourceVersion")
	}
	for _, path := range []string{deployments + "edge-control-plane", deployments + "edge-signer"} {
		versions[path] = at(k.get(path), "metadata", "generation")
	}
	if actions, err := reconcileAsOperator(t, reconciler, ns); err != nil || actions["edge"] != operator.ActionNone {
		t.Fatalf("converged reconcile = %v, %v", actions, err)
	}
	for path, before := range versions {
		field := "resourceVersion"
		if strings.Contains(path, "/deployments/") {
			field = "generation"
		}
		if after := at(k.get(path), "metadata", field); after != before {
			t.Fatalf("a converged pass rewrote %s (%s %v -> %v)", path, field, before, after)
		}
	}
	if status := at(k.get(base), "status"); at(status, "phase") != "Ready" || at(status, "readySurfaces") != float64(8) {
		t.Fatalf("converged status = %v", status)
	}
	t.Logf("converged pass rewrote none of %d objects; phase Ready with 8 ready surfaces", len(versions))

	// Back to the sidecar signer on a new port, with one annotation swapped.
	k.must(http.MethodPatch, base, "application/merge-patch+json", map[string]any{"spec": map[string]any{
		"signerMode": "sidecar",
		"service":    map[string]any{"port": 8443, "annotations": map[string]any{"example.com/team": nil, "example.com/owner": "sec"}},
	}})
	if _, err := reconcileAsOperator(t, reconciler, ns); err != nil {
		t.Fatalf("reconcile back to the sidecar: %v", err)
	}
	for _, path := range []string{deployments + "edge-signer", services + "edge-signer", policies + "edge-signer",
		secrets + "edge-signer-mtls", secrets + "edge-cp-signer-mtls"} {
		k.waitGone(path)
	}
	service = k.get(services + "edge-control-plane")
	if at(service, "spec", "ports", 0, "port") != float64(8443) || at(service, "metadata", "annotations", "example.com/team") != nil ||
		at(service, "metadata", "annotations", "example.com/owner") != "sec" {
		t.Fatalf("service after the port and annotation change = %v", at(service, "metadata", "annotations"))
	}
	if egress, _ := at(k.get(policies+"edge-control-plane"), "spec", "egress").([]any); len(egress) != 2 {
		t.Fatalf("control-plane egress still reaches a signer pod: %v", egress)
	}
	controlPlane = k.get(deployments + "edge-control-plane")
	if containers, _ := at(controlPlane, "spec", "template", "spec", "containers").([]any); len(containers) != 2 {
		t.Fatalf("the sidecar control plane runs %d containers, want the signer beside it", len(containers))
	}
	t.Logf("back to the sidecar: signer Deployment, Service, NetworkPolicy and generated pair removed; service now %v", at(service, "spec", "ports", 0, "port"))

	// Ingress and NetworkPolicy off: both removed.
	k.must(http.MethodPatch, base, "application/merge-patch+json", map[string]any{"spec": map[string]any{
		"ingress": map[string]any{"enabled": false}, "networkPolicy": map[string]any{"enabled": false},
	}})
	if _, err := reconcileAsOperator(t, reconciler, ns); err != nil {
		t.Fatalf("reconcile without ingress and policy: %v", err)
	}
	k.waitGone(ingresses + "edge-control-plane")
	k.waitGone(policies + "edge-control-plane")

	// Someone else's Ingress at the managed name is left alone while the spec
	// asks for none, and refused rather than taken over when it asks again.
	k.must(http.MethodPost, "/apis/networking.k8s.io/v1/namespaces/"+ns+"/ingresses", "", map[string]any{
		"apiVersion": "networking.k8s.io/v1", "kind": "Ingress",
		"metadata": map[string]any{"name": "edge-control-plane"},
		"spec":     map[string]any{"defaultBackend": map[string]any{"service": map[string]any{"name": "someone-else", "port": map[string]any{"number": 80}}}},
	})
	if _, err := reconcileAsOperator(t, reconciler, ns); err != nil {
		t.Fatalf("reconcile beside a foreign ingress: %v", err)
	}
	k.get(ingresses + "edge-control-plane")
	k.must(http.MethodPatch, base, "application/merge-patch+json", map[string]any{"spec": map[string]any{"ingress": map[string]any{"enabled": true}}})
	if _, err := reconcileAsOperator(t, reconciler, ns); err == nil || !strings.Contains(err.Error(), "not owned") {
		t.Fatalf("reconcile over a foreign ingress = %v, want a refusal", err)
	}
	if status := at(k.get(base), "status"); at(status, "phase") != "Blocked" || !strings.Contains(fmt.Sprint(at(status, "message")), "not owned") {
		t.Fatalf("status over a foreign ingress = %v", status)
	}
	foreign := k.get(ingresses + "edge-control-plane")
	if at(foreign, "metadata", "labels") != nil || at(foreign, "spec", "defaultBackend", "service", "name") != "someone-else" {
		t.Fatalf("the operator changed someone else's ingress: %v", foreign)
	}
	t.Logf("foreign ingress at the managed name: left alone, then refused (phase Blocked) and unchanged")
}
