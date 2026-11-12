// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/cli"
)

// TestServedBrowserKubernetesPodsOnKindA259L4 is A259-L4: a browser terminal's
// pod and container are chosen from the cluster, not typed. The opener of a
// Kubernetes session opened for the browser lists the pods its session's
// account can see, through the session's gateway as kubectl would. With no
// namespace named, the list is the provider's namespace. Each pod comes with
// its containers in its spec's order. The opener alone may list; a namespace
// the account cannot read is refused by the cluster; the gateway records the
// list. A listed pod and container open a terminal. The runner names the
// cluster (K8S_SERVER, K8S_ADMIN_TOKEN, K8S_CA_FILE).
func TestServedBrowserKubernetesPodsOnKindA259L4(t *testing.T) {
	c := startKindPAMCluster(t, "trstctl-a259")
	f, h := c.f, c.f.h
	// A second pod with two containers: the containers come from its spec.
	if status, body := c.kube(http.MethodPost, "/api/v1/namespaces/"+c.namespace+"/pods", map[string]any{"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"name": "pair"},
		"spec": map[string]any{"containers": []any{
			map[string]any{"name": "app", "image": "registry.k8s.io/e2e-test-images/busybox:1.29-4", "command": []string{"sleep", "3600"}},
			map[string]any{"name": "sidecar", "image": "registry.k8s.io/e2e-test-images/busybox:1.29-4", "command": []string{"sleep", "3600"}},
		}}}); status != http.StatusCreated {
		t.Fatalf("create the two-container pod: %d %s", status, body)
	}
	a201Await(t, "the two-container pod runs", func() bool {
		_, body := c.kube(http.MethodGet, "/api/v1/namespaces/"+c.namespace+"/pods/pair", nil)
		return strings.Contains(string(body), `"phase":"Running"`)
	})
	opened := f.open("a259l4-kubernetes-pods", map[string]any{"target_type": "kubernetes", "target_id": "k8s-gw", "role": "operator",
		"ttl_seconds": 900, "browser": true})
	if opened.Delivery != "gateway" || opened.Gateway == nil {
		t.Fatalf("a browser open = %+v", opened)
	}
	var replies strings.Builder
	podsPath := "/api/v1/access/sessions/" + opened.ID + "/pods"
	type pod struct {
		Name       string   `json:"name"`
		Phase      string   `json:"phase"`
		Containers []string `json:"containers"`
	}
	var listed struct {
		Namespace string `json:"namespace"`
		Pods      []pod  `json:"pods"`
		Truncated bool   `json:"truncated"`
	}
	status, body := secretsReq(t, h.servedHarness, http.MethodGet, podsPath, f.requester, nil)
	replies.Write(body)
	if status != http.StatusOK || json.Unmarshal(body, &listed) != nil {
		t.Fatalf("list the session's pods = %d %s (gateway: %s)", status, body, f.gatewayLog.String())
	}
	if listed.Namespace != c.namespace || listed.Truncated || len(listed.Pods) != 2 ||
		listed.Pods[0].Name != "pair" || strings.Join(listed.Pods[0].Containers, ",") != "app,sidecar" || listed.Pods[0].Phase != "Running" ||
		listed.Pods[1].Name != "shell" || strings.Join(listed.Pods[1].Containers, ",") != "shell" || listed.Pods[1].Phase != "Running" {
		t.Fatalf("the provider's namespace lists %+v, want pair (app, sidecar) and shell (shell), running", listed)
	}
	// Naming the namespace reads the same list.
	if status, named := secretsReq(t, h.servedHarness, http.MethodGet, podsPath+"?namespace="+c.namespace, f.requester, nil); status != http.StatusOK || !bytes.Equal(named, body) {
		t.Fatalf("the named namespace = %d %s", status, named)
	}
	// Only the opener lists; the cluster refuses a namespace the session's
	// account cannot read; a namespace that is not a Kubernetes name is
	// refused before anything is asked.
	if status, other := secretsReq(t, h.servedHarness, http.MethodGet, podsPath, f.operator, nil); status != http.StatusForbidden {
		t.Fatalf("someone other than the opener listed the pods: %d %s", status, other)
	}
	if status, refused := secretsReq(t, h.servedHarness, http.MethodGet, podsPath+"?namespace=kube-system", f.requester, nil); status != http.StatusForbidden ||
		!strings.Contains(string(refused), "may not list pods in kube-system") {
		t.Fatalf("another namespace = %d %s", status, refused)
	}
	if status, invalid := secretsReq(t, h.servedHarness, http.MethodGet, podsPath+"?namespace=Not_A_Name", f.requester, nil); status != http.StatusUnprocessableEntity {
		t.Fatalf("an invalid namespace = %d %s", status, invalid)
	}
	// The CLI lists them too.
	api := httptest.NewServer(h.srv.Handler())
	defer api.Close()
	var stdout, stderr bytes.Buffer
	if code := cli.Run(t.Context(), []string{"--server", api.URL, "--token", f.requester, "--tenant", h.tenant,
		"access", "sessions", "pods", opened.ID}, cli.Env{HTTPClient: api.Client()}, nil, &stdout, &stderr); code != 0 ||
		!strings.Contains(stdout.String(), `"sidecar"`) {
		t.Fatalf("trstctl-cli access sessions pods = %d %s%s", code, stdout.String(), stderr.String())
	}
	replies.WriteString(stdout.String())

	// A listed pod and container open a terminal.
	terminalPath := "/api/v1/access/sessions/" + opened.ID + "/terminals"
	status, body = secretsReqKey(t, h.servedHarness, http.MethodPost, terminalPath, f.requester, "a259l4-terminal",
		map[string]any{"cols": 100, "rows": 30, "namespace": listed.Namespace, "pod": listed.Pods[0].Name, "container": listed.Pods[0].Containers[1]})
	replies.Write(body)
	var terminal struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &terminal) != nil {
		t.Fatalf("open a terminal in the listed container = %d %s", status, body)
	}
	base := terminalPath + "/" + terminal.ID
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, base+"/input", f.requester, "a259l4-input",
		map[string]any{"data": base64.StdEncoding.EncodeToString([]byte("echo listed-$((40+2))\n"))}); status != http.StatusOK {
		t.Fatalf("type = %d %s", status, body)
	}
	var seen strings.Builder
	next := int64(0)
	a201Await(t, "the listed container's output", func() bool {
		status, body := secretsReq(t, h.servedHarness, http.MethodGet, base+"/output?from="+strconv.FormatInt(next, 10)+"&wait=5", f.requester, nil)
		var out struct {
			Data []byte `json:"data"`
			Next int64  `json:"next"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &out) != nil {
			t.Fatalf("read the terminal = %d %s", status, body)
		}
		seen.Write(out.Data)
		next = out.Next
		return strings.Contains(seen.String(), "listed-42")
	})
	if status, _ := secretsReqKey(t, h.servedHarness, http.MethodDelete, base, f.requester, "a259l4-close", nil); status != http.StatusOK {
		t.Fatalf("close the terminal = %d", status)
	}
	// No reply the browser or the CLI received carries the session's token
	// (a JWT, "eyJ...") or the cluster credential.
	if text := replies.String(); strings.Contains(text, "eyJ") || strings.Contains(text, c.adminToken) {
		t.Fatalf("a reply carries a credential: %s", text)
	}

	// The gateway recorded the list as the session's own request.
	if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+opened.ID+"/terminate", f.operator, "a259l4-terminate",
		map[string]any{"reason": "pods list proof"}); status != http.StatusAccepted {
		t.Fatalf("terminate = %d", status)
	}
	a201Await(t, "the Kubernetes recording seals", func() bool {
		status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+opened.ID+"/recording", f.requester, nil)
		return status == http.StatusOK && strings.Contains(string(body), `"status":"sealed"`)
	})
	text := recordingText(t, h, opened.ID)
	for _, want := range []string{"request: GET /api/v1/namespaces/" + c.namespace + "/pods", "request: GET /api/v1/namespaces/kube-system/pods", "listed-42"} {
		if !strings.Contains(text, want) {
			t.Fatalf("the Kubernetes recording lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, c.adminToken) {
		t.Fatalf("the Kubernetes recording kept the cluster credential")
	}
	a201Await(t, "the session's service account is deleted", func() bool { return len(c.serviceAccounts()) == 0 })
}
