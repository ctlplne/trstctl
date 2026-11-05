// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestServedBrowserKubernetesExecOnKindA259: a Kubernetes session opened for
// the browser leaves its ticket with the control plane — the reply carries
// none — and its opener works in a pod through a terminal the control plane
// opens through the session's gateway as an exec: typed input runs in the
// pod, its output comes back by long-polling, a resize reaches the pod's
// terminal, and the exec's exit status ends the terminal. A terminal must
// name a pod and only the opener can open one; the gateway records the exec
// stream as it records any session's, with no credential in it. The runner
// names the cluster (K8S_SERVER, K8S_ADMIN_TOKEN, K8S_CA_FILE).
func TestServedBrowserKubernetesExecOnKindA259(t *testing.T) {
	c := startKindPAMCluster(t, "trstctl-a259")
	f, h := c.f, c.f.h
	opened := f.open("a259-kubernetes-browser", map[string]any{"target_type": "kubernetes", "target_id": "k8s-gw", "role": "operator",
		"ttl_seconds": 900, "browser": true})
	if opened.Delivery != "gateway" || opened.Gateway == nil || opened.Gateway.Ticket != "" {
		t.Fatalf("a browser open's reply carries a ticket or no gateway: %+v", opened.Gateway)
	}
	// Every reply the browser receives is kept, to show no credential is in
	// any of them.
	var replies strings.Builder
	if raw, err := json.Marshal(opened); err == nil {
		replies.Write(raw)
	}

	terminalPath := "/api/v1/access/sessions/" + opened.ID + "/terminals"
	pod := map[string]any{"cols": 100, "rows": 30, "namespace": c.namespace, "pod": "shell", "container": "shell"}
	if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, terminalPath, f.requester, "a259-k8s-no-pod", map[string]any{"cols": 100, "rows": 30}); status == http.StatusCreated {
		t.Fatal("a Kubernetes terminal opened without naming a pod")
	}
	if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, terminalPath, f.operator, "a259-k8s-other", pod); status == http.StatusCreated {
		t.Fatal("someone other than the opener opened a terminal")
	}
	status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, terminalPath, f.requester, "a259-k8s-terminal", pod)
	replies.Write(body)
	var terminal struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &terminal) != nil || terminal.ID == "" {
		t.Fatalf("open a pod terminal = %d %s (gateway: %s)", status, body, f.gatewayLog.String())
	}
	base := terminalPath + "/" + terminal.ID
	var seen strings.Builder
	next, closed, exitStatus := int64(0), false, -1
	read := func() {
		t.Helper()
		status, body := secretsReq(t, h.servedHarness, http.MethodGet, base+"/output?from="+strconv.FormatInt(next, 10)+"&wait=5", f.requester, nil)
		var out struct {
			Data       []byte `json:"data"`
			Next       int64  `json:"next"`
			Closed     bool   `json:"closed"`
			ExitStatus *int   `json:"exit_status"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &out) != nil {
			t.Fatalf("read the terminal = %d %s", status, body)
		}
		seen.Write(out.Data)
		next, closed = out.Next, out.Closed
		if out.ExitStatus != nil {
			exitStatus = *out.ExitStatus
		}
	}
	typed := 0
	typeLine := func(line string) {
		t.Helper()
		typed++
		status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, base+"/input", f.requester, "a259-k8s-input-"+strconv.Itoa(typed),
			map[string]any{"data": base64.StdEncoding.EncodeToString([]byte(line + "\n"))})
		if status != http.StatusOK {
			t.Fatalf("type %q = %d %s", line, status, body)
		}
		replies.Write(body)
	}
	typeLine("echo browser-$((40+2))")
	a201Await(t, "the pod's output reaches the browser", func() bool {
		read()
		return strings.Contains(seen.String(), "browser-42")
	})
	if status, _ := secretsReq(t, h.servedHarness, http.MethodGet, base+"/output?from=0", f.operator, nil); status == http.StatusOK {
		t.Fatal("someone other than the opener read the terminal")
	}
	if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, base+"/resize", f.requester, "a259-k8s-resize", map[string]any{"cols": 120, "rows": 40}); status != http.StatusOK {
		t.Fatalf("resize = %d", status)
	}
	// The kubelet applies a resize apart from the input stream, so the size
	// is asked until the pod's terminal reports it.
	a201Await(t, "the pod's terminal takes the new size", func() bool {
		typeLine("stty size")
		read()
		return strings.Contains(seen.String(), "40 120")
	})
	typeLine("exit 3")
	for deadline := time.Now().Add(60 * time.Second); !closed && time.Now().Before(deadline); {
		read()
	}
	if !closed || exitStatus != 3 {
		t.Fatalf("the exec's end: closed=%v exit status=%d, output %q", closed, exitStatus, seen.String())
	}
	// The session's service-account token (a JWT, "eyJ...") and the cluster
	// credential stay out of everything the browser received: the replies,
	// and the terminal's output decoded (its replies hold only that output
	// and its offsets).
	if text := replies.String() + seen.String(); strings.Contains(text, "eyJ") || strings.Contains(text, c.adminToken) {
		t.Fatalf("a reply to the browser carries a credential: %s", text)
	}
	if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, base+"/input", f.requester, "a259-k8s-after", map[string]any{"data": base64.StdEncoding.EncodeToString([]byte("id\n"))}); status == http.StatusOK {
		t.Fatal("an ended terminal took input")
	}

	// Ending the session seals its recording: the gateway recorded the exec
	// stream the browser worked in, with no credential in it.
	if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+opened.ID+"/terminate", f.operator, "a259-k8s-terminate",
		map[string]any{"reason": "browser exec proof"}); status != http.StatusAccepted {
		t.Fatalf("terminate = %d", status)
	}
	a201Await(t, "the session's service account is deleted", func() bool { return len(c.serviceAccounts()) == 0 })
	a201Await(t, "the Kubernetes recording seals", func() bool {
		status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+opened.ID+"/recording", f.requester, nil)
		return status == http.StatusOK && strings.Contains(string(body), `"status":"sealed"`)
	})
	if status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+opened.ID+"/recording/verify", f.requester, nil); status != http.StatusOK || !strings.Contains(string(body), `"verified":true`) {
		t.Fatalf("verify = %d %s", status, body)
	}
	text := recordingText(t, h, opened.ID)
	if strings.Contains(text, c.adminToken) {
		t.Fatalf("the Kubernetes recording kept the cluster credential:\n%s", text)
	}
	for _, want := range []string{"request: GET /api/v1/namespaces/" + c.namespace + "/pods/shell/exec", "stream websocket v5.channel.k8s.io", "browser-42", "40 120"} {
		if !strings.Contains(text, want) {
			t.Fatalf("the Kubernetes recording lacks %q:\n%s", want, text)
		}
	}
}
