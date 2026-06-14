package kubernetes_test

import (
	"bytes"
	"io/fs"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	kubernetes "trustctl.io/trustctl/deploy/kubernetes"
)

// docs parses every embedded manifest into individual YAML documents.
func docs(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	entries, err := fs.Glob(kubernetes.Manifests, "*.yaml")
	if err != nil || len(entries) == 0 {
		t.Fatalf("no embedded manifests (err=%v)", err)
	}
	for _, name := range entries {
		raw, err := kubernetes.Manifests.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		dec := yaml.NewDecoder(bytes.NewReader(raw))
		for {
			var d map[string]any
			err := dec.Decode(&d)
			if err != nil {
				break
			}
			if len(d) == 0 {
				continue
			}
			out = append(out, d)
		}
	}
	return out
}

// TestManifestsAreWellFormedKubernetesObjects: every document parses and has an
// apiVersion and kind.
func TestManifestsAreWellFormedKubernetesObjects(t *testing.T) {
	for i, d := range docs(t) {
		if d["apiVersion"] == nil || d["kind"] == nil {
			t.Errorf("document %d missing apiVersion/kind: %v", i, d)
		}
	}
}

// TestManifestsDeclareTheDaemonSetAndItsRBAC: the bundle includes a Namespace, a
// ServiceAccount, an RBAC role + binding, and the DaemonSet — everything needed
// to run the agent on every node with permission to write secrets and reconcile
// cert-manager requests.
func TestManifestsDeclareTheDaemonSetAndItsRBAC(t *testing.T) {
	kinds := map[string]bool{}
	for _, d := range docs(t) {
		kinds[d["kind"].(string)] = true
	}
	for _, want := range []string{"Namespace", "ServiceAccount", "DaemonSet"} {
		if !kinds[want] {
			t.Errorf("manifests missing a %s", want)
		}
	}
	if !kinds["ClusterRole"] && !kinds["Role"] {
		t.Error("manifests declare no (Cluster)Role for the agent")
	}
	if !kinds["ClusterRoleBinding"] && !kinds["RoleBinding"] {
		t.Error("manifests declare no (Cluster)RoleBinding for the agent")
	}
}

// TestDaemonSetRunsAgentAsServiceAccount: the DaemonSet runs the trustctl-agent
// image in --k8s mode under the dedicated service account.
func TestDaemonSetRunsAgentAsServiceAccount(t *testing.T) {
	var ds map[string]any
	for _, d := range docs(t) {
		if d["kind"] == "DaemonSet" {
			ds = d
		}
	}
	if ds == nil {
		t.Fatal("no DaemonSet found")
	}
	podSpec := ds["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
	if podSpec["serviceAccountName"] == nil || podSpec["serviceAccountName"] == "" {
		t.Error("DaemonSet pod does not run under a serviceAccountName")
	}
	containers, ok := podSpec["containers"].([]any)
	if !ok || len(containers) == 0 {
		t.Fatal("DaemonSet has no containers")
	}
	c := containers[0].(map[string]any)
	// The agent ships inside the single multi-binary trustctl image and is run by
	// overriding the entrypoint to trustctl-agent (OPS-002: there is no separate,
	// un-built -agent image). So assert on the COMMAND that runs (the behaviour),
	// not on the image name string.
	command := strings.Join(asStringSlice(c["command"]), " ")
	if !strings.Contains(command, "trustctl-agent") {
		t.Errorf("DaemonSet container command = %q, want it to run trustctl-agent", command)
	}
	img, _ := c["image"].(string)
	if !strings.Contains(img, "/trustctl") {
		t.Errorf("container image = %q, want the built multi-binary trustctl image", img)
	}
	args := command + " "
	for _, a := range asStringSlice(c["args"]) {
		args += a + " "
	}
	if !strings.Contains(args, "--k8s") {
		t.Errorf("DaemonSet does not run the agent in --k8s mode (args=%q)", args)
	}
}

func asStringSlice(v any) []string {
	raw, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, e := range raw {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
