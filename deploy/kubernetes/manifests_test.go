package kubernetes_test

import (
	"bytes"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	kubernetes "trstctl.com/trstctl/deploy/kubernetes"
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

// TestDaemonSetRunsAgentAsServiceAccount: the DaemonSet runs the trstctl-agent
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
	// The agent ships inside the single multi-binary trstctl image and is run by
	// overriding the entrypoint to trstctl-agent (OPS-002: there is no separate,
	// un-built -agent image). So assert on the COMMAND that runs (the behaviour),
	// not on the image name string.
	command := strings.Join(asStringSlice(c["command"]), " ")
	if !strings.Contains(command, "trstctl-agent") {
		t.Errorf("DaemonSet container command = %q, want it to run trstctl-agent", command)
	}
	img, _ := c["image"].(string)
	if !strings.Contains(img, "/trstctl") {
		t.Errorf("container image = %q, want the built multi-binary trstctl image", img)
	}

	// OPS-008 behavioural: every flag the DaemonSet passes to trstctl-agent must be a
	// flag the agent BINARY actually defines (parsed from its --help, not hard-coded),
	// and the agent must be put into --k8s mode. The old test only substring-matched
	// "--k8s" — it could not catch a typo'd or removed flag (the OPS-001 crash-loop
	// class). This binds the manifest to the real binary flag set.
	agentFlags := agentBinaryFlags(t)
	passed := manifestFlagNames(asStringSlice(c["args"]))
	if len(passed) == 0 {
		t.Fatal("DaemonSet passes no flags to trstctl-agent")
	}
	for _, fl := range passed {
		if !agentFlags[fl] {
			t.Errorf("DaemonSet passes --%s to trstctl-agent, which it does not define (real flags: %v) — the OPS-001 crash-loop class", fl, sortedFlagNames(agentFlags))
		}
	}
	if !contains(passed, "k8s") {
		t.Errorf("DaemonSet does not run the agent in --k8s mode (flags=%v)", passed)
	}

	// Mutation proof: an injected undefined flag is rejected; the real --k8s is accepted.
	t.Run("rejects_undefined_agent_flag", func(t *testing.T) {
		bad := manifestFlagNames([]string{"--k8s", "--not-a-real-agent-flag=x"})
		flagged := false
		for _, fl := range bad {
			if !agentFlags[fl] {
				flagged = true
			}
		}
		if !flagged {
			t.Fatal("the flag-vs-binary check failed to flag --not-a-real-agent-flag — it is vacuous")
		}
		if !agentFlags["k8s"] {
			t.Error("the flag-vs-binary check wrongly rejected the real --k8s flag")
		}
	})
}

// agentBinaryFlags parses the trstctl-agent binary's real flag set from its --help
// output (run from the repo root, two levels up from deploy/kubernetes).
func agentBinaryFlags(t *testing.T) map[string]bool {
	t.Helper()
	cmd := exec.Command("go", "run", "./cmd/trstctl-agent", "--help")
	cmd.Dir = filepath.Join("..", "..")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=readonly")
	_ = cmd.Run()
	re := regexp.MustCompile(`(?m)^\s+-([A-Za-z][\w-]*)`)
	flags := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(out.String(), -1) {
		flags[m[1]] = true
	}
	if len(flags) == 0 {
		t.Fatalf("could not parse any flags from `go run ./cmd/trstctl-agent --help`:\n%s", out.String())
	}
	return flags
}

// manifestFlagNames extracts long-flag names (without leading dashes, without
// =value) from a list of arg tokens.
func manifestFlagNames(args []string) []string {
	var out []string
	for _, a := range args {
		a = strings.TrimSpace(a)
		if !strings.HasPrefix(a, "-") {
			continue
		}
		name := strings.TrimLeft(a, "-")
		if i := strings.IndexByte(name, '='); i >= 0 {
			name = name[:i]
		}
		if name != "" {
			out = append(out, name)
		}
	}
	return out
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func sortedFlagNames(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
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
