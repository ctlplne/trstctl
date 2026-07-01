package kubernetes_test

import (
	"bytes"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
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

func TestManifestsDeclareTrstctlIssuerAndCertificateCRDs(t *testing.T) {
	crds := map[string]map[string]any{}
	for _, d := range docs(t) {
		if d["kind"] != "CustomResourceDefinition" {
			continue
		}
		name, _ := nestedString(d, "metadata", "name")
		crds[name] = d
	}
	for _, tc := range []struct {
		name  string
		scope string
		kind  string
	}{
		{name: "issuers.trstctl.com", scope: "Namespaced", kind: "Issuer"},
		{name: "clusterissuers.trstctl.com", scope: "Cluster", kind: "ClusterIssuer"},
		{name: "certificates.trstctl.com", scope: "Namespaced", kind: "Certificate"},
		{name: "trustbundles.trstctl.com", scope: "Cluster", kind: "TrustBundle"},
	} {
		crd := crds[tc.name]
		if crd == nil {
			t.Fatalf("manifests missing %s CRD", tc.name)
		}
		if got, _ := nestedString(crd, "spec", "group"); got != "trstctl.com" {
			t.Errorf("%s group = %q, want trstctl.com", tc.name, got)
		}
		if got, _ := nestedString(crd, "spec", "scope"); got != tc.scope {
			t.Errorf("%s scope = %q, want %s", tc.name, got, tc.scope)
		}
		if got, _ := nestedString(crd, "spec", "names", "kind"); got != tc.kind {
			t.Errorf("%s kind = %q, want %s", tc.name, got, tc.kind)
		}
		versions := asMaps(crd["spec"].(map[string]any)["versions"])
		if len(versions) == 0 {
			t.Fatalf("%s has no served versions", tc.name)
		}
		subresources, _ := versions[0]["subresources"].(map[string]any)
		if _, ok := subresources["status"]; !ok {
			t.Errorf("%s does not enable the status subresource", tc.name)
		}
		if tc.kind == "Certificate" {
			schema := versions[0]["schema"].(map[string]any)
			openapi := schema["openAPIV3Schema"].(map[string]any)
			properties := openapi["properties"].(map[string]any)
			spec := properties["spec"].(map[string]any)
			required := asStringSlice(spec["required"])
			for _, want := range []string{"secretName", "issuerRef"} {
				if !contains(required, want) {
					t.Errorf("%s spec.required missing %q: %v", tc.name, want, required)
				}
			}
		}
		if tc.kind == "TrustBundle" {
			schema := versions[0]["schema"].(map[string]any)
			openapi := schema["openAPIV3Schema"].(map[string]any)
			properties := openapi["properties"].(map[string]any)
			spec := properties["spec"].(map[string]any)
			required := asStringSlice(spec["required"])
			for _, want := range []string{"caBundlePEM", "target"} {
				if !contains(required, want) {
					t.Errorf("%s spec.required missing %q: %v", tc.name, want, required)
				}
			}
		}
	}
}

func TestAgentRBACAllowsNativeKubernetesCSRStatusUpdates(t *testing.T) {
	role := clusterRole(t)
	for _, tc := range []struct {
		group    string
		resource string
		verbs    []string
	}{
		{group: "certificates.k8s.io", resource: "certificatesigningrequests", verbs: []string{"get", "list", "watch"}},
		{group: "certificates.k8s.io", resource: "certificatesigningrequests/status", verbs: []string{"update", "patch"}},
	} {
		if !hasClusterRoleRule(role, tc.group, tc.resource, tc.verbs...) {
			t.Fatalf("ClusterRole missing %s %s verbs %v for CAP-K8S-04 native Kubernetes CSR support", tc.group, tc.resource, tc.verbs)
		}
	}
}

func TestAgentRBACAllowsTrustBundleDistribution(t *testing.T) {
	role := clusterRole(t)
	for _, tc := range []struct {
		group    string
		resource string
		verbs    []string
	}{
		{group: "", resource: "configmaps", verbs: []string{"get", "list", "watch", "create", "update", "patch"}},
		{group: "trstctl.com", resource: "trustbundles", verbs: []string{"get", "list", "watch"}},
		{group: "trstctl.com", resource: "trustbundles/status", verbs: []string{"update", "patch"}},
	} {
		if !hasClusterRoleRule(role, tc.group, tc.resource, tc.verbs...) {
			t.Fatalf("ClusterRole missing %s %s verbs %v for CAP-K8S-07 trust-bundle distribution", tc.group, tc.resource, tc.verbs)
		}
	}
}

// TestDaemonSetRunsAgentAsServiceAccount: the DaemonSet runs the trstctl-agent
// image in --k8s mode under the dedicated service account.
func TestDaemonSetRunsAgentAsServiceAccount(t *testing.T) {
	ds := daemonSet(t)
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

func TestAgentBootstrapManifestWiresTokenAndAgentChannel(t *testing.T) {
	ds := daemonSet(t)
	podSpec := ds["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
	containers, _ := podSpec["containers"].([]any)
	if len(containers) == 0 {
		t.Fatal("DaemonSet has no containers")
	}
	c := containers[0].(map[string]any)
	args := asStringSlice(c["args"])
	for _, want := range []string{
		"--enroll-url=$(TRSTCTL_ENROLL_URL)",
		"--bootstrap-token-file=/var/run/trstctl/bootstrap-token",
		"--ca-bundle=/etc/trstctl/ca-bundle.pem",
		"--server=$(TRSTCTL_SERVER)",
		"--server-name=$(TRSTCTL_SERVER_NAME)",
		"--cert-manager-controller",
		"--bridge-signer-url=$(TRSTCTL_BRIDGE_SIGNER_URL)",
		"--bridge-signer-token-file=/var/run/trstctl/cert-manager/token",
	} {
		if !contains(args, want) {
			t.Errorf("DaemonSet args missing %q; got %v", want, args)
		}
	}

	env := envValues(c["env"])
	if got := env["TRSTCTL_ENROLL_URL"]; got != "https://trstctl:8443" {
		t.Errorf("TRSTCTL_ENROLL_URL = %q, want control-plane base URL without duplicated /enroll", got)
	}
	if got := env["TRSTCTL_SERVER"]; got != "trstctl:9443" {
		t.Errorf("TRSTCTL_SERVER = %q, want agent-channel service endpoint", got)
	}
	if got := env["TRSTCTL_SERVER_NAME"]; got != "trstctl" {
		t.Errorf("TRSTCTL_SERVER_NAME = %q, want DNS SAN configured on Helm agentChannel.serverName", got)
	}
	if !hasEnvFromSecret(c, "TRSTCTL_BRIDGE_SIGNER_URL", "trstctl-cert-manager-issuer", "signer-url") {
		t.Fatal("DaemonSet must read TRSTCTL_BRIDGE_SIGNER_URL from Secret trstctl-cert-manager-issuer/signer-url")
	}

	if !hasVolumeMountSubPath(c, "bootstrap-token", "/var/run/trstctl/bootstrap-token", "$(NODE_NAME)") {
		t.Fatal("DaemonSet must mount only the NODE_NAME key from Secret trstctl-agent-bootstrap as /var/run/trstctl/bootstrap-token")
	}
	if !hasVolumeMount(c, "cert-manager-issuer", "/var/run/trstctl/cert-manager") {
		t.Fatal("DaemonSet does not mount the cert-manager signer token Secret at /var/run/trstctl/cert-manager")
	}
	if !hasSecretVolumeAllKeys(podSpec, "bootstrap-token", "trstctl-agent-bootstrap") {
		t.Fatal("DaemonSet must mount every key from Secret trstctl-agent-bootstrap so each node reads its own node-named token file")
	}
	if !hasSecretVolume(podSpec, "cert-manager-issuer", "trstctl-cert-manager-issuer", "token") {
		t.Fatal("DaemonSet does not source /var/run/trstctl/cert-manager/token from Secret trstctl-cert-manager-issuer/token")
	}
	if !hasConfigMapVolume(podSpec, "ca-bundle", "trstctl-ca-bundle", false) {
		t.Fatal("DaemonSet must require ConfigMap trstctl-ca-bundle so bootstrap HTTPS is CA-pinned before the token is posted")
	}
}

func TestAgentBootstrapManifestUsesNodeSpecificTokenFile(t *testing.T) {
	ds := daemonSet(t)
	podSpec := ds["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
	containers, _ := podSpec["containers"].([]any)
	if len(containers) == 0 {
		t.Fatal("DaemonSet has no containers")
	}
	c := containers[0].(map[string]any)
	args := asStringSlice(c["args"])
	if contains(args, "--bootstrap-token-file=/var/run/trstctl/bootstrap/token") {
		t.Fatalf("DaemonSet still points every pod at one shared single-use token file: %v", args)
	}
	if !contains(args, "--bootstrap-token-file=/var/run/trstctl/bootstrap-token") {
		t.Fatalf("DaemonSet must read the bootstrap token from the node-specific Secret subPath mount; got %v", args)
	}
	if !hasEnvFieldRef(c, "NODE_NAME", "spec.nodeName") {
		t.Fatal("DaemonSet must populate NODE_NAME from spec.nodeName before expanding the token-file path")
	}
	if !hasVolumeMountSubPath(c, "bootstrap-token", "/var/run/trstctl/bootstrap-token", "$(NODE_NAME)") {
		t.Fatal("DaemonSet bootstrap-token mount must use subPathExpr=$(NODE_NAME) so each pod sees only its node's token file")
	}
	if !hasSecretVolumeAllKeys(podSpec, "bootstrap-token", "trstctl-agent-bootstrap") {
		t.Fatal("DaemonSet bootstrap-token volume must expose all Secret keys, not remap one shared key named token")
	}
}

func TestDaemonSetIdentityPersistsAcrossPodReschedule(t *testing.T) {
	ds := daemonSet(t)
	podSpec := ds["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
	containers, _ := podSpec["containers"].([]any)
	if len(containers) == 0 {
		t.Fatal("DaemonSet has no containers")
	}
	c := containers[0].(map[string]any)
	args := asStringSlice(c["args"])
	const (
		identityVolume = "identity"
		identityDir    = "/var/lib/trstctl-agent"
		keyPath        = identityDir + "/agent.key"
		certPath       = identityDir + "/agent.crt"
	)
	for _, want := range []string{
		"--key=" + keyPath,
		"--cert=" + certPath,
	} {
		if !contains(args, want) {
			t.Fatalf("DaemonSet args missing persistent identity path %q; got %v", want, args)
		}
	}
	for _, bad := range []string{"--key=agent.key", "--cert=agent.crt"} {
		if contains(args, bad) {
			t.Fatalf("DaemonSet still uses relative identity path %q on a read-only root filesystem", bad)
		}
	}

	if !hasWritableVolumeMount(c, identityVolume, identityDir) {
		t.Fatalf("DaemonSet must mount a writable identity volume named %q at %s", identityVolume, identityDir)
	}
	if !hasHostPathVolume(podSpec, identityVolume, identityDir, "DirectoryOrCreate") {
		t.Fatalf("DaemonSet identity volume %q must be a hostPath %s DirectoryOrCreate so pod replacement does not force re-enrollment", identityVolume, identityDir)
	}
	if !hasIdentityPrepInitContainer(podSpec, identityVolume, identityDir, 65532, 65532) {
		t.Fatalf("DaemonSet must prepare the hostPath identity directory for uid/gid 65532 before the non-root agent starts")
	}
	if got, ok := nestedBool(c, "securityContext", "readOnlyRootFilesystem"); !ok || !got {
		t.Fatalf("agent container must keep readOnlyRootFilesystem=true; identity persistence belongs on the writable volume")
	}
	for _, tc := range []struct {
		key  string
		want int
	}{
		{key: "runAsUser", want: 65532},
		{key: "runAsGroup", want: 65532},
		{key: "fsGroup", want: 65532},
	} {
		got, ok := nestedInt(podSpec, "securityContext", tc.key)
		if !ok || got != tc.want {
			t.Fatalf("DaemonSet pod securityContext.%s = %d (present=%v), want %d so the non-root agent can write identity files", tc.key, got, ok, tc.want)
		}
	}
}

func TestAgentDaemonSetRequiresRenderedReleaseDigest(t *testing.T) {
	ds := daemonSet(t)
	podSpec := ds["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
	containers, _ := podSpec["containers"].([]any)
	if len(containers) == 0 {
		t.Fatal("DaemonSet has no containers")
	}
	c := containers[0].(map[string]any)
	image, _ := c["image"].(string)
	if image == "" {
		t.Fatal("DaemonSet agent container has no image")
	}
	zeroDigest := "sha256:" + strings.Repeat("0", 64)
	if strings.Contains(image, zeroDigest) {
		t.Fatalf("DaemonSet still carries the all-zero image digest placeholder; render it with a release digest before apply")
	}
	validReleaseImage := regexp.MustCompile(`^[a-z0-9./:_-]+/trstctl@sha256:[0-9a-f]{64}$`)
	if validReleaseImage.MatchString(image) {
		return
	}
	if image != "ghcr.io/ctlplne/trstctl@sha256:RELEASE_DIGEST_REQUIRED" {
		t.Fatalf("DaemonSet image = %q, want a real release digest or the required-digest template marker", image)
	}
}

func TestRenderAgentDaemonSetRequiresImmutableDigest(t *testing.T) {
	root := filepath.Join("..", "..")
	script := filepath.Join("scripts", "release", "render-kubernetes-agent-daemonset.sh")
	goodImage := "ghcr.io/ctlplne/trstctl@sha256:" + strings.Repeat("1", 64)
	cmd := exec.Command("bash", script, goodImage)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("render agent daemonset with digest: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "image: "+goodImage) {
		t.Fatalf("rendered DaemonSet did not contain the requested digest image %q:\n%s", goodImage, out)
	}
	if strings.Contains(string(out), "RELEASE_DIGEST_REQUIRED") {
		t.Fatalf("rendered DaemonSet still contains the digest marker:\n%s", out)
	}

	for _, bad := range []string{
		"ghcr.io/ctlplne/trstctl:latest",
		"ghcr.io/ctlplne/trstctl@sha256:" + strings.Repeat("0", 64),
		"ghcr.io/ctlplne/trstctl@sha256:abc",
	} {
		cmd := exec.Command("bash", script, bad)
		cmd.Dir = root
		if out, err := cmd.CombinedOutput(); err == nil {
			t.Fatalf("render accepted invalid image %q; output:\n%s", bad, out)
		}
	}
}

func TestAgentBootstrapDocsMintSecretAndEnableChannel(t *testing.T) {
	body, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(body)
	flatDoc := strings.Join(strings.Fields(doc), " ")
	for _, want := range []string{
		"trstctl-cli agents enroll-token",
		"create secret generic trstctl-agent-bootstrap",
		"--from-file=\"$bootstrap_token_dir\"",
		"subPathExpr: $(NODE_NAME)",
		"agentChannel.enabled=true",
		"agentChannel.serverName=trstctl",
		"TRSTCTL_AGENT_IMAGE",
		"scripts/release/render-kubernetes-agent-daemonset.sh",
		"kubectl apply -f \"$rendered_agent_daemonset\"",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("deploy/kubernetes/README.md missing runnable bootstrap marker %q", want)
		}
	}
	if !strings.Contains(flatDoc, "one key per node") {
		t.Error("deploy/kubernetes/README.md must say the bootstrap Secret has one key per node")
	}
	if strings.Contains(doc, "kubectl apply -f deploy/kubernetes/daemonset.yaml") {
		t.Error("deploy/kubernetes/README.md still applies the raw digest-template DaemonSet instead of the rendered release manifest")
	}
	if strings.Contains(doc, "--from-literal=token=\"$TOKEN\"") {
		t.Error("deploy/kubernetes/README.md still creates one shared single-use bootstrap token for the whole DaemonSet")
	}
}

func TestAgentDaemonSetRenderPathIsWiredIntoCIAndRelease(t *testing.T) {
	root := filepath.Join("..", "..")
	ci, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Validate packaged agent DaemonSet apply path",
		"scripts/release/render-kubernetes-agent-daemonset.sh",
		"kubectl apply --dry-run=server -f \"$rendered_agent_daemonset\"",
		"trstctl-agent-bootstrap",
		"trstctl-cert-manager-issuer",
		"trstctl-ca-bundle",
	} {
		if !strings.Contains(string(ci), want) {
			t.Errorf("ci.yml missing Kubernetes agent apply-path guard marker %q", want)
		}
	}

	release, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Render Kubernetes agent DaemonSet manifest",
		"${GHCR_IMAGE}@${{ steps.build.outputs.digest }}",
		"name: trstctl-agent-kubernetes",
		"dist/kubernetes/trstctl-agent-daemonset.yaml",
	} {
		if !strings.Contains(string(release), want) {
			t.Errorf("release.yml missing Kubernetes agent release-manifest marker %q", want)
		}
	}
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

func daemonSet(t *testing.T) map[string]any {
	t.Helper()
	for _, d := range docs(t) {
		if d["kind"] == "DaemonSet" {
			return d
		}
	}
	t.Fatal("no DaemonSet found")
	return nil
}

func clusterRole(t *testing.T) map[string]any {
	t.Helper()
	for _, d := range docs(t) {
		if d["kind"] == "ClusterRole" {
			return d
		}
	}
	t.Fatal("no ClusterRole found")
	return nil
}

func hasClusterRoleRule(role map[string]any, group, resource string, verbs ...string) bool {
	for _, rule := range asMaps(role["rules"]) {
		if !contains(asStringSlice(rule["apiGroups"]), group) || !contains(asStringSlice(rule["resources"]), resource) {
			continue
		}
		gotVerbs := asStringSlice(rule["verbs"])
		all := true
		for _, verb := range verbs {
			if !contains(gotVerbs, verb) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
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

func envValues(v any) map[string]string {
	out := map[string]string{}
	for _, raw := range asMaps(v) {
		name, _ := raw["name"].(string)
		value, _ := raw["value"].(string)
		if name != "" {
			out[name] = value
		}
	}
	return out
}

func hasVolumeMount(container map[string]any, name, path string) bool {
	for _, m := range asMaps(container["volumeMounts"]) {
		gotName, _ := m["name"].(string)
		gotPath, _ := m["mountPath"].(string)
		if gotName == name && gotPath == path {
			return true
		}
	}
	return false
}

func hasVolumeMountSubPath(container map[string]any, name, path, subPathExpr string) bool {
	for _, m := range asMaps(container["volumeMounts"]) {
		gotName, _ := m["name"].(string)
		gotPath, _ := m["mountPath"].(string)
		gotSubPathExpr, _ := m["subPathExpr"].(string)
		if gotName == name && gotPath == path && gotSubPathExpr == subPathExpr {
			return true
		}
	}
	return false
}

func hasWritableVolumeMount(container map[string]any, name, path string) bool {
	for _, m := range asMaps(container["volumeMounts"]) {
		gotName, _ := m["name"].(string)
		gotPath, _ := m["mountPath"].(string)
		if gotName != name || gotPath != path {
			continue
		}
		readOnly, hasReadOnly := m["readOnly"].(bool)
		return !hasReadOnly || !readOnly
	}
	return false
}

func hasSecretVolume(podSpec map[string]any, name, secretName, key string) bool {
	for _, v := range asMaps(podSpec["volumes"]) {
		if gotName, _ := v["name"].(string); gotName != name {
			continue
		}
		secret, _ := v["secret"].(map[string]any)
		if gotSecret, _ := secret["secretName"].(string); gotSecret != secretName {
			return false
		}
		for _, item := range asMaps(secret["items"]) {
			if gotKey, _ := item["key"].(string); gotKey == key {
				return true
			}
		}
	}
	return false
}

func hasSecretVolumeAllKeys(podSpec map[string]any, name, secretName string) bool {
	for _, v := range asMaps(podSpec["volumes"]) {
		if gotName, _ := v["name"].(string); gotName != name {
			continue
		}
		secret, _ := v["secret"].(map[string]any)
		if gotSecret, _ := secret["secretName"].(string); gotSecret != secretName {
			return false
		}
		_, hasItems := secret["items"]
		return !hasItems
	}
	return false
}

func hasHostPathVolume(podSpec map[string]any, name, path, typ string) bool {
	for _, v := range asMaps(podSpec["volumes"]) {
		if gotName, _ := v["name"].(string); gotName != name {
			continue
		}
		hostPath, _ := v["hostPath"].(map[string]any)
		gotPath, _ := hostPath["path"].(string)
		gotType, _ := hostPath["type"].(string)
		return gotPath == path && gotType == typ
	}
	return false
}

func hasIdentityPrepInitContainer(podSpec map[string]any, volumeName, dir string, uid, gid int) bool {
	for _, c := range asMaps(podSpec["initContainers"]) {
		if gotName, _ := c["name"].(string); gotName != "prepare-identity" {
			continue
		}
		command := asStringSlice(c["command"])
		args := asStringSlice(c["args"])
		if !contains(command, "/usr/local/bin/trstctl-agent") {
			return false
		}
		for _, want := range []string{
			"--prepare-identity-dir=" + dir,
			"--prepare-identity-uid=" + strconv.Itoa(uid),
			"--prepare-identity-gid=" + strconv.Itoa(gid),
		} {
			if !contains(args, want) {
				return false
			}
		}
		if !hasWritableVolumeMount(c, volumeName, dir) {
			return false
		}
		if got, ok := nestedInt(c, "securityContext", "runAsUser"); !ok || got != 0 {
			return false
		}
		if got, ok := nestedBool(c, "securityContext", "allowPrivilegeEscalation"); !ok || got {
			return false
		}
		sc, _ := c["securityContext"].(map[string]any)
		caps, _ := sc["capabilities"].(map[string]any)
		if !contains(asStringSlice(caps["drop"]), "ALL") || !contains(asStringSlice(caps["add"]), "CHOWN") {
			return false
		}
		return true
	}
	return false
}

func hasConfigMapVolume(podSpec map[string]any, name, configMapName string, optional bool) bool {
	for _, v := range asMaps(podSpec["volumes"]) {
		if gotName, _ := v["name"].(string); gotName != name {
			continue
		}
		configMap, _ := v["configMap"].(map[string]any)
		if gotName, _ := configMap["name"].(string); gotName != configMapName {
			return false
		}
		gotOptional, hasOptional := configMap["optional"].(bool)
		if !optional && !hasOptional {
			return true
		}
		return gotOptional == optional
	}
	return false
}

func hasEnvFromSecret(container map[string]any, envName, secretName, key string) bool {
	for _, env := range asMaps(container["env"]) {
		if got, _ := env["name"].(string); got != envName {
			continue
		}
		valueFrom, _ := env["valueFrom"].(map[string]any)
		secretKeyRef, _ := valueFrom["secretKeyRef"].(map[string]any)
		return secretKeyRef["name"] == secretName && secretKeyRef["key"] == key
	}
	return false
}

func hasEnvFieldRef(container map[string]any, envName, fieldPath string) bool {
	for _, env := range asMaps(container["env"]) {
		if got, _ := env["name"].(string); got != envName {
			continue
		}
		valueFrom, _ := env["valueFrom"].(map[string]any)
		fieldRef, _ := valueFrom["fieldRef"].(map[string]any)
		return fieldRef["fieldPath"] == fieldPath
	}
	return false
}

func nestedBool(m map[string]any, keys ...string) (bool, bool) {
	cur := m
	for i, k := range keys {
		if i == len(keys)-1 {
			b, ok := cur[k].(bool)
			return b, ok
		}
		next, ok := cur[k].(map[string]any)
		if !ok {
			return false, false
		}
		cur = next
	}
	return false, false
}

func nestedInt(m map[string]any, keys ...string) (int, bool) {
	cur := m
	for i, k := range keys {
		if i == len(keys)-1 {
			switch v := cur[k].(type) {
			case int:
				return v, true
			case int64:
				return int(v), true
			case float64:
				return int(v), true
			}
			return 0, false
		}
		next, ok := cur[k].(map[string]any)
		if !ok {
			return 0, false
		}
		cur = next
	}
	return 0, false
}

func nestedString(m map[string]any, keys ...string) (string, bool) {
	cur := m
	for i, k := range keys {
		if i == len(keys)-1 {
			s, ok := cur[k].(string)
			return s, ok
		}
		next, ok := cur[k].(map[string]any)
		if !ok {
			return "", false
		}
		cur = next
	}
	return "", false
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

func asMaps(v any) []map[string]any {
	raw, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(raw))
	for _, e := range raw {
		if m, ok := e.(map[string]any); ok {
			out = append(out, m)
		}
	}
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
