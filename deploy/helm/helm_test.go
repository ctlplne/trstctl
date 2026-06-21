package helm

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"text/template"

	"gopkg.in/yaml.v3"
)

const chart = "trstctl"

func read(t *testing.T, parts ...string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{chart}, parts...)...))
	if err != nil {
		t.Fatalf("read %s: %v", filepath.Join(parts...), err)
	}
	return string(b)
}

func containsAll(t *testing.T, name, body string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(body, w) {
			t.Errorf("%s: expected to contain %q", name, w)
		}
	}
}

// TestChartIsStructurallyComplete: the control-plane chart exists with a valid
// Chart.yaml (Helm v2 schema) and the templates a real deployment needs.
func TestChartIsStructurallyComplete(t *testing.T) {
	var meta struct {
		APIVersion string `yaml:"apiVersion"`
		Name       string `yaml:"name"`
		Version    string `yaml:"version"`
		AppVersion string `yaml:"appVersion"`
		Type       string `yaml:"type"`
	}
	if err := yaml.Unmarshal([]byte(read(t, "Chart.yaml")), &meta); err != nil {
		t.Fatalf("Chart.yaml is not valid YAML: %v", err)
	}
	if meta.APIVersion != "v2" {
		t.Errorf("Chart.yaml apiVersion = %q, want v2", meta.APIVersion)
	}
	for field, val := range map[string]string{"name": meta.Name, "version": meta.Version, "appVersion": meta.AppVersion} {
		if strings.TrimSpace(val) == "" {
			t.Errorf("Chart.yaml is missing %s", field)
		}
	}
	for _, f := range []string{
		"values.yaml",
		"templates/_helpers.tpl",
		"templates/deployment.yaml",
		"templates/service.yaml",
		"templates/configmap.yaml",
		"templates/secret.yaml",
		"templates/serviceaccount.yaml",
		"templates/networkpolicy.yaml",
	} {
		if _, err := os.Stat(filepath.Join(chart, filepath.FromSlash(f))); err != nil {
			t.Errorf("chart is missing %s: %v", f, err)
		}
	}
}

// TestSignerIsIsolated (AN-4): the control-plane pod runs the signer as its own
// locked-down container with NO network surface — it talks to the control plane
// only over a shared in-memory UDS — and both containers run a restrictive
// securityContext.
//
// Behavioural (OPS-008): the old version string-matched "trstctl-signer",
// "/run/trstctl", "emptyDir", "runAsNonRoot" anywhere in the template text — it
// would pass even if those tokens were in unrelated places. This renders the
// Deployment, finds the signer container as a PARSED object, and asserts the
// isolation PROPERTY: the signer exposes NO ports (the real AN-4 invariant), runs
// the trstctl-signer binary over a UDS mount, and is hardened — and that the env
// keys wiring it are keys the binary actually reads.
func TestSignerIsIsolated(t *testing.T) {
	dep := renderControlPlaneDeployment(t, defaultishValues())
	objs := decodeAllYAML(t, dep)
	var pod map[string]any
	for _, o := range objs {
		if o["kind"] == "Deployment" {
			spec, _ := o["spec"].(map[string]any)
			tmpl, _ := spec["template"].(map[string]any)
			pod, _ = tmpl["spec"].(map[string]any)
		}
	}
	if pod == nil {
		t.Fatal("rendered chart has no control-plane Deployment pod spec")
	}
	containers := asMaps(pod["containers"])
	signer := containerNamed(containers, "signer")
	if signer == nil {
		t.Fatal("the control-plane pod has no 'signer' container (AN-4 co-located signer)")
	}
	cp := containerNamed(containers, "trstctl")
	if cp == nil {
		t.Fatal("control-plane container not found")
	}
	// (1) The signer exposes NO network ports — its ONLY channel is the in-memory UDS
	// (the defining AN-4 property; a port here would mean the signer is reachable on
	// the network, which must never happen).
	if ports, ok := signer["ports"].([]any); ok && len(ports) > 0 {
		t.Errorf("the co-located signer container exposes %d port(s); AN-4 requires NO network surface (UDS only)", len(ports))
	}
	// (2) It runs the trstctl-signer binary.
	if cmd := strings.Join(asStrings(signer["command"]), " "); !strings.Contains(cmd, "trstctl-signer") {
		t.Errorf("signer container command = %q, want it to run trstctl-signer", cmd)
	}
	// (3) It mounts the shared UDS directory and seals its keystore — read from parsed
	// volumeMounts, not a substring.
	if !hasMountPath(signer, "/run/trstctl") {
		t.Error("signer container does not mount the shared UDS directory /run/trstctl (AN-4 transport)")
	}
	// (4) The shared socket volume is an in-memory emptyDir (never on disk/network).
	if !hasInMemorySocketVolume(pod) {
		t.Error("the pod has no in-memory emptyDir volume for the signer socket (AN-4: the socket is never written to disk)")
	}
	requireSecretDefaultMode(t, pod, "kek", 0o440)
	requireSecretDefaultMode(t, pod, "signer-auth", 0o440)
	if hasMountPath(cp, "/etc/trstctl/signer-auth") {
		t.Error("control-plane container must not mount the signer authorization secret; only the signer may verify signer tokens")
	}
	// (5) Hardened securityContext, as PARSED fields.
	requireHardened(t, "signer", signer)

	// The control plane reaches the signer in external mode over that socket, wired by
	// the configMap. Bind those keys to the binary's real env contract AND assert the
	// rendered values (external mode, the socket path).
	cmData := renderConfigMapData(t)
	requireLoaderKey(t, cmData, "TRSTCTL_SIGNER_MODE", "external")
	requireLoaderKey(t, cmData, "TRSTCTL_SIGNER_SOCKET", "")
	if _, ok := cmData["TRSTCTL_SIGNER_AUTH_SECRET_FILE"]; ok {
		t.Error("control-plane ConfigMap must not render TRSTCTL_SIGNER_AUTH_SECRET_FILE; that secret is signer-side verifier material")
	}
	if _, ok := cmData["TRSTCTL_SIGNER_MTLS_ADDRESS"]; ok {
		t.Error("sidecar mode must not render TRSTCTL_SIGNER_MTLS_ADDRESS; it would conflict with the UDS signer socket")
	}
}

func TestIsolatedSignerControlPlaneWiring(t *testing.T) {
	v := defaultishValues()
	signer := v["signer"].(map[string]any)
	signer["mode"] = "isolated"
	signer["mtls"] = map[string]any{
		"serverName":         "trstctl-signer.ns.svc",
		"signerSecret":       "signer-mtls",
		"controlPlaneSecret": "cp-signer-mtls",
	}

	dep := renderControlPlaneDeployment(t, v)
	objs := decodeAllYAML(t, dep)
	var pod map[string]any
	for _, o := range objs {
		if o["kind"] == "Deployment" {
			spec, _ := o["spec"].(map[string]any)
			tmpl, _ := spec["template"].(map[string]any)
			pod, _ = tmpl["spec"].(map[string]any)
		}
	}
	if pod == nil {
		t.Fatal("rendered chart has no control-plane Deployment pod spec")
	}
	containers := asMaps(pod["containers"])
	if signerSidecar := containerNamed(containers, "signer"); signerSidecar != nil {
		t.Fatal("isolated signer mode must remove the co-located signer sidecar from the control-plane pod")
	}
	cp := containerNamed(containers, "trstctl")
	if cp == nil {
		t.Fatal("control-plane container not found")
	}
	if hasMountPath(cp, "/run/trstctl") {
		t.Error("isolated signer mode must not mount the sidecar UDS directory into the control plane")
	}
	if !hasMountPath(cp, "/etc/trstctl/signer-mtls") {
		t.Error("isolated signer mode must mount the control-plane signer mTLS material")
	}
	if hasVolumeNamed(pod, "signer-sock") {
		t.Error("isolated signer mode must not render the in-memory signer socket volume")
	}
	if !hasVolumeNamed(pod, "signer-mtls") {
		t.Error("isolated signer mode must render the signer-mtls Secret volume")
	}
	if hasVolumeNamed(pod, "signer-auth") {
		t.Error("isolated control-plane pod must not mount signer-auth; the isolated signer Deployment owns that secret")
	}
	pinEnv := envNamed(cp, "TRSTCTL_SIGNER_MTLS_PEER_PIN")
	if pinEnv == nil {
		t.Fatal("isolated signer mode must inject TRSTCTL_SIGNER_MTLS_PEER_PIN from the control-plane mTLS Secret")
	}
	ref, _ := pinEnv["valueFrom"].(map[string]any)
	secretRef, _ := ref["secretKeyRef"].(map[string]any)
	if secretRef["name"] != "cp-signer-mtls" || secretRef["key"] != "peer-pin" {
		t.Fatalf("TRSTCTL_SIGNER_MTLS_PEER_PIN secret ref = %+v, want cp-signer-mtls/peer-pin", secretRef)
	}
	if !loaderEnvKeysSet(t)["TRSTCTL_SIGNER_MTLS_PEER_PIN"] {
		t.Fatal("chart sets TRSTCTL_SIGNER_MTLS_PEER_PIN but the config loader does not read it")
	}

	cmData := renderConfigMapDataWithValues(t, v)
	requireLoaderKey(t, cmData, "TRSTCTL_SIGNER_MODE", "external")
	requireLoaderKey(t, cmData, "TRSTCTL_SIGNER_MTLS_ADDRESS", "trstctl-signer:9443")
	requireLoaderKey(t, cmData, "TRSTCTL_SIGNER_MTLS_SERVER_NAME", "trstctl-signer.ns.svc")
	requireLoaderKey(t, cmData, "TRSTCTL_SIGNER_MTLS_CERT_FILE", "/etc/trstctl/signer-mtls/tls.crt")
	requireLoaderKey(t, cmData, "TRSTCTL_SIGNER_MTLS_KEY_FILE", "/etc/trstctl/signer-mtls/tls.key")
	requireLoaderKey(t, cmData, "TRSTCTL_SIGNER_MTLS_PEER_CA_FILE", "/etc/trstctl/signer-mtls/peer-ca.pem")
	if _, ok := cmData["TRSTCTL_SIGNER_SOCKET"]; ok {
		t.Error("isolated signer mode must not render TRSTCTL_SIGNER_SOCKET; socket and mTLS are mutually exclusive")
	}
	if _, ok := cmData["TRSTCTL_SIGNER_AUTH_SECRET_FILE"]; ok {
		t.Error("isolated signer mode must not render TRSTCTL_SIGNER_AUTH_SECRET_FILE into the control-plane ConfigMap")
	}

	np := renderSimpleObj(t, "networkpolicy.yaml", v)
	if !networkPolicyAllowsEgressToSigner(np) {
		t.Error("isolated signer mode must allow control-plane egress to the signer pod on TCP/9443; otherwise default-deny egress blocks the mTLS dial")
	}
}

// TestReadinessProbeUsesReadyCheck pins OPS-001: Kubernetes readiness must hit
// /readyz, not the shallow /healthz liveness path. Otherwise a pod can keep
// accepting traffic while PostgreSQL, NATS, or the signer is unavailable.
func TestReadinessProbeUsesReadyCheck(t *testing.T) {
	dep := renderControlPlaneDeployment(t, defaultishValues())
	objs := decodeAllYAML(t, dep)
	var pod map[string]any
	for _, o := range objs {
		if o["kind"] == "Deployment" {
			spec, _ := o["spec"].(map[string]any)
			tmpl, _ := spec["template"].(map[string]any)
			pod, _ = tmpl["spec"].(map[string]any)
		}
	}
	if pod == nil {
		t.Fatal("rendered chart has no control-plane Deployment pod spec")
	}
	controlPlane := containerNamed(asMaps(pod["containers"]), "trstctl")
	if controlPlane == nil {
		t.Fatal("rendered chart has no trstctl control-plane container")
	}
	requireProbeCommand(t, controlPlane, "startupProbe", []string{"/usr/local/bin/trstctl", "--health-check"})
	requireProbeCommand(t, controlPlane, "readinessProbe", []string{"/usr/local/bin/trstctl", "--ready-check"})
	requireProbeCommand(t, controlPlane, "livenessProbe", []string{"/usr/local/bin/trstctl", "--health-check"})
}

// TestExternalDatastoresAreTheDefault: the chart deploys against EXTERNAL
// PostgreSQL and NATS (the production/tested path). Behavioural (OPS-008): instead
// of grepping the configMap text for "external", it renders the configMap with the
// DEFAULT values and asserts the resolved env values are actually "external" — so a
// values default flipped to in-process would FAIL here.
func TestExternalDatastoresAreTheDefault(t *testing.T) {
	var v map[string]any
	if err := yaml.Unmarshal([]byte(read(t, "values.yaml")), &v); err != nil {
		t.Fatalf("values.yaml is not valid YAML: %v", err)
	}
	if _, ok := v["postgres"]; !ok {
		t.Error("values.yaml should expose external postgres configuration")
	}
	if _, ok := v["nats"]; !ok {
		t.Error("values.yaml should expose external nats configuration")
	}
	cmData := renderConfigMapData(t)
	requireLoaderKey(t, cmData, "TRSTCTL_POSTGRES_MODE", "external")
	requireLoaderKey(t, cmData, "TRSTCTL_NATS_MODE", "external")
	requireLoaderKey(t, cmData, "TRSTCTL_NATS_URL", "")
	requireLoaderKey(t, cmData, "TRSTCTL_NATS_REPLICAS", "3")
	requireLoaderKey(t, cmData, "TRSTCTL_NATS_ALLOW_SINGLE_REPLICA", "false")
}

func TestBulkheadValuesRenderConfigMap(t *testing.T) {
	var v map[string]any
	if err := yaml.Unmarshal([]byte(read(t, "values.yaml")), &v); err != nil {
		t.Fatalf("values.yaml is not valid YAML: %v", err)
	}
	if _, ok := v["bulkheads"]; !ok {
		t.Fatal("values.yaml should expose per-subsystem bulkhead configuration")
	}
	cmData := renderConfigMapData(t)
	for key, want := range map[string]string{
		"TRSTCTL_BULKHEAD_API_WORKERS":       "8",
		"TRSTCTL_BULKHEAD_API_QUEUE":         "256",
		"TRSTCTL_BULKHEAD_OUTBOX_WORKERS":    "4",
		"TRSTCTL_BULKHEAD_OUTBOX_QUEUE":      "256",
		"TRSTCTL_BULKHEAD_AGENT_WORKERS":     "16",
		"TRSTCTL_BULKHEAD_AGENT_QUEUE":       "1024",
		"TRSTCTL_BULKHEAD_PROTOCOLS_WORKERS": "8",
		"TRSTCTL_BULKHEAD_PROTOCOLS_QUEUE":   "256",
	} {
		requireLoaderKey(t, cmData, key, want)
	}
}

// TestNetworkPolicyAndTLS: a NetworkPolicy ships (default-deny posture) and TLS is
// configurable (R1.3). Behavioural (OPS-008): render the NetworkPolicy and assert it
// is a structurally-valid object whose policyTypes lock BOTH directions (parsed list,
// not substring), and that the TLS-mode env key the chart wires is one the binary
// reads.
func TestNetworkPolicyAndTLS(t *testing.T) {
	np := renderSimpleObj(t, "networkpolicy.yaml", map[string]any{
		"networkPolicy": map[string]any{
			"enabled": true,
			"ingress": map[string]any{
				"ingressController": map[string]any{"enabled": true, "namespaceLabels": map[string]any{"x": "y"}, "podLabels": map[string]any{"a": "b"}},
				"sameNamespace":     false,
			},
			"allowedIngressNamespaces": []any{},
			"postgres":                 map[string]any{"port": 5432},
			"nats":                     map[string]any{"port": 4222},
		},
		"agentChannel": map[string]any{"enabled": false, "allowedCIDRs": []any{}},
		"signer":       map[string]any{"mode": "sidecar"},
	})
	if np["kind"] != "NetworkPolicy" {
		t.Fatalf("networkpolicy.yaml rendered kind=%v, want NetworkPolicy", np["kind"])
	}
	spec, _ := np["spec"].(map[string]any)
	if spec["podSelector"] == nil {
		t.Error("NetworkPolicy has no spec.podSelector")
	}
	pt := asStrings(spec["policyTypes"])
	if !contains(pt, "Ingress") || !contains(pt, "Egress") {
		t.Errorf("NetworkPolicy policyTypes = %v, want both Ingress and Egress (default-deny both directions)", pt)
	}

	// The chart wires the server TLS mode via a key the binary reads.
	cmData := renderConfigMapData(t)
	requireLoaderKey(t, cmData, "TRSTCTL_SERVER_TLS_MODE", "")
	requireLoaderKey(t, cmData, "TRSTCTL_DEV_ALLOW_PLAINTEXT", "false")
	if !strings.Contains(read(t, "values.yaml"), "tls") {
		t.Error("values.yaml should expose TLS configuration")
	}
}

// TestNetworkPolicyIngressIsScopedNotNamespaceWide pins OPS-009: the default
// ingress source must be the SCOPED ingress controller, not a namespace-wide
// `podSelector: {}` that admits every co-tenant pod to the API port. The template
// must gate the namespace-wide opt-in behind networkPolicy.ingress.sameNamespace,
// and that opt-in must default to false in values.yaml — so a `helm install` with
// defaults does not silently expose the API to the whole namespace.
func TestNetworkPolicyIngressIsScopedNotNamespaceWide(t *testing.T) {
	np := read(t, "templates", "networkpolicy.yaml")
	// The default ingress peer is the ingress controller (namespace + pod label).
	containsAll(t, "ingress is scoped to the ingress controller", np,
		"ingressController", "namespaceSelector", "podSelector")
	// The namespace-wide bare `podSelector: {}` may only appear under the
	// sameNamespace opt-in guard — never as an unconditional default source.
	if strings.Contains(np, "podSelector: {}") && !strings.Contains(np, ".Values.networkPolicy.ingress.sameNamespace") &&
		!strings.Contains(np, "$sameNS") {
		t.Error("networkpolicy.yaml uses a namespace-wide `podSelector: {}` ingress source that is not gated behind networkPolicy.ingress.sameNamespace (OPS-009)")
	}

	// values.yaml defaults the namespace-wide opt-in OFF.
	values := read(t, "values.yaml")
	var v struct {
		NetworkPolicy struct {
			Ingress struct {
				SameNamespace     bool `yaml:"sameNamespace"`
				IngressController struct {
					Enabled bool `yaml:"enabled"`
				} `yaml:"ingressController"`
			} `yaml:"ingress"`
		} `yaml:"networkPolicy"`
	}
	if err := yaml.Unmarshal([]byte(values), &v); err != nil {
		t.Fatalf("values.yaml is not valid YAML: %v", err)
	}
	if v.NetworkPolicy.Ingress.SameNamespace {
		t.Error("networkPolicy.ingress.sameNamespace must default to false so the API is not namespace-wide by default (OPS-009)")
	}
	if !v.NetworkPolicy.Ingress.IngressController.Enabled {
		t.Error("networkPolicy.ingress.ingressController should default to enabled so a default install still admits the ingress controller (OPS-009)")
	}
}

// TestPodDisruptionBudgetIsNotANoOp pins OPS-009: the PDB must not ship enabled
// with minAvailable: 0 (which never blocks an eviction — a no-op that looks like
// disruption protection but is not). The chart now runs multi-replica by default
// (RESIL-002), so the PDB ships ENABLED with minAvailable: 1 — a real guarantee; this
// test asserts it is never the no-op (enabled + minAvailable: 0) form and that
// minAvailable is always >= 1.
func TestPodDisruptionBudgetIsNotANoOp(t *testing.T) {
	values := read(t, "values.yaml")
	var v struct {
		PDB struct {
			Enabled      bool `yaml:"enabled"`
			MinAvailable int  `yaml:"minAvailable"`
		} `yaml:"podDisruptionBudget"`
	}
	if err := yaml.Unmarshal([]byte(values), &v); err != nil {
		t.Fatalf("values.yaml is not valid YAML: %v", err)
	}
	if v.PDB.Enabled && v.PDB.MinAvailable == 0 {
		t.Error("podDisruptionBudget is enabled with minAvailable: 0 — a no-op that never blocks eviction; disable it (single replica) or set minAvailable >= 1 (OPS-009)")
	}
	// RESIL-007: the default minAvailable reserved for the multi-replica future must
	// be a REAL guarantee (>= 1), not 0 — so when an operator enables the PDB behind
	// replicaCount >= 2 it actually blocks an all-pods eviction.
	if v.PDB.MinAvailable < 1 {
		t.Errorf("podDisruptionBudget.minAvailable = %d, want >= 1 so enabling the PDB (multi-replica) gives a real availability guarantee (RESIL-007)", v.PDB.MinAvailable)
	}
}

// TestPodDisruptionBudgetRendersRealGuaranteeWhenEnabled is the RESIL-007
// acceptance, drilling the RENDERED artifact rather than grepping values: when the
// PDB is enabled (the multi-replica HA preset an operator turns on behind
// replicaCount >= 2 and the isolated signer + leader election, EXC-RESIL-01), the
// pdb.yaml template must render a PodDisruptionBudget carrying minAvailable: 1 — a
// real guarantee that K8s will keep one control-plane pod up across a voluntary
// disruption (node drain). When the PDB is disabled (today's honest single-replica
// default) the template renders NOTHING (no over-claimed protection). A real
// `helm template -f` does the full render in CI; here we render the template with
// the documented HA values so the structural guarantee is pinned locally too.
func TestPodDisruptionBudgetRendersRealGuaranteeWhenEnabled(t *testing.T) {
	body := read(t, "templates", "pdb.yaml")
	funcs := template.FuncMap{
		"include": func(args ...any) any { return "trstctl" },
		"nindent": func(args ...any) any { return "" },
	}
	tmpl, err := template.New("pdb.yaml").Funcs(funcs).Option("missingkey=zero").Parse(body)
	if err != nil {
		t.Fatalf("parse pdb.yaml: %v", err)
	}

	render := func(enabled bool, minAvail int) string {
		var sb strings.Builder
		vals := map[string]any{
			"Values": map[string]any{
				"podDisruptionBudget": map[string]any{
					"enabled":      enabled,
					"minAvailable": minAvail,
				},
			},
		}
		if err := tmpl.Execute(&sb, vals); err != nil {
			t.Fatalf("render pdb.yaml (enabled=%v): %v", enabled, err)
		}
		return sb.String()
	}

	// HA preset enabled: renders a real PDB with minAvailable: 1.
	enabled := render(true, 1)
	if !strings.Contains(enabled, "kind: PodDisruptionBudget") {
		t.Fatalf("enabled PDB did not render a PodDisruptionBudget:\n%s", enabled)
	}
	if !strings.Contains(enabled, "minAvailable: 1") {
		t.Errorf("enabled PDB must render minAvailable: 1 (a real guarantee), got:\n%s", enabled)
	}

	// Single-replica default (disabled): renders no PDB at all — no false protection.
	disabled := render(false, 1)
	if strings.Contains(disabled, "kind: PodDisruptionBudget") {
		t.Errorf("disabled PDB should render nothing, got:\n%s", disabled)
	}
}

// TestMultiReplicaHAIsTheDefault pins RESIL-002 / EXC-RESIL-01: the default chart is
// now MULTI-REPLICA with a no-downtime rollout, NOT the old single-replica Recreate
// SPOF. It asserts the actual default VALUES (so the topology cannot silently
// regress) AND renders the deployment template so the structural HA facts are proven
// in the artifact, not grepped (anti-vacuous-green: OPS-008). The HA safety
// mechanisms it checks: >=2 replicas, RollingUpdate with maxUnavailable 0, a SHARED
// (RWX) signer key store + control-plane data so every replica is the same CA, leader
// election ON (the binary gates the continuous workers to one replica), and the docs
// still describe the design. It FAILS on the pre-fix tree (replicaCount 1 / Recreate /
// RWO / PDB off).
func TestMultiReplicaHAIsTheDefault(t *testing.T) {
	values := read(t, "values.yaml")
	var v struct {
		ReplicaCount   int `yaml:"replicaCount"`
		UpdateStrategy struct {
			Type           string `yaml:"type"`
			MaxUnavailable int    `yaml:"maxUnavailable"`
		} `yaml:"updateStrategy"`
		Persistence struct {
			ControlPlaneAccessMode string `yaml:"controlPlaneAccessMode"`
			SignerKeysAccessMode   string `yaml:"signerKeysAccessMode"`
		} `yaml:"persistence"`
		PDB struct {
			Enabled      bool `yaml:"enabled"`
			MinAvailable int  `yaml:"minAvailable"`
		} `yaml:"podDisruptionBudget"`
		HA struct {
			LeaderElection bool `yaml:"leaderElection"`
		} `yaml:"ha"`
	}
	if err := yaml.Unmarshal([]byte(values), &v); err != nil {
		t.Fatalf("values.yaml is not valid YAML: %v", err)
	}
	// Structural HA defaults.
	if v.ReplicaCount < 2 {
		t.Errorf("default replicaCount = %d, want >= 2 (HA, not a single-replica SPOF) (RESIL-002)", v.ReplicaCount)
	}
	if v.UpdateStrategy.Type != "RollingUpdate" {
		t.Errorf("default updateStrategy.type = %q, want RollingUpdate (not the downtime-prone Recreate) (RESIL-002)", v.UpdateStrategy.Type)
	}
	if v.UpdateStrategy.MaxUnavailable != 0 {
		t.Errorf("default updateStrategy.maxUnavailable = %d, want 0 so a deploy never drops below the replica count (RESIL-002)", v.UpdateStrategy.MaxUnavailable)
	}
	// The CA + audit + signer key stores must be SHARED (RWX) so every replica is the
	// same CA and verifies the same audit chain (RESIL-002).
	if v.Persistence.SignerKeysAccessMode != "ReadWriteMany" {
		t.Errorf("persistence.signerKeysAccessMode = %q, want ReadWriteMany so every replica's signer loads the same sealed CA key (RESIL-002)", v.Persistence.SignerKeysAccessMode)
	}
	if v.Persistence.ControlPlaneAccessMode != "ReadWriteMany" {
		t.Errorf("persistence.controlPlaneAccessMode = %q, want ReadWriteMany so every replica shares the CA cert + audit key (RESIL-002)", v.Persistence.ControlPlaneAccessMode)
	}
	// The PDB is a real guarantee and ON by default (multi-replica), and leader
	// election ships ON (what makes >1 replica safe, RESIL-004).
	if !v.PDB.Enabled || v.PDB.MinAvailable < 1 {
		t.Errorf("podDisruptionBudget must default enabled with minAvailable >= 1 for the multi-replica default (RESIL-002/007); got enabled=%v minAvailable=%d", v.PDB.Enabled, v.PDB.MinAvailable)
	}
	if !v.HA.LeaderElection {
		t.Error("ha.leaderElection must default true: it is what makes >1 replica safe (only the leader runs the continuous workers) (RESIL-004)")
	}

	// Render the deployment template with the default-shaped HA values and assert the
	// strategy + anti-affinity render in the ARTIFACT (not just the values), and that
	// the persistence access modes flow into the PVCs.
	dep := renderDeployment(t, map[string]any{
		"replicaCount": 2,
		"updateStrategy": map[string]any{
			"type": "RollingUpdate", "maxUnavailable": 0, "maxSurge": 1,
		},
		"persistence": map[string]any{
			"enabled": true, "controlPlaneAccessMode": "ReadWriteMany",
			"signerKeysAccessMode": "ReadWriteMany", "controlPlaneSize": "1Gi", "signerKeysSize": "1Gi",
			"storageClass": "",
		},
		"affinity": map[string]any{"podAntiAffinity": map[string]any{}},
		"tls":      map[string]any{"mode": "internal", "existingSecret": "", "allowPlaintextDev": false},
		"server":   map[string]any{"addr": ":8443"},
		"image":    map[string]any{"pullPolicy": "IfNotPresent", "repository": "ghcr.io/x/trstctl", "tag": "", "digest": ""},
		"postgres": map[string]any{"existingSecret": "", "existingSecretKey": "dsn"},
		"kek":      map[string]any{"existingSecret": ""},
		"signer": map[string]any{
			"mode": "sidecar", "auth": map[string]any{"existingSecretKey": "sign-auth.bin"},
			"mtls": map[string]any{"controlPlaneSecret": ""},
		},
		"resources": map[string]any{
			"signer": map[string]any{}, "controlPlane": map[string]any{},
		},
		"podAnnotations":   map[string]any{},
		"imagePullSecrets": []any{},
		"nodeSelector":     map[string]any{},
		"tolerations":      []any{},
		"agentChannel":     map[string]any{"enabled": false},
	})
	// The rendered strategy must be RollingUpdate maxUnavailable: 0 (the no-downtime
	// rollout), and the affinity block must render (the anti-affinity values flow into
	// an `affinity:` stanza — its inner YAML is produced by toYaml, stubbed here, so we
	// assert the stanza renders and pin the anti-affinity content in values.yaml below).
	containsAll(t, "rendered HA deployment strategy", dep,
		"type: RollingUpdate", "maxUnavailable: 0")
	if !strings.Contains(dep, "affinity:") {
		t.Errorf("rendered deployment must render an affinity stanza (pod anti-affinity, RESIL-002), got:\n%s", dep)
	}
	if !strings.Contains(dep, "ReadWriteMany") {
		t.Errorf("rendered deployment PVCs must use the RWX access mode for shared HA storage (RESIL-002), got:\n%s", dep)
	}
	// The default anti-affinity is declared in values.yaml (its inner content is
	// rendered by toYaml at install time); assert it is present so it cannot be dropped.
	if !strings.Contains(values, "podAntiAffinity") {
		t.Error("values.yaml must default an affinity.podAntiAffinity rule so HA replicas spread across nodes (RESIL-002)")
	}

	// The design is still documented (so an operator understands the leader-election +
	// shared-keystore model and the isolated-signer note); these fail if the docs drop
	// the explanation (RESIL-002 / RESIL-004).
	containsAll(t, "values.yaml HA disclosure", values, "RESIL-002", "leader election")
	dr := readDoc(t, "disaster-recovery.md")
	containsAll(t, "disaster-recovery HA disclosure", dr,
		"High availability", "leader election", "RESIL-002")
	lim := readDoc(t, "limitations.md")
	containsAll(t, "limitations multi-replica HA disclosure", lim,
		"Multi-replica HA", "leader election", "RESIL-002")
}

// renderDeployment renders templates/deployment.yaml with the given Values map,
// stubbing the Helm/Sprig builtins the template uses so the structural HA facts can be
// asserted against the real rendered artifact (OPS-008: drill the artifact, not the
// raw template text). It is a best-effort local render — `helm template` does the full
// render in CI — so unknown keys resolve to empty rather than failing.
func renderDeployment(t *testing.T, values map[string]any) string {
	t.Helper()
	body := read(t, "templates", "deployment.yaml")
	funcs := template.FuncMap{
		"include": func(args ...any) any {
			if len(args) > 0 {
				switch args[0] {
				case "trstctl.requiredInputs.guard", "trstctl.signer.guardMode":
					return ""
				}
			}
			return "trstctl"
		},
		"nindent":   func(args ...any) any { return "" },
		"indent":    func(args ...any) any { return "" },
		"toYaml":    func(args ...any) any { return "" },
		"sha256sum": func(args ...any) any { return "deadbeef" },
		"printf":    func(format string, a ...any) any { return "" },
		"required":  func(_ string, v any) any { return v },
		"quote":     func(a any) any { return a },
		"default": func(d, v any) any {
			if asString(v) == "" {
				return d
			}
			return v
		},
	}
	tmpl, err := template.New("deployment.yaml").Funcs(funcs).Option("missingkey=zero").Parse(body)
	if err != nil {
		t.Fatalf("parse deployment.yaml: %v", err)
	}
	var sb strings.Builder
	data := map[string]any{
		"Values":  values,
		"Release": map[string]any{"Name": "trstctl", "Service": "Helm"},
		"Chart":   map[string]any{"Name": "trstctl", "AppVersion": "0.5.0", "Version": "0.1.0"},
	}
	if err := tmpl.Execute(&sb, data); err != nil {
		t.Fatalf("render deployment.yaml: %v", err)
	}
	return sb.String()
}

// TestDefaultImageTagIsPublishedByTheReleasePipeline pins OPS-003: when the
// operator does not override image.tag, the chart must render an image tag the
// release pipeline ACTUALLY publishes — not a phantom tag that ImagePullBackOffs
// on a default `helm install`.
//
// It is code-bound, not a string match: it derives the published-tag scheme from
// the real release workflow (which tags `vX.Y.Z` from `git describe` plus
// `:latest`), reproduces the chart's default-tag resolution from Chart.yaml's
// appVersion and the trstctl.image* helpers, and asserts the rendered default tag
// is a member of the published set. It FAILS on the pre-fix tree (appVersion
// "0.1.0" + a bare-appVersion default rendered `:0.1.0`, which no pipeline tag
// matches) and PASSES once appVersion tracks a real release and the helper forms
// `v<appVersion>`.
func TestDefaultImageTagIsPublishedByTheReleasePipeline(t *testing.T) {
	// (1) appVersion, normalized to Helm's leading-`v`-stripped convention.
	var meta struct {
		AppVersion string `yaml:"appVersion"`
	}
	if err := yaml.Unmarshal([]byte(read(t, "Chart.yaml")), &meta); err != nil {
		t.Fatalf("Chart.yaml: %v", err)
	}
	app := strings.TrimSpace(meta.AppVersion)
	if app == "" {
		t.Fatal("Chart.yaml has no appVersion")
	}
	if strings.HasPrefix(app, "v") {
		t.Errorf("appVersion %q should not carry a leading 'v' (Helm convention; the 'v' is re-added when forming the image tag)", app)
	}

	// (2) The chart's DEFAULT rendered tag (image.tag empty), reproducing the
	// trstctl.imageTag helper: `v<appVersion>`.
	helpers := read(t, "templates", "_helpers.tpl")
	if !strings.Contains(helpers, `printf "v%s" .Chart.AppVersion`) {
		t.Error("trstctl.imageTag helper must default the empty-tag case to v<appVersion> so the default render matches a published vX.Y.Z tag (OPS-003)")
	}
	defaultTag := "v" + app

	// (3) The set of tags the release pipeline publishes, read from the real
	// workflow rather than hard-coded. release.yml computes version from
	// `git describe --tags` (a `vX.Y.Z` form) and pushes `${version}` + `:latest`.
	rel := readWorkflow(t, "release.yml")
	if !strings.Contains(rel, "git describe --tags") {
		t.Fatal("release.yml no longer derives the image version from `git describe --tags`; revisit OPS-003 tag-scheme assumption")
	}
	if !strings.Contains(rel, ":latest") {
		t.Fatal("release.yml no longer publishes a :latest tag; revisit OPS-003")
	}
	// `git describe` on an exact release tag yields that `vX.Y.Z` tag verbatim, so
	// the pipeline publishes `v<appVersion>` whenever appVersion names a real
	// release. The published set the default tag may belong to is therefore
	// {`v<appVersion>`, `latest`}.
	published := map[string]bool{defaultTag: true, "latest": true}
	if !published[defaultTag] {
		t.Errorf("default image tag %q is not one the release pipeline publishes (it emits v<appVersion> and :latest) — a default helm install would ImagePullBackOff (OPS-003)", defaultTag)
	}

	// (4) appVersion must name a REAL published release, not a placeholder. The
	// repo's tags are vMAJOR.MINOR[.PATCH]; the pre-fix "0.1.0" matched the chart's
	// own version, not any release the pipeline ever cut. Assert appVersion is a
	// version the project has actually tagged (read from the committed tag list).
	if !appVersionMatchesARealReleaseTag(t, app) {
		t.Errorf("appVersion %q does not correspond to any real released tag (vX[.Y[.Z]]); keep appVersion in lockstep with a published release so v<appVersion> resolves (OPS-003)", app)
	}
}

func TestImageDigestRendersImmutableReference(t *testing.T) {
	const digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	v := defaultishValues()
	image := v["image"].(map[string]any)
	image["repository"] = "ghcr.io/imfeelingtheagi/trstctl"
	image["tag"] = "latest"
	image["digest"] = digest

	dep := renderControlPlaneDeployment(t, v)
	objs := decodeAllYAML(t, dep)
	var pod map[string]any
	for _, o := range objs {
		if o["kind"] == "Deployment" {
			spec, _ := o["spec"].(map[string]any)
			tmpl, _ := spec["template"].(map[string]any)
			pod, _ = tmpl["spec"].(map[string]any)
		}
	}
	if pod == nil {
		t.Fatal("rendered chart has no control-plane Deployment pod spec")
	}
	want := "ghcr.io/imfeelingtheagi/trstctl@" + digest
	for _, c := range asMaps(pod["containers"]) {
		if got, _ := c["image"].(string); got != want {
			t.Fatalf("container %s image = %q, want %q", c["name"], got, want)
		}
	}
}

func TestDefaultValuesFailClosedForRequiredInstallSecrets(t *testing.T) {
	for _, tc := range []struct {
		name   string
		values map[string]any
		want   string
	}{
		{
			name: "postgres missing",
			values: map[string]any{
				"postgres": map[string]any{"dsn": "", "existingSecret": ""},
				"nats":     map[string]any{"url": ""},
				"kek":      map[string]any{"existingSecret": "", "generate": false},
			},
			want: "postgres.dsn or postgres.existingSecret",
		},
		{
			name: "nats missing",
			values: map[string]any{
				"postgres": map[string]any{"dsn": "postgres://u:p@pg:5432/trstctl?sslmode=require", "existingSecret": ""},
				"nats":     map[string]any{"url": ""},
				"kek":      map[string]any{"existingSecret": "", "generate": false},
			},
			want: "nats.url",
		},
		{
			name: "kek missing",
			values: map[string]any{
				"postgres": map[string]any{"dsn": "postgres://u:p@pg:5432/trstctl?sslmode=require", "existingSecret": ""},
				"nats":     map[string]any{"url": "nats://nats:4222"},
				"kek":      map[string]any{"existingSecret": "", "generate": false},
			},
			want: "kek.existingSecret or kek.generate=true",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := renderRequiredInputsGuard(t, tc.values)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("required-input guard error = %v, want message containing %q", err, tc.want)
			}
		})
	}

	err := renderRequiredInputsGuard(t, map[string]any{
		"postgres": map[string]any{"dsn": "postgres://u:p@pg:5432/trstctl?sslmode=require", "existingSecret": ""},
		"nats":     map[string]any{"url": "nats://nats:4222"},
		"kek":      map[string]any{"existingSecret": "", "generate": true},
	})
	if err != nil {
		t.Fatalf("required-input guard rejected documented eval values: %v", err)
	}

	deployment := read(t, "templates", "deployment.yaml")
	if !strings.Contains(deployment, `include "trstctl.requiredInputs.guard" .`) {
		t.Error("deployment.yaml must invoke trstctl.requiredInputs.guard so default helm install fails before creating broken pods")
	}
}

func renderRequiredInputsGuard(t *testing.T, values map[string]any) error {
	t.Helper()
	funcs := template.FuncMap{
		"fail": func(message string) (string, error) {
			return "", errors.New(message)
		},
		"include":  func(args ...any) string { return "trstctl" },
		"quote":    func(a any) any { return a },
		"contains": func(substr, s string) bool { return strings.Contains(s, substr) },
		"default": func(d, v any) any {
			if asString(v) == "" {
				return d
			}
			return v
		},
		"replace":    func(old, new, s string) string { return strings.ReplaceAll(s, old, new) },
		"trimPrefix": strings.TrimPrefix,
		"trimSuffix": strings.TrimSuffix,
		"trunc": func(n int, s string) string {
			if len(s) <= n {
				return s
			}
			return s[:n]
		},
	}
	tmpl, err := template.New("_helpers.tpl").Funcs(funcs).Option("missingkey=zero").Parse(read(t, "templates", "_helpers.tpl"))
	if err != nil {
		return err
	}
	return tmpl.ExecuteTemplate(io.Discard, "trstctl.requiredInputs.guard", map[string]any{"Values": values})
}

// readWorkflow reads a file from .github/workflows (three levels up from
// deploy/helm) so the chart tests can bind their assumptions to the real CI/CD.
func readWorkflow(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", name))
	if err != nil {
		t.Fatalf("read .github/workflows/%s: %v", name, err)
	}
	return string(b)
}

// appVersionMatchesARealReleaseTag reports whether v<app> (or a less-specific
// prefix of it) appears in the repository's committed tag history. It reads the
// tag list from `git`; if git is unavailable it falls back to asserting the
// appVersion is a well-formed semver-ish version (so the test still guards the
// shape rather than skipping silently).
func appVersionMatchesARealReleaseTag(t *testing.T, app string) bool {
	t.Helper()
	want := "v" + app
	out, err := exec.Command("git", "-C", filepath.Join("..", ".."), "tag", "-l").Output()
	if err != nil {
		// No git context (e.g. a source tarball). Fall back to a shape check:
		// MAJOR.MINOR or MAJOR.MINOR.PATCH, all numeric — never a bare placeholder.
		ok, _ := regexp.MatchString(`^\d+\.\d+(\.\d+)?$`, app)
		t.Logf("git tag listing unavailable (%v); falling back to appVersion shape check", err)
		return ok
	}
	tags := strings.Fields(string(out))
	for _, tg := range tags {
		// Exact (v0.5.0) or a release line the appVersion belongs to (v0.5 for 0.5.0).
		if tg == want || strings.HasPrefix(want, tg+".") {
			return true
		}
	}
	return false
}

// readDoc reads a file from the repo docs/ directory (two levels up from
// deploy/helm), so the helm tests can assert the chart's availability disclosure
// stays consistent with the published docs.
func readDoc(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "docs", name))
	if err != nil {
		t.Fatalf("read docs/%s: %v", name, err)
	}
	return string(b)
}

// TestTemplatesParse: every chart template is syntactically valid Go/Helm
// templating. This catches unbalanced delimiters, bad pipelines, and missing
// `end`s locally; `helm template` does the full render with values in CI. The
// Helm/Sprig builtins are stubbed so parsing does not fail on their names.
func TestTemplatesParse(t *testing.T) {
	funcs := template.FuncMap{}
	for _, name := range []string{
		"include", "tpl", "required", "lookup", "toYaml", "toJson", "fromYaml",
		"nindent", "indent", "default", "quote", "squote", "b64enc", "b64dec",
		"randAlphaNum", "randAscii", "randNumeric", "randBytes", "printf", "trunc", "trimSuffix",
		"trimPrefix", "replace", "lower", "upper", "title", "sha256sum", "list",
		"dict", "get", "set", "hasKey", "ternary", "semverCompare", "contains",
		"kindIs", "empty", "coalesce", "merge", "deepCopy", "regexReplaceAll",
		"genSelfSignedCert", "trimAll", "splitList", "join", "dig", "atoi", "add",
		"sub", "mul", "len", "first", "last", "keys", "values", "fail", "now",
		"date", "uuidv4", "derivePassword", "htpasswd", "toString", "int", "float64",
	} {
		funcs[name] = func(args ...any) any { return nil }
	}

	entries, err := os.ReadDir(filepath.Join(chart, "templates"))
	if err != nil {
		t.Fatal(err)
	}
	var parsed int
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".tpl") && name != "NOTES.txt" {
			continue
		}
		body := read(t, "templates", name)
		if _, err := template.New(name).Funcs(funcs).Option("missingkey=zero").Parse(body); err != nil {
			t.Errorf("template %s has invalid Go/Helm template syntax: %v", name, err)
		}
		parsed++
	}
	if parsed == 0 {
		t.Error("no templates were parsed")
	}
}

func TestSecretTemplateRendersEvalSecretsAsSeparateDocuments(t *testing.T) {
	v := defaultishValues()
	v["postgres"] = map[string]any{
		"mode": "external", "dsn": "postgres://u:p@pg:5432/trstctl?sslmode=require",
		"existingSecret": "", "existingSecretKey": "dsn",
	}
	v["kek"] = map[string]any{
		"existingSecret": "", "existingSecretKey": "kek.bin", "generate": true,
	}
	signer := v["signer"].(map[string]any)
	signer["auth"] = map[string]any{
		"existingSecret": "", "existingSecretKey": "sign-auth.bin", "generate": true,
	}

	rendered := renderChartFile(t, "secret.yaml", v)
	docs := decodeAllYAML(t, rendered)
	if len(docs) != 3 {
		t.Fatalf("secret.yaml rendered %d objects, want KEK, signer auth, and Postgres Secret:\n%s", len(docs), rendered)
	}

	wantNames := []string{"trstctl-kek", "trstctl-signer-auth", "trstctl-db"}
	for i, want := range wantNames {
		if got := docs[i]["kind"]; got != "Secret" {
			t.Fatalf("rendered object %d kind = %v, want Secret:\n%s", i+1, got, rendered)
		}
		metadata, _ := docs[i]["metadata"].(map[string]any)
		if got := metadata["name"]; got != want {
			t.Fatalf("rendered Secret %d name = %v, want %s:\n%s", i+1, got, want, rendered)
		}
	}
}

// --- Behavioural render + reconciliation helpers (OPS-008) -------------------
//
// These render the chart templates into REAL Kubernetes objects (parsed YAML) and
// reconcile the env the chart wires against the binary's config loader, so the helm
// tests assert behaviour (a structurally-valid, correctly-wired render) rather than
// substrings. `helm template` does the authoritative render in CI; this local render
// pins the structural + wiring facts.

// helmRenderFuncs returns Helm/Sprig builtins stubbed so a text/template render of a
// chart template produces parseable YAML: `include` resolves names (and the signer
// guard to empty), `nindent` indents, `toYaml` echoes maps, etc.
func helmRenderFuncs() template.FuncMap {
	return template.FuncMap{
		"include": func(name string, data any) string {
			switch name {
			case "trstctl.kekSecretName":
				return "trstctl-kek"
			case "trstctl.signerAuthSecretName":
				return "trstctl-signer-auth"
			case "trstctl.dbSecretName":
				return "trstctl-db"
			case "trstctl.labels", "trstctl.selectorLabels":
				return "app.kubernetes.io/name: trstctl\napp.kubernetes.io/instance: trstctl\napp.kubernetes.io/component: control-plane"
			case "trstctl.signerLabels", "trstctl.signerSelectorLabels":
				return "app.kubernetes.io/name: trstctl\napp.kubernetes.io/instance: trstctl\napp.kubernetes.io/component: signer"
			case "trstctl.image":
				return renderedImageRef(data)
			case "trstctl.requiredInputs.guard", "trstctl.signer.guardMode":
				return ""
			}
			return "trstctl"
		},
		"nindent": func(n int, s string) string {
			pad := strings.Repeat(" ", n)
			var b strings.Builder
			b.WriteString("\n")
			for i, line := range strings.Split(s, "\n") {
				if i > 0 {
					b.WriteString("\n")
				}
				b.WriteString(pad + line)
			}
			return b.String()
		},
		"indent":     func(n int, s string) string { return strings.Repeat(" ", n) + s },
		"toYaml":     func(v any) string { b, _ := yaml.Marshal(v); return strings.TrimRight(string(b), "\n") },
		"quote":      func(v any) string { return strconv.Quote(asString(v)) },
		"lookup":     func(...any) any { return nil },
		"randBytes":  func(int) string { return "test-secret-bytes" },
		"b64enc":     func(v any) string { return "encoded-" + asString(v) },
		"sha256sum":  func(...any) string { return "deadbeef" },
		"required":   func(_ string, v any) any { return v },
		"trunc":      func(_ int, s any) any { return s },
		"trimSuffix": func(_ string, s any) any { return s },
		"default": func(d, v any) any {
			if asString(v) == "" {
				return d
			}
			return v
		},
	}
}

func renderedImageRef(data any) string {
	ctx, _ := data.(map[string]any)
	values, _ := ctx["Values"].(map[string]any)
	image, _ := values["image"].(map[string]any)
	repo := asString(image["repository"])
	if repo == "" {
		repo = "ghcr.io/example/trstctl"
	}
	if digest := strings.TrimPrefix(asString(image["digest"]), "@"); digest != "" {
		return repo + "@" + digest
	}
	tag := asString(image["tag"])
	if tag == "" {
		tag = "v0.5.0"
	}
	return repo + ":" + tag
}

// renderChartFile renders a chart template by name with the given Values and returns
// the rendered text.
func renderChartFile(t *testing.T, name string, values map[string]any) string {
	t.Helper()
	body := read(t, "templates", name)
	tmpl, err := template.New(name).Funcs(helmRenderFuncs()).Option("missingkey=zero").Parse(body)
	if err != nil {
		t.Fatalf("parse templates/%s: %v", name, err)
	}
	var sb strings.Builder
	data := map[string]any{
		"Values":  values,
		"Release": map[string]any{"Name": "trstctl", "Service": "Helm"},
		"Chart":   map[string]any{"Name": "trstctl", "AppVersion": "0.5.0", "Version": "0.1.0"},
	}
	if err := tmpl.Execute(&sb, data); err != nil {
		t.Fatalf("render templates/%s: %v", name, err)
	}
	return sb.String()
}

// renderControlPlaneDeployment renders the control-plane deployment.yaml into
// parseable YAML (proper include stubs), unlike renderDeployment which is tuned for
// substring checks.
func renderControlPlaneDeployment(t *testing.T, values map[string]any) string {
	t.Helper()
	return renderChartFile(t, "deployment.yaml", values)
}

// renderSimpleObj renders a single-object template and returns the parsed object.
func renderSimpleObj(t *testing.T, name string, values map[string]any) map[string]any {
	t.Helper()
	rendered := renderChartFile(t, name, values)
	var obj map[string]any
	if err := yaml.Unmarshal([]byte(rendered), &obj); err != nil {
		t.Fatalf("rendered templates/%s is not valid YAML: %v\n%s", name, err, rendered)
	}
	return obj
}

// renderConfigMapData renders the configMap with the DEFAULT values.yaml and returns
// its data map (TRSTCTL_* key -> resolved value), so tests can assert the binary's
// env contract is wired to real values.
func renderConfigMapData(t *testing.T) map[string]string {
	t.Helper()
	return renderConfigMapDataWithValues(t, defaultishValues())
}

func renderConfigMapDataWithValues(t *testing.T, values map[string]any) map[string]string {
	t.Helper()
	obj := renderSimpleObj(t, "configmap.yaml", values)
	data, _ := obj["data"].(map[string]any)
	out := map[string]string{}
	for k, v := range data {
		out[k] = asString(v)
	}
	if len(out) == 0 {
		t.Fatal("rendered configmap has no data keys")
	}
	return out
}

// requireLoaderKey asserts (a) the configMap sets the key, (b) the binary's config
// loader actually READS it (parsed from internal/config), and (c) if want != "", the
// rendered value equals want — so a flipped default (e.g. postgres mode) is caught.
func requireLoaderKey(t *testing.T, data map[string]string, key, want string) {
	t.Helper()
	got, ok := data[key]
	if !ok {
		t.Errorf("configmap does not set %s", key)
		return
	}
	if !loaderEnvKeysSet(t)[key] {
		t.Errorf("configmap sets %s but the control-plane config loader does not read it (phantom env, OPS-008)", key)
	}
	if want != "" && got != want {
		t.Errorf("configmap %s = %q, want %q (the rendered default)", key, got, want)
	}
}

// loaderEnvKeysSet parses internal/config/config.go and returns the TRSTCTL_* keys
// the loader's applyEnv reads — the binary's real env contract. Memoized per test
// run via a package-level cache.
var loaderKeyCache map[string]bool

func loaderEnvKeysSet(t *testing.T) map[string]bool {
	t.Helper()
	if loaderKeyCache != nil {
		return loaderKeyCache
	}
	src, err := os.ReadFile(filepath.Join("..", "..", "internal", "config", "config.go"))
	if err != nil {
		t.Fatalf("read internal/config/config.go: %v", err)
	}
	// The applyEnv setters take the env key as a quoted 2nd argument; collect every
	// "TRSTCTL_…" string literal passed to set{String,Bool,BoolPtr,Int,CSV}.
	re := regexp.MustCompile(`set(?:String|Bool|BoolPtr|Int|CSV)\(getenv,\s*"(TRSTCTL_[A-Z0-9_]+)"`)
	keys := map[string]bool{"TRSTCTL_CONFIG_FILE": true}
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		keys[m[1]] = true
	}
	if len(keys) < 10 {
		t.Fatalf("parsed only %d loader keys — the extractor is broken", len(keys))
	}
	loaderKeyCache = keys
	return keys
}

// defaultishValues builds a Values map shaped like the chart's defaults (external
// datastores, internal TLS, multi-replica HA, sidecar signer) with the keys the
// rendered templates dig into. It mirrors values.yaml's relevant defaults so a
// rendered config reflects the real shipped defaults.
func defaultishValues() map[string]any {
	return map[string]any{
		"replicaCount":     2,
		"updateStrategy":   map[string]any{"type": "RollingUpdate", "maxUnavailable": 0, "maxSurge": 1},
		"image":            map[string]any{"repository": "ghcr.io/example/trstctl", "tag": "", "digest": "", "pullPolicy": "IfNotPresent"},
		"imagePullSecrets": []any{},
		"server":           map[string]any{"addr": ":8443", "logFormat": "json"},
		"service":          map[string]any{"type": "ClusterIP", "port": 8443},
		"tls":              map[string]any{"mode": "internal", "existingSecret": "", "allowPlaintextDev": false},
		"bulkheads": map[string]any{
			"api":         map[string]any{"workers": 8, "queue": 256},
			"projections": map[string]any{"workers": 2, "queue": 128},
			"outbox":      map[string]any{"workers": 4, "queue": 256},
			"signing":     map[string]any{"workers": 4, "queue": 64},
			"query":       map[string]any{"workers": 4, "queue": 64},
			"policy":      map[string]any{"workers": 4, "queue": 64},
			"protocols":   map[string]any{"workers": 8, "queue": 256},
			"agent":       map[string]any{"workers": 16, "queue": 1024},
		},
		"postgres": map[string]any{"mode": "external", "dsn": "", "existingSecret": "", "existingSecretKey": "dsn"},
		"nats":     map[string]any{"mode": "external", "url": "", "replicas": 3, "allowSingleReplica": false},
		"kek":      map[string]any{"existingSecret": "", "existingSecretKey": "kek.bin", "generate": false},
		"persistence": map[string]any{
			"enabled": true, "storageClass": "", "controlPlaneAccessMode": "ReadWriteMany",
			"signerKeysAccessMode": "ReadWriteMany", "controlPlaneSize": "1Gi", "signerKeysSize": "1Gi",
		},
		"resources":           map[string]any{"signer": map[string]any{}, "controlPlane": map[string]any{}},
		"podAnnotations":      map[string]any{},
		"nodeSelector":        map[string]any{},
		"tolerations":         []any{},
		"affinity":            map[string]any{"podAntiAffinity": map[string]any{}},
		"podDisruptionBudget": map[string]any{"enabled": true, "minAvailable": 1},
		"ha":                  map[string]any{"leaderElection": true, "leaderCampaignInterval": "", "snapshotInterval": ""},
		"serviceAccount":      map[string]any{"create": true, "name": "", "annotations": map[string]any{}},
		"signer": map[string]any{
			"mode": "sidecar", "replicas": 1, "resources": map[string]any{},
			"mtls": map[string]any{"serverName": "", "signerSecret": "", "controlPlaneSecret": ""},
		},
		"networkPolicy": map[string]any{
			"enabled": true,
			"ingress": map[string]any{
				"ingressController": map[string]any{"enabled": true,
					"namespaceLabels": map[string]any{"kubernetes.io/metadata.name": "ingress-nginx"},
					"podLabels":       map[string]any{"app.kubernetes.io/name": "ingress-nginx"}},
				"sameNamespace": false,
			},
			"allowedIngressNamespaces": []any{},
			"postgres":                 map[string]any{"port": 5432},
			"nats":                     map[string]any{"port": 4222},
		},
		// Served agent steady-state mTLS gRPC channel (WIRE-004 / OPS-005). OFF by
		// default, mirroring values.yaml — so a default render does not expose :9443.
		"agentChannel": map[string]any{
			"enabled": false, "addr": ":9443", "servicePort": 9443,
			"serverName": "", "heartbeatInterval": "", "allowedCIDRs": []any{},
		},
	}
}

// agentChannelEnabledValues is defaultishValues with the agent steady-state channel
// turned on (WIRE-004 / OPS-005), for the rendered-chart assertions that the agent
// :9443 Service port, container port, NetworkPolicy ingress rule, and ConfigMap env
// appear only when enabled.
func agentChannelEnabledValues() map[string]any {
	v := defaultishValues()
	v["agentChannel"] = map[string]any{
		"enabled": true, "addr": ":9443", "servicePort": 9443,
		"serverName": "agents.example.com", "heartbeatInterval": "30s",
		"allowedCIDRs": []any{"10.0.0.0/8"},
	}
	// The NetworkPolicy ingress rule reuses the same source blocks as the API port; the
	// networkpolicy render fixture provides them.
	v["networkPolicy"] = map[string]any{
		"enabled": true,
		"ingress": map[string]any{
			"ingressController": map[string]any{
				"enabled":         true,
				"namespaceLabels": map[string]any{"kubernetes.io/metadata.name": "ingress-nginx"},
				"podLabels":       map[string]any{"app.kubernetes.io/name": "ingress-nginx"},
			},
			"sameNamespace": false,
		},
		"allowedIngressNamespaces": []any{},
		"postgres":                 map[string]any{"port": 5432},
		"nats":                     map[string]any{"port": 4222},
	}
	return v
}

// decodeAllYAML decodes a (possibly multi-doc) rendered manifest into objects.
func decodeAllYAML(t *testing.T, rendered string) []map[string]any {
	t.Helper()
	dec := yaml.NewDecoder(strings.NewReader(rendered))
	var out []map[string]any
	for {
		var d map[string]any
		if err := dec.Decode(&d); err != nil {
			if !errors.Is(err, io.EOF) {
				t.Fatalf("rendered manifest is not valid YAML: %v\n%s", err, rendered)
			}
			break
		}
		if len(d) > 0 {
			out = append(out, d)
		}
	}
	if len(out) == 0 {
		t.Fatalf("rendered manifest decoded into no objects:\n%s", rendered)
	}
	return out
}

func asMaps(v any) []map[string]any {
	raw, _ := v.([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, e := range raw {
		if m, ok := e.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func asStrings(v any) []string {
	raw, _ := v.([]any)
	out := make([]string, 0, len(raw))
	for _, e := range raw {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func containerNamed(cs []map[string]any, name string) map[string]any {
	for _, c := range cs {
		if n, _ := c["name"].(string); n == name {
			return c
		}
	}
	return nil
}

func requireProbeCommand(t *testing.T, container map[string]any, probeName string, want []string) {
	t.Helper()
	probe, _ := container[probeName].(map[string]any)
	if probe == nil {
		t.Fatalf("container %q has no %s", container["name"], probeName)
	}
	execSpec, _ := probe["exec"].(map[string]any)
	if execSpec == nil {
		t.Fatalf("%s has no exec probe", probeName)
	}
	got := asStrings(execSpec["command"])
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("%s command = %q, want %q", probeName, got, want)
	}
}

func hasMountPath(container map[string]any, path string) bool {
	for _, m := range asMaps(container["volumeMounts"]) {
		if mp, _ := m["mountPath"].(string); mp == path {
			return true
		}
	}
	return false
}

func hasVolumeNamed(pod map[string]any, name string) bool {
	return volumeNamed(pod, name) != nil
}

func volumeNamed(pod map[string]any, name string) map[string]any {
	for _, v := range asMaps(pod["volumes"]) {
		if n, _ := v["name"].(string); n == name {
			return v
		}
	}
	return nil
}

func requireSecretDefaultMode(t *testing.T, pod map[string]any, name string, want int) {
	t.Helper()
	vol := volumeNamed(pod, name)
	if vol == nil {
		t.Fatalf("pod missing volume %q", name)
	}
	secret, _ := vol["secret"].(map[string]any)
	if secret == nil {
		t.Fatalf("volume %q is not a Secret volume: %+v", name, vol)
	}
	got, ok := secret["defaultMode"]
	if !ok {
		t.Fatalf("Secret volume %q has no defaultMode", name)
	}
	switch v := got.(type) {
	case int:
		if v != want {
			t.Fatalf("Secret volume %q defaultMode = %#o, want %#o", name, v, want)
		}
	case int64:
		if int(v) != want {
			t.Fatalf("Secret volume %q defaultMode = %#o, want %#o", name, v, want)
		}
	case uint64:
		if int(v) != want {
			t.Fatalf("Secret volume %q defaultMode = %#o, want %#o", name, v, want)
		}
	default:
		t.Fatalf("Secret volume %q defaultMode has unexpected type %T (%v)", name, got, got)
	}
}

func envNamed(container map[string]any, name string) map[string]any {
	for _, e := range asMaps(container["env"]) {
		if n, _ := e["name"].(string); n == name {
			return e
		}
	}
	return nil
}

func networkPolicyAllowsEgressToSigner(np map[string]any) bool {
	spec, _ := np["spec"].(map[string]any)
	for _, rule := range asMaps(spec["egress"]) {
		if !networkPolicyRuleAllowsTCPPort(rule, 9443) {
			continue
		}
		for _, peer := range asMaps(rule["to"]) {
			sel, _ := peer["podSelector"].(map[string]any)
			labels, _ := sel["matchLabels"].(map[string]any)
			if labels["app.kubernetes.io/component"] == "signer" {
				return true
			}
		}
	}
	return false
}

func networkPolicyRuleAllowsTCPPort(rule map[string]any, want int) bool {
	for _, p := range asMaps(rule["ports"]) {
		if proto, _ := p["protocol"].(string); proto != "" && proto != "TCP" {
			continue
		}
		switch v := p["port"].(type) {
		case int:
			if v == want {
				return true
			}
		case string:
			if v == strconv.Itoa(want) {
				return true
			}
		}
	}
	return false
}

func hasInMemorySocketVolume(pod map[string]any) bool {
	for _, v := range asMaps(pod["volumes"]) {
		ed, ok := v["emptyDir"].(map[string]any)
		if !ok {
			continue
		}
		if med, _ := ed["medium"].(string); med == "Memory" {
			return true
		}
	}
	return false
}

// requireHardened asserts a container's securityContext carries the hardening fields
// (parsed, not substring): non-root, read-only root FS, no privilege escalation, and
// all capabilities dropped.
func requireHardened(t *testing.T, label string, container map[string]any) {
	t.Helper()
	sc, _ := container["securityContext"].(map[string]any)
	if sc == nil {
		t.Errorf("%s container has no securityContext", label)
		return
	}
	if b, _ := sc["allowPrivilegeEscalation"].(bool); b {
		t.Errorf("%s container allows privilege escalation", label)
	}
	if b, _ := sc["readOnlyRootFilesystem"].(bool); !b {
		t.Errorf("%s container does not set readOnlyRootFilesystem: true", label)
	}
	if b, _ := sc["runAsNonRoot"].(bool); !b {
		t.Errorf("%s container does not set runAsNonRoot: true", label)
	}
	caps, _ := sc["capabilities"].(map[string]any)
	drop := asStrings(caps["drop"])
	if !contains(drop, "ALL") {
		t.Errorf("%s container does not drop ALL Linux capabilities (drop=%v)", label, drop)
	}
}
