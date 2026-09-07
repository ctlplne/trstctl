// SPDX-License-Identifier: MPL-2.0

package demo

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

type composeDependency struct {
	Condition string `yaml:"condition"`
	Restart   bool   `yaml:"restart"`
}

type composeService struct {
	Image       string                       `yaml:"image"`
	Build       map[string]any               `yaml:"build"`
	PullPolicy  string                       `yaml:"pull_policy"`
	User        string                       `yaml:"user"`
	Profiles    []string                     `yaml:"profiles"`
	Environment map[string]any               `yaml:"environment"`
	Entrypoint  []string                     `yaml:"entrypoint"`
	Command     []string                     `yaml:"command"`
	Ports       []string                     `yaml:"ports"`
	DependsOn   map[string]composeDependency `yaml:"depends_on"`
	NetworkMode string                       `yaml:"network_mode"`
	Volumes     []string                     `yaml:"volumes"`
}

func parseComposeAt(t *testing.T, parts ...string) composeFile {
	t.Helper()
	var cf composeFile
	if err := yaml.Unmarshal([]byte(read(t, parts...)), &cf); err != nil {
		t.Fatalf("%s is not valid Compose YAML: %v", filepath.Join(parts...), err)
	}
	return cf
}

type composeFile struct {
	Name     string                    `yaml:"name"`
	Services map[string]composeService `yaml:"services"`
	Volumes  map[string]any            `yaml:"volumes"`
}

func read(t *testing.T, parts ...string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(parts...)) // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
	if err != nil {
		t.Fatalf("read %s: %v", filepath.Join(parts...), err)
	}
	return string(b)
}

func parseCompose(t *testing.T) composeFile {
	t.Helper()
	return parseComposeAt(t, "docker-compose.yml")
}

func TestPartnerLabComposeRunsRealLocalFrontDoorsWithoutPretendingLinuxIsIIS(t *testing.T) {
	cf := parseComposeAt(t, "lab", "docker-compose.yml")
	if cf.Name != "trstctl-demo" {
		t.Fatalf("partner lab compose name = %q, want trstctl-demo so it overlays the retained demo", cf.Name)
	}
	for _, want := range []string{
		"lab-init", "pebble", "pebble-challtestsrv", "pebble-loopback", "dns-webhook-loopback",
		"alert-sink", "lab-bootstrap", "frontdoors-lab", "lab-runner",
	} {
		service, ok := cf.Services[want]
		if !ok {
			t.Fatalf("partner lab compose missing %s", want)
		}
		if !slices.Equal(service.Profiles, []string{"partner-lab"}) {
			t.Fatalf("partner lab service %s profiles = %v, want opt-in partner-lab", want, service.Profiles)
		}
	}
	for name, want := range map[string]string{
		"pebble":              "ghcr.io/letsencrypt/pebble:2.10.1@sha256:ddf230642b1a584f519f32e347de1b05a6e4c1f6c35c1863b33effeab5f78199",
		"pebble-challtestsrv": "ghcr.io/letsencrypt/pebble-challtestsrv:2.10.1@sha256:12ce21884def456bcf9786542113949e1f19dc7738d2c70e156c2d0c38a1405b",
	} {
		if got := cf.Services[name].Image; got != want {
			t.Fatalf("partner lab %s image = %q, want exact digest %q", name, got, want)
		}
	}
	if _, exists := cf.Services["iis-lab"]; exists {
		t.Fatal("partner lab must not market a Linux container as real Windows IIS")
	}
	cp := cf.Services["trstctl"]
	buildArgs, ok := cp.Build["args"].(map[string]any)
	if !ok {
		t.Fatalf("partner lab trstctl build args = %#v, want candidate provenance mapping", cp.Build["args"])
	}
	for key, want := range map[string]string{
		"VERSION": "${TRSTCTL_LAB_BUILD_VERSION:-dev}",
		"COMMIT":  "${TRSTCTL_LAB_BUILD_COMMIT:-none}",
		"DATE":    "${TRSTCTL_LAB_BUILD_DATE:-1970-01-01T00:00:00Z}",
	} {
		if got := stringValue(buildArgs[key]); got != want {
			t.Fatalf("partner lab build arg %s = %q, want %q", key, got, want)
		}
	}
	for _, want := range []string{"127.0.0.1:10443:10443", "127.0.0.1:10444:10444", "127.0.0.1:10445:10445", "127.0.0.1:10446:10446", "127.0.0.1:10447:10447", "127.0.0.1:10448:10448"} {
		if !contains(cp.Ports, want) {
			t.Fatalf("partner lab trstctl ports = %v, missing real target listener %s", cp.Ports, want)
		}
	}
	if got := stringValue(cp.Environment["TRSTCTL_CONNECTORS_ENABLED"]); got != "apache,nginx,haproxy,caddy,traefik,postgresql" {
		t.Fatalf("partner lab enabled connectors = %q, want apache,nginx,haproxy,caddy,traefik,postgresql", got)
	}
	if got := stringValue(cp.Environment["TRSTCTL_AGENT_CHANNEL_CLAIMABLE_JOB_KINDS"]); !strings.Contains(got, "connector.deploy") || !strings.Contains(got, "connector.rollback") {
		t.Fatalf("partner lab claimable jobs = %q, want deploy and rollback", got)
	}
	// One host agent owns all six real processes. Six same-role agents could
	// otherwise race to claim a targetless endpoint.renew row and run it with the
	// wrong host allowlist. The combined target is both smaller and faithfully
	// models one edge host running several front doors.
	for _, name := range []string{"frontdoors-lab"} {
		service := cf.Services[name]
		if service.NetworkMode != "service:trstctl" {
			t.Fatalf("%s network_mode = %q, want service:trstctl", name, service.NetworkMode)
		}
		if service.User != "65532:65532" {
			t.Fatalf("%s user = %q, want nonroot 65532:65532", name, service.User)
		}
		if service.DependsOn["trstctl"].Condition != "service_healthy" || !service.DependsOn["trstctl"].Restart {
			t.Fatalf("%s must follow the control-plane network namespace across replacement", name)
		}
		if service.DependsOn["lab-bootstrap"].Condition != "service_completed_successfully" {
			t.Fatalf("%s must wait for bounded runtime token and baseline preparation", name)
		}
	}
}

func TestPartnerLabRunnerIsPersistentTruthfulAndSecretSafe(t *testing.T) {
	launcher := read(t, "lab", "run.sh")
	if !strings.Contains(launcher, "TRSTCTL_LAB_PROJECT:-trstctl-partner-lab") || !strings.Contains(launcher, "-p $lab_project") {
		t.Fatal("partner lab launcher must default and constrain its isolated Compose project name")
	}
	for _, want := range []string{
		"up -d --no-deps signer", "up -d --no-deps trstctl",
		"up -d --no-deps localstack-loopback", "run --rm --no-deps lab-runner",
		"DOD_CENSUS_OUT=", "make dod-gate", "Connector census evidence:",
		"TRSTCTL_LAB_RUN_DOD:-1", "live repair loop", "full qualification",
		"TRSTCTL_LAB_RUN_JOURNEYS:-1", "drive it yourself", `if [ "$run_journeys" -eq 1 ]; then`,
		"${lab_project}-control:local", "${lab_project}-seed:local", "${lab_project}-frontdoors:local",
		"dod_cache_parent", `chmod 0700 "$dod_cache_parent" "$dod_cache"`,
		"TRSTCTL_LAB_BUILD_COMMIT", "dirty-$lab_head", "TRSTCTL_LAB_BUILD_VERSION", "TRSTCTL_LAB_BUILD_DATE",
	} {
		if !strings.Contains(launcher, want) {
			t.Errorf("partner lab launcher is missing staged startup %q", want)
		}
	}
	runner := read(t, "lab", "journey-runner.mjs")
	for _, want := range []string{
		"apache", "nginx", "haproxy", "caddy", "traefik", "postgresql", "postgresTLSProbe", "connector-contract-census", "iis-windows-required",
		"continue_after_failure", "blocked_external", "before_fingerprint", "after_fingerprint",
		"listed.agents ?? []", "runtime-pebble-root.crt", "subject_alt_name", "sink_receipts_after",
		"network-discovery", "partner-lab-loopback", `agent.roles ?? []).includes(role)`,
		"allow_loopback: true", "-renew-and-rollback", `"recover"`, "rollback_queued", "rolled_back",
		"runNonce", "targetName", "planKey", "normalizedFingerprint", "waitForDelivery", "delivery_id", "renewal_delivery_id", "partner-lab-dry-run-${target.connector}-${created.target.id}", "candidate.outbox_id === queued.outbox_id", "-renew-${runNonce}", "-rollback-${runNonce}",
	} {
		if !strings.Contains(runner, want) {
			t.Errorf("partner lab runner is missing contract marker %q", want)
		}
	}
	labReadme := read(t, "lab", "README.md")
	for _, want := range []string{"TRSTCTL_LAB_RUN_JOURNEYS=0", "Drive it yourself", "Local Pebble DNS validation", "Allow loopback targets", "External CA: Local independent ACME lab CA (Pebble)"} {
		if !strings.Contains(labReadme, want) {
			t.Errorf("partner lab README no longer documents the start-only mode marker %q", want)
		}
	}
	bootstrap := read(t, "lab", "bootstrap.mjs")
	postgresConfig := read(t, "lab", "frontdoors", "postgresql.conf")
	if !strings.Contains(postgresConfig, "unix_socket_directories = '/lab/run'") {
		t.Error("partner lab PostgreSQL target must keep its Unix socket inside the nonroot-owned lab run directory")
	}
	for _, want := range []string{"/roots/0", "runtime-pebble-root.crt", `roles: ["host", "network"]`,
		"/api/v1/acme/dns-01/provider-configs", "partner-lab-dns-provider-v1", "allow_upstream_dv: true", "dns01_provider_config"} {
		if !strings.Contains(bootstrap, want) {
			t.Errorf("partner lab bootstrap is missing contract marker %q", want)
		}
	}
	for _, forbidden := range []string{"console.log(token", "console.log(bearer", "NODE_TLS_REJECT_UNAUTHORIZED"} {
		if strings.Contains(runner, forbidden) {
			t.Errorf("partner lab runner contains secret-unsafe pattern %q", forbidden)
		}
	}
	matrix := read(t, "lab", "journey-matrix.json")
	for _, want := range []string{"\"real_local\"", "\"faithful_local\"", "\"external_only\"", "\"iis\"", "\"f5\"", "\"haproxy\""} {
		if !strings.Contains(matrix, want) {
			t.Errorf("partner lab journey matrix is missing %s", want)
		}
	}
	if strings.Contains(matrix, "\"iis\": \"real_local\"") {
		t.Fatal("journey matrix must not classify IIS as real-local on Linux Docker")
	}
}

func TestDemoComposeIsSeparatePrepopulatedStack(t *testing.T) {
	cf := parseCompose(t)
	if cf.Name != "trstctl-demo" {
		t.Fatalf("demo compose name = %q, want trstctl-demo", cf.Name)
	}
	for _, want := range []string{"postgres", "nats", "localstack", "localstack-loopback", "localstack-signer-loopback", "managedkeys-config", "oidc-keys", "demo-oidc", "oidc-loopback", "signer", "trstctl", "demo-seed"} {
		if _, ok := cf.Services[want]; !ok {
			t.Fatalf("demo compose missing %s service", want)
		}
	}
	cp := cf.Services["trstctl"]
	if got := stringValue(cp.Build["target"]); got != "demo" {
		t.Fatalf("demo trstctl build target = %q, want demo", got)
	}
	for _, want := range []string{
		"127.0.0.1:9443:8443",
		"127.0.0.1:29443:9443",
		"127.0.0.1:29444:9444",
	} {
		if !contains(cp.Ports, want) {
			t.Fatalf("demo trstctl ports = %v, missing loopback-only publication %s", cp.Ports, want)
		}
	}
	if contains(cp.Ports, "127.0.0.1:19081:19081") {
		t.Fatalf("demo trstctl ports = %v, OIDC port belongs only to demo-oidc", cp.Ports)
	}
	for k, want := range map[string]string{ // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
		"TRSTCTL_AGENT_CHANNEL_CA_CERT_FILE":               "/data/ca/agent-ca.crt",
		"TRSTCTL_AGENT_CHANNEL_PUBLIC_ADDRESS":             "localhost:29443",
		"TRSTCTL_AGENT_CHANNEL_SERVER_NAME":                "localhost",
		"TRSTCTL_AGENT_CHANNEL_HTTP_RENEWAL_ADDR":          ":9444",
		"TRSTCTL_RATE_LIMIT_ENABLED":                       "true",
		"TRSTCTL_RATE_LIMIT_REQUESTS":                      "10000",
		"TRSTCTL_RATE_LIMIT_WINDOW":                        "1m",
		"TRSTCTL_CA_CERT_FILE":                             "/data/ca/issuing-ca.crt",
		"TRSTCTL_CA_PUBLIC_CERT_FILE":                      "/public-trust/issuing-ca.crt",
		"TRSTCTL_AUTH_OIDC_ENABLED":                        "true",
		"TRSTCTL_AUTH_OIDC_REDIRECT_URI":                   "https://127.0.0.1:9443/auth/callback",
		"TRSTCTL_AUTH_OIDC_AUTH_ENDPOINT":                  "http://127.0.0.1:19081/authorize",
		"TRSTCTL_AUTH_OIDC_TOKEN_ENDPOINT":                 "http://127.0.0.1:19081/token",
		"TRSTCTL_OUTBOUND_ENV_CREDENTIAL_REFS":             "env:TRSTCTL_DISCOVERY_AWS_ACCESS_KEY_ID,env:TRSTCTL_DISCOVERY_AWS_SECRET_ACCESS_KEY,env:TRSTCTL_DISCOVERY_GCP_TOKEN,env:TRSTCTL_DISCOVERY_AWS_SM_ACCESS_KEY_ID,env:TRSTCTL_DISCOVERY_AWS_SM_SECRET_ACCESS_KEY,env:TRSTCTL_DISCOVERY_GCP_SM_TOKEN",
		"TRSTCTL_SECRETS_ENABLE_API":                       "true",
		"TRSTCTL_SECRETS_AUTH_SECRET_FILE":                 "/data/secrets/machine-auth.bin",
		"TRSTCTL_SECRETS_AUTH_TOKEN_TENANT_ID":             "11111111-1111-4111-8111-111111111111",
		"TRSTCTL_SECRETS_AUTH_TOKEN_SCOPES":                "secrets:read",
		"TRSTCTL_LICENSE_FILE":                             "/etc/trstctl/demo-provider-license.json",
		"TRSTCTL_MANAGED_KEYS_ENABLED":                     "true",
		"TRSTCTL_MANAGED_KEYS_AWS_ENDPOINT":                "http://127.0.0.1:4566",
		"TRSTCTL_MANAGED_KEYS_AWS_ALLOW_INSECURE_LOOPBACK": "true",
		"TRSTCTL_MANAGED_KEYS_AWS_SECRET_ACCESS_KEY_FILE":  "/demo-managed-keys/aws-secret-access-key",
		"TRSTCTL_LIFECYCLE_RENEW_BEFORE":                   "5m",
		"TRSTCTL_PROTOCOLS_ACME_TENANT_ID":                 "11111111-1111-4111-8111-111111111111",
		"TRSTCTL_PROTOCOLS_EST_TENANT_ID":                  "11111111-1111-4111-8111-111111111111",
		"TRSTCTL_ATTESTED_ISSUANCE_ENABLED":                "true",
		"TRSTCTL_ATTESTED_ISSUANCE_TRUST_DOMAIN":           "demo.trstctl.local",
		"TRSTCTL_ATTESTED_ISSUANCE_DEFAULT_TTL":            "10m",
		"TRSTCTL_ATTESTED_ISSUANCE_MAX_TTL":                "1h",
		"TRSTCTL_EPHEMERAL_ISSUANCE_ENABLED":               "true",
		"TRSTCTL_EPHEMERAL_ISSUANCE_TRUST_DOMAIN":          "demo.trstctl.local",
		"TRSTCTL_EPHEMERAL_ISSUANCE_DEFAULT_TTL":           "5m",
		"TRSTCTL_EPHEMERAL_ISSUANCE_MAX_TTL":               "30m",
		"TRSTCTL_EPHEMERAL_ISSUANCE_APPROVAL_TTL":          "15m",
		"TRSTCTL_EPHEMERAL_ISSUANCE_REQUIRED_APPROVALS":    "1",
		"TRSTCTL_PROTOCOLS_SSH_ENABLED":                    "true",
		"TRSTCTL_PROTOCOLS_SSH_TENANT_ID":                  "11111111-1111-4111-8111-111111111111",
		"TRSTCTL_SERVER_TLS_INTERNAL_TRUST_FILE":           "/public-trust/control-plane.crt",
	} {
		if got := stringValue(cp.Environment[k]); got != want {
			t.Fatalf("demo trstctl env %s = %q, want %q", k, got, want)
		}
	}
	idp := cf.Services["demo-oidc"]
	if got := idp.NetworkMode; got != "" {
		t.Fatalf("demo OIDC IdP network_mode = %q, want default project network so host port publishing works", got)
	}
	if !contains(idp.Ports, "127.0.0.1:19081:19081") {
		t.Fatalf("demo OIDC IdP ports = %v, want loopback-only browser SSO port 127.0.0.1:19081:19081", idp.Ports)
	}
	if got := stringValue(idp.Environment["OIDC_REDIRECT_URI"]); got != "https://127.0.0.1:9443/auth/callback" {
		t.Fatalf("demo OIDC redirect allowlist = %q, want exact demo callback", got)
	}
	if got := cf.Services["oidc-loopback"].NetworkMode; got != "service:trstctl" {
		t.Fatalf("demo OIDC loopback proxy network_mode = %q, want service:trstctl for the validated loopback token endpoint", got)
	}
	if !cf.Services["oidc-loopback"].DependsOn["trstctl"].Restart {
		t.Fatal("demo OIDC loopback proxy must restart when Compose replaces/restarts trstctl's network namespace")
	}
	if got := cf.Services["localstack-loopback"].NetworkMode; got != "service:trstctl" {
		t.Fatalf("demo LocalStack loopback proxy network_mode = %q, want service:trstctl for the SSRF-guarded KMS endpoint", got)
	}
	if !cf.Services["localstack-loopback"].DependsOn["trstctl"].Restart {
		t.Fatal("demo LocalStack control-plane proxy must restart with trstctl's network namespace")
	}
	if got := cf.Services["localstack-signer-loopback"].NetworkMode; got != "service:signer" {
		t.Fatalf("demo signer LocalStack proxy network_mode = %q, want service:signer for the signer-local SSRF-guarded KMS endpoint", got)
	}
	if !cf.Services["localstack-signer-loopback"].DependsOn["signer"].Restart {
		t.Fatal("demo LocalStack signer proxy must restart with the signer's network namespace")
	}
	signer := cf.Services["signer"]
	if len(signer.Build) != 0 || signer.PullPolicy != "never" {
		t.Fatalf("demo signer must reuse the single trstctl demo build without pulling: build=%v pull_policy=%q", signer.Build, signer.PullPolicy)
	}
	if !contains(signer.Command, "--license=/etc/trstctl/demo-provider-license.json") {
		t.Fatalf("demo signer command = %v, want signed demo license", signer.Command)
	}
	if !contains(signer.Command, "--managed-keys-config=/demo-managed-keys/provider.json") {
		t.Fatalf("demo signer command = %v, want file-backed managed-key provider descriptor", signer.Command)
	}
	if got := signer.DependsOn["managedkeys-config"].Condition; got != "service_completed_successfully" {
		t.Fatalf("demo signer must wait for managed-key config, got %q", got)
	}
	seed := cf.Services["demo-seed"]
	if got := stringValue(seed.Build["dockerfile"]); got != "deploy/demo/Dockerfile.seed" {
		t.Fatalf("demo seed Dockerfile = %q", got)
	}
	if got := seed.DependsOn["trstctl"].Condition; got != "service_healthy" {
		t.Fatalf("demo seed must wait for a healthy control plane, got %q", got)
	}
	if strings.Contains(read(t, "seed.mjs"), "/trstctl-data/") {
		t.Fatal("demo seed still refers to the private control-plane data-volume alias")
	}
	if _, ok := seed.Environment["NODE_TLS_REJECT_UNAUTHORIZED"]; ok {
		t.Fatal("demo seed globally disables TLS verification")
	}
	if got := stringValue(seed.Environment["NODE_EXTRA_CA_CERTS"]); got != "/public-trust/control-plane.crt" {
		t.Fatalf("demo seed explicit TLS trust file = %q, want public control-plane certificate", got)
	}
	if contains(seed.Volumes, "trstctldata:/data:ro") || contains(seed.Volumes, "trstctldata:/trstctl-data:ro") {
		t.Fatalf("demo seed can read the private control-plane data volume: %v", seed.Volumes)
	}
	if !contains(seed.Volumes, "publictrust:/public-trust:ro") {
		t.Fatalf("demo seed lacks the public-only trust volume: %v", seed.Volumes)
	}
}

func TestDemoSeedSourceNeverLogsOneTimeCredentials(t *testing.T) {
	body := read(t, "seed.mjs")
	for _, forbidden := range []string{
		"One-time share token:",
		"Demo API token for ci-release-bot:",
		"Ephemeral incident token:",
		"Agent enrollment token:",
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("demo seed source still renders credential-bearing log label %q", forbidden)
		}
	}
	for _, line := range strings.Split(body, "\n") {
		if strings.Contains(line, "console.log") && strings.Contains(line, ".token") {
			t.Fatalf("demo seed log statement can render a token field: %s", strings.TrimSpace(line))
		}
	}
}

func TestDemoSeedSharesControlPlaneCustodyBoundaryAUD68(t *testing.T) {
	if err := validateDemoSeedCustody(parseCompose(t)); err != nil {
		t.Fatal(err)
	}
}

func TestDemoSeedCustodyGuardRejectsMissingOrWrongConfigurationAUD68(t *testing.T) {
	tests := []struct {
		name   string
		want   string
		mutate func(*composeFile)
	}{
		{
			name: "root admin identity",
			want: "demo-seed user",
			mutate: func(cf *composeFile) {
				seed := cf.Services["demo-seed"]
				seed.User = "0:0"
				cf.Services["demo-seed"] = seed
			},
		},
		{
			name: "root signer identity",
			want: "signer user",
			mutate: func(cf *composeFile) {
				signer := cf.Services["signer"]
				signer.User = "0:0"
				cf.Services["signer"] = signer
			},
		},
		{
			name: "root control identity",
			want: "trstctl user",
			mutate: func(cf *composeFile) {
				cp := cf.Services["trstctl"]
				cp.User = "0:0"
				cf.Services["trstctl"] = cp
			},
		},
		{
			name: "shared control image tag",
			want: "control image",
			mutate: func(cf *composeFile) {
				cp := cf.Services["trstctl"]
				cp.Image = "ctlplne-demo-control:local"
				cf.Services["trstctl"] = cp
			},
		},
		{
			name: "duplicate signer image builder",
			want: "single build owner",
			mutate: func(cf *composeFile) {
				signer := cf.Services["signer"]
				signer.Build = map[string]any{"context": "../.."}
				cf.Services["signer"] = signer
			},
		},
		{
			name: "signer may pull over local build",
			want: "pull policy",
			mutate: func(cf *composeFile) {
				signer := cf.Services["signer"]
				signer.PullPolicy = "missing"
				cf.Services["signer"] = signer
			},
		},
		{
			name: "missing control image builder",
			want: "control image build",
			mutate: func(cf *composeFile) {
				cp := cf.Services["trstctl"]
				cp.Build = nil
				cf.Services["trstctl"] = cp
			},
		},
		{
			name: "shared seed image tag",
			want: "demo-seed image",
			mutate: func(cf *composeFile) {
				seed := cf.Services["demo-seed"]
				seed.Image = "ctlplne-demo-seed:local"
				cf.Services["demo-seed"] = seed
			},
		},
		{
			name: "default relative KEK",
			want: "TRSTCTL_SECRETS_KEK_FILE",
			mutate: func(cf *composeFile) {
				seed := cf.Services["demo-seed"]
				seed.Environment["TRSTCTL_SECRETS_KEK_FILE"] = "data/secrets/kek.bin"
				cf.Services["demo-seed"] = seed
			},
		},
		{
			name: "control custody drift",
			want: "trstctl TRSTCTL_SECRETS_KEK_FILE",
			mutate: func(cf *composeFile) {
				cp := cf.Services["trstctl"]
				cp.Environment["TRSTCTL_SECRETS_KEK_FILE"] = "/other/kek.bin"
				cf.Services["trstctl"] = cp
			},
		},
		{
			name: "disposable child signer",
			want: "TRSTCTL_SIGNER_MODE",
			mutate: func(cf *composeFile) {
				seed := cf.Services["demo-seed"]
				seed.Environment["TRSTCTL_SIGNER_MODE"] = "child"
				cf.Services["demo-seed"] = seed
			},
		},
		{
			name: "missing signer authorizer",
			want: "TRSTCTL_SIGNER_AUTH_SECRET_FILE",
			mutate: func(cf *composeFile) {
				seed := cf.Services["demo-seed"]
				delete(seed.Environment, "TRSTCTL_SIGNER_AUTH_SECRET_FILE")
				cf.Services["demo-seed"] = seed
			},
		},
		{
			name: "wrong signer KEK command",
			want: "signer command",
			mutate: func(cf *composeFile) {
				signer := cf.Services["signer"]
				signer.Command = withoutString(signer.Command, "--kek=/data/secrets/kek.bin")
				signer.Command = append(signer.Command, "--kek=/other/kek.bin")
				cf.Services["signer"] = signer
			},
		},
		{
			name: "missing signer dependency",
			want: "signer dependency",
			mutate: func(cf *composeFile) {
				seed := cf.Services["demo-seed"]
				delete(seed.DependsOn, "signer")
				cf.Services["demo-seed"] = seed
			},
		},
		{
			name: "weak control dependency",
			want: "trstctl dependency",
			mutate: func(cf *composeFile) {
				seed := cf.Services["demo-seed"]
				seed.DependsOn["trstctl"] = composeDependency{Condition: "service_started"}
				cf.Services["demo-seed"] = seed
			},
		},
		{
			name: "missing secrets mount",
			want: "secrets volume",
			mutate: func(cf *composeFile) {
				seed := cf.Services["demo-seed"]
				seed.Volumes = withoutComposeMount(seed.Volumes, "secrets", "/data/secrets")
				cf.Services["demo-seed"] = seed
			},
		},
		{
			name: "writable secrets mount",
			want: "secrets volume",
			mutate: func(cf *composeFile) {
				seed := cf.Services["demo-seed"]
				seed.Volumes = withoutComposeMount(seed.Volumes, "secrets", "/data/secrets")
				seed.Volumes = append(seed.Volumes, "secrets:/data/secrets")
				cf.Services["demo-seed"] = seed
			},
		},
		{
			name: "wrong signer socket mount",
			want: "signersock volume",
			mutate: func(cf *composeFile) {
				seed := cf.Services["demo-seed"]
				seed.Volumes = withoutComposeMount(seed.Volumes, "signersock", "/run/trstctl")
				seed.Volumes = append(seed.Volumes, "other-socket:/run/trstctl")
				cf.Services["demo-seed"] = seed
			},
		},
		{
			name: "private control data exposed",
			want: "exact custody mount allowlist",
			mutate: func(cf *composeFile) {
				seed := cf.Services["demo-seed"]
				seed.Volumes = append(seed.Volumes, "trstctldata:/data:ro")
				cf.Services["demo-seed"] = seed
			},
		},
		{
			name: "writable public trust mount",
			want: "public trust volume",
			mutate: func(cf *composeFile) {
				seed := cf.Services["demo-seed"]
				seed.Volumes = withoutComposeMount(seed.Volumes, "publictrust", "/public-trust")
				seed.Volumes = append(seed.Volumes, "publictrust:/public-trust")
				cf.Services["demo-seed"] = seed
			},
		},
		{
			name: "signer keys at alternate target",
			want: "exact custody mount allowlist",
			mutate: func(cf *composeFile) {
				seed := cf.Services["demo-seed"]
				seed.Volumes = append(seed.Volumes, "signerkeys:/not-the-default-target:ro")
				cf.Services["demo-seed"] = seed
			},
		},
		{
			name: "unexpected custody alias",
			want: "exact custody mount allowlist",
			mutate: func(cf *composeFile) {
				seed := cf.Services["demo-seed"]
				seed.Volumes = append(seed.Volumes, "other-volume:/data/signer:ro")
				cf.Services["demo-seed"] = seed
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cf := parseCompose(t)
			test.mutate(&cf)
			err := validateDemoSeedCustody(cf)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("custody guard error=%v, want error containing %q", err, test.want)
			}
		})
	}
}

func TestDemoSeedCustodyGuardMutatesEverySharedAuthorityAUD68(t *testing.T) {
	for _, key := range []string{
		"TRSTCTL_AUDIT_SIGNING_KEY_FILE",
		"TRSTCTL_SIGNER_MODE",
		"TRSTCTL_SIGNER_SOCKET",
		"TRSTCTL_SIGNER_ALLOW_CO_RESIDENT_AUTHORIZER",
		"TRSTCTL_SIGNER_AUTH_SECRET_FILE",
		"TRSTCTL_SECRETS_KEK_FILE",
	} {
		key := key
		for _, serviceName := range []string{"trstctl", "demo-seed"} {
			serviceName := serviceName
			t.Run(serviceName+"/"+key, func(t *testing.T) {
				cf := parseCompose(t)
				service := cf.Services[serviceName]
				delete(service.Environment, key)
				cf.Services[serviceName] = service
				err := validateDemoSeedCustody(cf)
				if err == nil || !strings.Contains(err.Error(), key) {
					t.Fatalf("custody guard error=%v, want error containing %q", err, key)
				}
			})
		}
	}
	for _, command := range []string{
		"--socket=/run/trstctl/signer.sock",
		"--kek=/data/secrets/kek.bin",
		"--auth-secret=/data/secrets/sign-auth.bin",
		"--legacy-audit-key=/data/audit/signing-key.pem",
	} {
		command := command
		t.Run("signer-command/"+command, func(t *testing.T) {
			cf := parseCompose(t)
			signer := cf.Services["signer"]
			signer.Command = withoutString(signer.Command, command)
			cf.Services["signer"] = signer
			err := validateDemoSeedCustody(cf)
			if err == nil || !strings.Contains(err.Error(), command) {
				t.Fatalf("custody guard error=%v, want error containing %q", err, command)
			}
		})
	}
	t.Run("seed-ca-view-missing", func(t *testing.T) {
		cf := parseCompose(t)
		seed := cf.Services["demo-seed"]
		seed.Volumes = withoutComposeMount(seed.Volumes, "publictrust", "/public-trust")
		cf.Services["demo-seed"] = seed
		err := validateDemoSeedCustody(cf)
		if err == nil || !strings.Contains(err.Error(), "public trust volume") {
			t.Fatalf("custody guard error=%v, want public trust volume refusal", err)
		}
	})
	t.Run("signer-socket-read-only", func(t *testing.T) {
		cf := parseCompose(t)
		seed := cf.Services["demo-seed"]
		seed.Volumes = withoutComposeMount(seed.Volumes, "signersock", "/run/trstctl")
		seed.Volumes = append(seed.Volumes, "signersock:/run/trstctl:ro")
		cf.Services["demo-seed"] = seed
		err := validateDemoSeedCustody(cf)
		if err == nil || !strings.Contains(err.Error(), "signersock volume") {
			t.Fatalf("custody guard error=%v, want writable signersock refusal", err)
		}
	})
}

func TestDemoSignerCustodyGuardRejectsDuplicateFlagsAndKeyMountDriftAUD68(t *testing.T) {
	for _, command := range []string{
		"--socket=/run/trstctl/signer.sock",
		"--kek=/data/secrets/kek.bin",
		"--auth-secret=/data/secrets/sign-auth.bin",
		"--legacy-audit-key=/data/audit/signing-key.pem",
	} {
		command := command
		t.Run("duplicate/"+command, func(t *testing.T) {
			cf := parseCompose(t)
			signer := cf.Services["signer"]
			signer.Command = append(signer.Command, command)
			cf.Services["signer"] = signer
			err := validateDemoSeedCustody(cf)
			if err == nil || !strings.Contains(err.Error(), "exact signer command") {
				t.Fatalf("custody guard error=%v, want duplicate signer flag refusal", err)
			}
		})
	}
	t.Run("keystore drift", func(t *testing.T) {
		cf := parseCompose(t)
		signer := cf.Services["signer"]
		signer.Command = withoutString(signer.Command, "--keystore=/data/signer/keys")
		signer.Command = append(signer.Command, "--keystore=/other/keys")
		cf.Services["signer"] = signer
		err := validateDemoSeedCustody(cf)
		if err == nil || !strings.Contains(err.Error(), "exact signer command") {
			t.Fatalf("custody guard error=%v, want keystore drift refusal", err)
		}
	})
	t.Run("appended spaced kek override", func(t *testing.T) {
		cf := parseCompose(t)
		signer := cf.Services["signer"]
		signer.Command = append(signer.Command, "--kek", "/alt")
		cf.Services["signer"] = signer
		err := validateDemoSeedCustody(cf)
		if err == nil || !strings.Contains(err.Error(), "exact signer command") {
			t.Fatalf("custody guard error=%v, want spaced KEK override refusal", err)
		}
	})
	t.Run("appended single-dash kek override", func(t *testing.T) {
		cf := parseCompose(t)
		signer := cf.Services["signer"]
		signer.Command = append(signer.Command, "-kek=/alt")
		cf.Services["signer"] = signer
		err := validateDemoSeedCustody(cf)
		if err == nil || !strings.Contains(err.Error(), "exact signer command") {
			t.Fatalf("custody guard error=%v, want single-dash KEK override refusal", err)
		}
	})
	t.Run("missing signerkeys", func(t *testing.T) {
		cf := parseCompose(t)
		signer := cf.Services["signer"]
		signer.Volumes = withoutComposeMount(signer.Volumes, "signerkeys", "/data/signer")
		cf.Services["signer"] = signer
		err := validateDemoSeedCustody(cf)
		if err == nil || !strings.Contains(err.Error(), "exact signer custody mount allowlist") {
			t.Fatalf("custody guard error=%v, want missing signerkeys refusal", err)
		}
	})
	t.Run("signerkeys wrong signer target", func(t *testing.T) {
		cf := parseCompose(t)
		signer := cf.Services["signer"]
		signer.Volumes = withoutComposeMount(signer.Volumes, "signerkeys", "/data/signer")
		signer.Volumes = append(signer.Volumes, "signerkeys:/other")
		cf.Services["signer"] = signer
		err := validateDemoSeedCustody(cf)
		if err == nil || !strings.Contains(err.Error(), "exact signer custody mount allowlist") {
			t.Fatalf("custody guard error=%v, want wrong signerkeys target refusal", err)
		}
	})
	t.Run("control signerkeys", func(t *testing.T) {
		cf := parseCompose(t)
		cp := cf.Services["trstctl"]
		cp.Volumes = append(cp.Volumes, "signerkeys:/stolen:ro")
		cf.Services["trstctl"] = cp
		err := validateDemoSeedCustody(cf)
		if err == nil || !strings.Contains(err.Error(), "exact control custody mount allowlist") {
			t.Fatalf("custody guard error=%v, want control signerkeys refusal", err)
		}
	})
}

func TestDemoImageUsesRealOfflineLicenseWithoutShippingItsSigningKey(t *testing.T) {
	body := read(t, "..", "docker", "Dockerfile")
	for _, want := range []string{
		"FROM build AS demo-build",
		"FROM runtime AS demo",
		"trstctl-license sign",
		"internal/license.builtinPubKeysB64",
		"rm -f /tmp/trstctl-license /tmp/demo-license-private.pem /tmp/demo-license-public.pem",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("demo image license path missing %q", want)
		}
	}
}

func TestDemoDocsKeepCommandsDistinct(t *testing.T) {
	body := read(t, "README.md")
	for _, want := range []string{
		"docker compose -f deploy/demo/docker-compose.yml up --build",
		"node deploy/demo/seed.mjs --check",
		"180-day",
		"https://127.0.0.1:9443",
		"docker compose -f deploy/docker/docker-compose.yml up --build",
		"down --volumes",
		"bash deploy/demo/aud68-custody-proof.sh",
		"unique Compose project",
		"mode-0600 files",
		"wrong and missing custody",
		"locally reachable Docker Engine",
		"Host ports 9443",
		"project-unique tags",
		"lacks Compose labels",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("demo README missing %q", want)
		}
	}
	ops := read(t, "..", "docker", "docker-compose.yml")
	if strings.Contains(ops, "demo-seed") || strings.Contains(ops, "trstctl-demo") || strings.Contains(ops, "19081:19081") {
		t.Fatal("operational/eval compose picked up demo-only services or ports")
	}
}

func TestDemoBrowserTestsUseTheOIDCCanonicalOrigin(t *testing.T) {
	playwright := read(t, "..", "..", "web", "playwright.config.ts")
	workflow := read(t, "..", "..", ".github", "workflows", "ci.yml")
	for label, body := range map[string]string{
		"Playwright default": playwright,
		"CI readiness URL":   workflow,
	} {
		if !strings.Contains(body, "https://127.0.0.1:9443") {
			t.Fatalf("%s must use the exact demo OIDC origin so the host-scoped pre-login cookie survives the callback", label)
		}
		if strings.Contains(body, "https://localhost:9443") {
			t.Fatalf("%s uses localhost, but the demo OIDC callback is allowlisted on 127.0.0.1", label)
		}
	}
}

func TestAUD68CustodyProofIsScopedFreshAndFailClosed(t *testing.T) {
	body := read(t, "aud68-custody-proof.sh")
	if err := validateAUD68ProofSource(body); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "-n", "aud68-custody-proof.sh")
	cmd.Dir = "."
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("AUD-68 proof is not valid bash: %v\n%s", err, out)
	}
}

func TestAUD68ProofVolumeCensusMatchesEveryComposeVolume(t *testing.T) {
	got, err := shellArrayValues(read(t, "aud68-custody-proof.sh"), "proof_volumes")
	if err != nil {
		t.Fatal(err)
	}
	cf := parseCompose(t)
	want := make([]string, 0, len(cf.Volumes))
	for name := range cf.Volumes {
		want = append(want, name)
	}
	if !sameStringSet(got, want) {
		t.Fatalf("AUD-68 exact volume census=%v, want every top-level Compose volume %v", got, want)
	}
}

func TestAUD68CustodyProofGuardRejectsBrokenLiveContracts(t *testing.T) {
	body := read(t, "aud68-custody-proof.sh")
	tests := []struct {
		name        string
		old         string
		replacement string
		want        string
	}{
		{
			name:        "shared image tag",
			old:         `export TRSTCTL_DEMO_CONTROL_IMAGE="${proof_control_image}"`,
			replacement: `export TRSTCTL_DEMO_CONTROL_IMAGE="ctlplne-demo-control:local"`,
			want:        "project-unique control image",
		},
		{
			name:        "missing exact volume collision check",
			old:         `assert_named_object_absent volume "${proof_project}_${volume_name}"`,
			replacement: `: "${proof_project}_${volume_name}"`,
			want:        "exact volume collision",
		},
		{
			name:        "missing exact container collision check",
			old:         `assert_named_object_absent container "${proof_project}-${service_name}-1"`,
			replacement: `: "${proof_project}-${service_name}-1"`,
			want:        "exact container collision",
		},
		{
			name:        "missing exact network collision check",
			old:         `assert_named_object_absent network "${proof_project}_default"`,
			replacement: `: "${proof_project}_default"`,
			want:        "exact network collision",
		},
		{
			name:        "missing exact image collision check",
			old:         `assert_named_object_absent image "${proof_control_image}"`,
			replacement: `: "${proof_control_image}"`,
			want:        "exact control image collision",
		},
		{
			name:        "missing exact image cleanup",
			old:         `docker image rm "${proof_image}"`,
			replacement: `docker image inspect "${proof_image}"`,
			want:        "exact proof image cleanup",
		},
		{
			name:        "wrong KEK init joins project custody",
			old:         `docker run --rm --network none --read-only`,
			replacement: `"${compose[@]}" run -T --rm --no-deps --user 65532:65532`,
			want:        "standalone networkless wrong-KEK initializer",
		},
		{
			name:        "wrong KEK init regains root",
			old:         `--user 65532:65532`,
			replacement: `--user 0:0`,
			want:        "nonroot wrong-KEK identity",
		},
		{
			name:        "wrong KEK init regains chown capability",
			old:         `--cap-drop ALL`,
			replacement: `--cap-drop ALL --cap-add CHOWN`,
			want:        "added capability",
		},
		{
			name:        "wrong KEK init writes outside isolated volume",
			old:         `head -c 32 /dev/urandom > /tmp/kek.bin`,
			replacement: `head -c 32 /dev/urandom > /wrong-kek/kek.bin`,
			want:        "exact wrong-KEK output",
		},
		{
			name:        "wrong KEK init mount drifts from temporary directory",
			old:         `--mount "type=volume,src=${wrong_kek_volume},dst=/tmp"`,
			replacement: `--mount "type=volume,src=${wrong_kek_volume},dst=/wrong-kek"`,
			want:        "wrong-KEK-only temporary mount",
		},
		{
			name:        "wrong KEK consumer mount becomes writable",
			old:         `--volume "${wrong_kek_volume}:/wrong-kek:ro"`,
			replacement: `--volume "${wrong_kek_volume}:/wrong-kek"`,
			want:        "read-only wrong-KEK consumer mount",
		},
		{
			name:        "loose token syntax",
			old:         `[[ "${loaded_token}" =~ ^trst_[A-Za-z0-9_-]{43}$ ]]`,
			replacement: `[[ "${loaded_token}" == trst_* ]]`,
			want:        "exact token syntax",
		},
		{
			name:        "trailing token output accepted",
			old:         `cmp -s -- "${path}" <(printf '%s\n' "${loaded_token}")`,
			replacement: `test -s "${path}"`,
			want:        "whole token file byte comparison",
		},
		{
			name:        "empty certificate items accepted",
			old:         `(.items | (type == "array" and length > 0))`,
			replacement: `(.items | type == "array")`,
			want:        "nonempty seeded certificate list",
		},
		{
			name:        "empty object accepted",
			old:         "type == \"object\" and\n    (.items | (type == \"array\" and length > 0))",
			replacement: "(. == {}) or\n    true",
			want:        "certificate-list object",
		},
		{
			name:        "wrong tenant accepted",
			old:         `(.tenant_id == $tenant)`,
			replacement: `(.tenant_id | type == "string")`,
			want:        "certificate item tenant",
		},
		{
			name:        "token state count only",
			old:         `jsonb_build_array(id::text, tenant_id::text, token_hash, subject, subject_ref, scopes, expires_at, created_at, revoked_at, revoked_by, revocation_reason) ORDER BY id`,
			replacement: `jsonb_build_array(count(*))`,
			want:        "token authority columns",
		},
		{
			name:        "scope assertion removed",
			old:         `assert_subject_scopes "${subject}"`,
			replacement: `: "${subject}"`,
			want:        "exact minted subject scopes",
		},
		{
			name:        "event freeze removed",
			old:         `"${compose[@]}" stop trstctl`,
			replacement: `"${compose[@]}" start trstctl`,
			want:        "freeze-before-failure order",
		},
		{
			name:        "all-stream head removed",
			old:         `const accounts = Array.isArray(payload.account_details) ? payload.account_details : [];`,
			replacement: `const accounts = [];`,
			want:        "all JetStream account details",
		},
		{
			name:        "compose feature preflight removed",
			old:         `docker compose wait --help >/dev/null`,
			replacement: `docker compose version >/dev/null`,
			want:        "Compose wait prerequisite",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := replaceExactlyOnce(t, body, test.old, test.replacement)
			err := validateAUD68ProofSource(mutated)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("proof guard error=%v, want error containing %q", err, test.want)
			}
		})
	}
}

func TestDemoSeedCheckModeCoversHistoryAndSurfaces(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "node", "seed.mjs", "--check")
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("demo seed --check timed out; it must be an offline dry-run, output:\n%s", out)
	}
	if err != nil {
		t.Fatalf("demo seed --check failed: %v\n%s", err, out)
	}
	body := string(out)
	for _, want := range []string{
		"trstctl demo seed check passed",
		"180-day history",
		"issuers",
		"agents",
		"managed certificates",
		"discovered certificates",
		"jobs and runs",
		"deploys",
		"connector targets",
		"audit",
		"notifications",
		"no secret material",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("demo seed --check output missing %q:\n%s", want, body)
		}
	}
}

func TestDemoSeedPreparesTruthfulConnectorPitchTargets(t *testing.T) {
	body := read(t, "seed.mjs")
	for _, want := range []string{
		`const seedVersion = "demo-seed-v3"`,
		`name: "Apache payments web tier (prepared, not contacted)"`,
		`name: "IIS customer portal (prepared, not contacted)"`,
		`name: "F5 edge HA pair (prepared, API-double proof only)"`,
		`proof_state: "prepared_not_contacted"`,
		`preparedConnector: "apache"`,
		`preparedConnector: "iis"`,
		`preparedConnector: "f5"`,
		`intended_connector: item.preparedConnector`,
		`required_agent_role: "host"`,
		`required_agent_role: "network"`,
		`"POST /api/v1/connectors/targets"`,
		`async function ensureConnectorTarget`,
		`connector_targets: history.connectorTargets.map`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("demo seed is missing truthful connector-pitch marker %q", want)
		}
	}
	for _, forbidden := range []string{
		`proof_state: "verified"`,
		`proof_state: "deployed"`,
		`hardware_tested: true`,
		`connectorTargetKey:`,
	} {
		if strings.Contains(body, forbidden) {
			t.Errorf("demo seed overstates connector proof with %q", forbidden)
		}
	}
}

func TestDemoSeedWritesProtectedRedactedFailureDiagnostic(t *testing.T) {
	body := read(t, "seed.mjs")
	for _, want := range []string{
		`const seedDiagnosticFile = "/seed-state/last-error.txt"`,
		`function redactSeedDiagnostic`,
		`writeFileSync(seedDiagnosticFile`,
		`mode: 0o600`,
		`main().catch((error) =>`,
		`redactSeedDiagnostic`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("demo seed failure diagnostics are missing %q", want)
		}
	}
	if strings.Contains(body, `console.error(error)`) || strings.Contains(body, `console.error(String(error))`) {
		t.Fatal("demo seed writes a raw error object to shared Docker logs")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	probe := `
import { redactSeedDiagnostic } from "./seed.mjs";
const pem = '-----BEGIN PRIVATE ' + 'KEY-----\\nmaterial\\n-----END PRIVATE ' + 'KEY-----';
const raw = 'POST /api/v1/test returned 400: {"password":"hunter2","token":"abc123","authorization":"Bearer ey.secret","private_key":"' + pem + '"}';
const got = redactSeedDiagnostic(new Error(raw));
for (const secret of ["hunter2", "abc123", "ey.secret", "material"]) {
  if (got.includes(secret)) throw new Error("diagnostic retained secret: " + secret);
}
if (!got.includes("POST /api/v1/test returned 400")) throw new Error("diagnostic removed actionable route/status context");
`
	cmd := exec.CommandContext(ctx, "node", "--input-type=module", "--eval", probe)
	cmd.Dir = "."
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("redacted seed diagnostic probe failed: %v\n%s", err, out)
	}
}

func TestDemoSeedExercisesManagedKeyDualControl(t *testing.T) {
	body := read(t, "seed.mjs")
	for _, want := range []string{
		`"/api/v1/managed-keys/approvals"`,
		`"/api/v1/approval-requests?status=pending&limit=100"`,
		`"demo-key-custodian-one"`,
		`"demo-key-custodian-two"`,
		`rotateKey, [403]`,
		`request.resource_kind === "managed_key"`,
		`request.resource_id === managedKey.key_id`,
		`request.action === "managedkey:rotate"`,
		`request.requester === "demo-seeder"`,
		`request_id: approvalRequest.id`,
		`intent_digest: approvalRequest.intent_digest`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("demo managed-key seed missing dual-control proof %q", want)
		}
	}
	if err := requireSourceOrder(body, []string{
		`const rotateAttempt = await api("POST", "/api/v1/managed-keys/rotate"`,
		`if (rotateAttempt?.status === 403)`,
		`"/api/v1/approval-requests?status=pending&limit=100"`,
		`matchingRequests.length !== 1`,
		`request_id: approvalRequest.id`,
		`for (const [index, subject] of ["demo-key-custodian-one", "demo-key-custodian-two"].entries())`,
		`await api("POST", "/api/v1/managed-keys/rotate", rotateBody, rotateKey)`,
	}); err != nil {
		t.Fatalf("demo managed-key exact approval flow: %v", err)
	}
}

func TestDemoSeedUsesOnlyEventSourcedSingleSecretWrites(t *testing.T) {
	body := read(t, "seed.mjs")
	if strings.Contains(body, `"/api/v1/secrets/store/import"`) {
		t.Fatal("demo seed invokes the intentionally unavailable non-event-sourced bulk import route")
	}
	for _, want := range []string{
		`ensureSecret("demo/stripe/api-key", "demo-stripe-api-key", 1, owners.payments.id, secretItems)`,
		`ensureSecret("demo/github/actions/deploy-token", "demo-github-actions-deploy-token", 1, owners.release.id, secretItems)`,
		`ensureSecret("demo/aws/iam/rotator", "demo-aws-iam-rotator", 1, owners.platform.id, secretItems)`,
		`owner_id: ownerID`,
		"stableKey(`secret-${valueLabel}`)",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("demo seed missing event-sourced single-secret write %q", want)
		}
	}
}

func TestDemoOIDCPrivateKeyIsGeneratedNotCommitted(t *testing.T) {
	privateKeyPEMHeader := "BEGIN " + "PRIVATE KEY"
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if strings.HasSuffix(path, ".pem") || strings.HasSuffix(path, ".key") {
			t.Fatalf("demo must not commit private key material: %s", path)
		}
		body := read(t, path)
		if strings.Contains(body, privateKeyPEMHeader) {
			t.Fatalf("demo file commits private key material: %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func contains(values []string, want string) bool {
	for _, got := range values {
		if got == want {
			return true
		}
	}
	return false
}

func stringValue(v any) string {
	switch x := v.(type) {
	case string:
		return x
	default:
		return ""
	}
}

func validateAUD68ProofSource(body string) error {
	code := activeShellSource(body)
	required := []struct {
		label  string
		needle string
	}{
		{label: "private temporary directory", needle: `proof_tmp="$(mktemp -d`},
		{label: "generated project", needle: `proof_project="trstctl-demo-custody-proof-${proof_suffix}"`},
		{label: "project-unique control image name", needle: `readonly proof_control_image="ctlplne-demo-control:aud68-${proof_suffix}"`},
		{label: "project-unique seed image name", needle: `readonly proof_seed_image="ctlplne-demo-seed:aud68-${proof_suffix}"`},
		{label: "project-unique control image", needle: `export TRSTCTL_DEMO_CONTROL_IMAGE="${proof_control_image}"`},
		{label: "project-unique seed image", needle: `export TRSTCTL_DEMO_SEED_IMAGE="${proof_seed_image}"`},
		{label: "complete service-name collision census", needle: "readonly -a proof_services=(\n  postgres nats localstack oidc-keys managedkeys-config signer trstctl demo-oidc\n  oidc-loopback localstack-loopback localstack-signer-loopback demo-seed\n)"},
		{label: "complete volume-name collision census", needle: "readonly -a proof_volumes=(\n  pgdata natsdata localstack signersock signerkeys seedstate secrets trstctldata publictrust demoidp managedkeys\n)"},
		{label: "exact container collision", needle: `assert_named_object_absent container "${proof_project}-${service_name}-1"`},
		{label: "exact volume collision", needle: `assert_named_object_absent volume "${proof_project}_${volume_name}"`},
		{label: "exact network collision", needle: `assert_named_object_absent network "${proof_project}_default"`},
		{label: "exact control image collision", needle: `assert_named_object_absent image "${proof_control_image}"`},
		{label: "exact seed image collision", needle: `assert_named_object_absent image "${proof_seed_image}"`},
		{label: "exact proof image cleanup", needle: `docker image rm "${proof_image}"`},
		{label: "both proof image cleanup targets", needle: `for proof_image in "${proof_seed_image}" "${proof_control_image}"`},
		{label: "project-scoped Compose command", needle: `compose=(docker compose -p "${proof_project}" -f "${compose_file}")`},
		{label: "exact project cleanup", needle: `"${compose[@]}" down --volumes --remove-orphans`},
		{label: "standalone networkless wrong-KEK initializer", needle: `docker run --rm --network none --read-only`},
		{label: "wrong-KEK-only temporary mount", needle: `--mount "type=volume,src=${wrong_kek_volume},dst=/tmp"`},
		{label: "nonroot wrong-KEK identity", needle: `--user 65532:65532`},
		{label: "exact wrong-KEK output", needle: `head -c 32 /dev/urandom > /tmp/kek.bin`},
		{label: "owner-only wrong-KEK mode", needle: `chmod 0600 /tmp/kek.bin`},
		{label: "exact wrong-KEK size check", needle: `test "$(wc -c < /tmp/kek.bin)" -eq 32`},
		{label: "exact wrong-KEK owner check", needle: `test "$(stat -c %u:%g /tmp/kek.bin)" = "65532:65532"`},
		{label: "exact wrong-KEK mode check", needle: `test "$(stat -c %a /tmp/kek.bin)" = "600"`},
		{label: "read-only wrong-KEK consumer mount", needle: `--volume "${wrong_kek_volume}:/wrong-kek:ro"`},
		{label: "whole token file load", needle: `loaded_token="$(<"${path}")"`},
		{label: "whole token file byte comparison", needle: `cmp -s -- "${path}" <(printf '%s\n' "${loaded_token}")`},
		{label: "exact token syntax", needle: `[[ "${loaded_token}" =~ ^trst_[A-Za-z0-9_-]{43}$ ]]`},
		{label: "verified TLS with stdin-only bearer config", needle: `curl --silent --show-error --cacert "${proof_tls_trust}" --config -`},
		{label: "public trust extraction", needle: `"${compose[@]}" cp trstctl:/public-trust/control-plane.crt "${proof_tls_trust}"`},
		{label: "parsed certificate-list response", needle: `jq -e --arg tenant "${tenant_id}" '`},
		{label: "certificate-list object", needle: `type == "object" and`},
		{label: "nonempty seeded certificate list", needle: `(.items | (type == "array" and length > 0))`},
		{label: "certificate item UUID", needle: `(.id | (type == "string" and test("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")))`},
		{label: "certificate item tenant", needle: `(.tenant_id == $tenant)`},
		{label: "certificate item subject", needle: `(.subject | (type == "string" and length > 0))`},
		{label: "certificate item fingerprint", needle: `(.fingerprint | (type == "string" and test("^[0-9a-f]{64}$")))`},
		{label: "certificate item status", needle: `((.status == "active") or (.status == "superseded") or (.status == "revoked"))`},
		{label: "exact minted subject scopes", needle: `assert_subject_scopes "${subject}"`},
		{label: "canonical SQL authority digest", needle: `encode(sha256(convert_to(coalesce(jsonb_agg(jsonb_build_array(`},
		{label: "tenant authority columns", needle: `tenant_id::text, name, created_at, event_seq`},
		{label: "token authority columns", needle: `id::text, tenant_id::text, token_hash, subject, subject_ref, scopes, expires_at, created_at, revoked_at, revoked_by, revocation_reason`},
		{label: "bootstrap authority columns", needle: `tenant_id::text, key, status, encode(result, 'hex'), created_at, completed_at, request_binding, result_codec`},
		{label: "all JetStream account details", needle: `payload.account_details`},
		{label: "all JetStream stream details", needle: `account.stream_detail`},
		{label: "wrong custody failure", needle: `"wrong read-only custody mount" "seal: decrypt failed"`},
		{label: "missing custody failure", needle: `TRSTCTL_SECRETS_KEK_FILE=/data/secrets/aud68-missing-kek.bin`},
		{label: "admin token container", needle: `--entrypoint /usr/local/bin/trstctl demo-seed token create`},
		{label: "control token container", needle: `"${compose[@]}" exec -T trstctl /usr/local/bin/trstctl token create`},
		{label: "Compose wait prerequisite", needle: `docker compose wait --help >/dev/null`},
		{label: "Compose wait-timeout prerequisite", needle: `[[ "${compose_up_help}" == *"--wait-timeout"* ]]`},
		{label: "jq/cmp prerequisites", needle: `for required in docker curl jq cmp`},
		{label: "Docker daemon prerequisite", needle: `docker info >/dev/null`},
		{label: "bounded restart failure branch", needle: `if ! "${compose[@]}" up -d --wait --wait-timeout 120 signer trstctl; then`},
		{label: "exact restart control state", needle: `docker inspect --format 'status={{.State.Status}} exit={{.State.ExitCode}} error={{json .State.Error}} health={{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}'`},
		{label: "bounded restart control logs", needle: `docker logs --tail 120 "${proof_project}-trstctl-1"`},
		{label: "restart token redaction", needle: `s/trst_[A-Za-z0-9_-]{43}/[REDACTED_TOKEN]/g`},
		{label: "restart DSN-password redaction", needle: `s#(postgres://[^:/@]+:)[^@[:space:]]+@#\1[REDACTED]@#g`},
	}
	for _, requirement := range required {
		if !strings.Contains(code, requirement.needle) {
			return fmt.Errorf("AUD-68 proof: missing live %s contract %q", requirement.label, requirement.needle)
		}
	}
	for _, exact := range []struct {
		label  string
		needle string
		count  int
	}{
		{label: "canonical SQL authority digests", needle: `encode(sha256(convert_to(coalesce(jsonb_agg(jsonb_build_array(`, count: 5},
		{label: "tenant authority digests", needle: `tenant_id::text, name, created_at, event_seq`, count: 2},
		{label: "token authority digest", needle: `id::text, tenant_id::text, token_hash, subject, subject_ref, scopes, expires_at, created_at, revoked_at, revoked_by, revocation_reason`, count: 1},
		{label: "bootstrap authority digests", needle: `tenant_id::text, key, status, encode(result, 'hex'), created_at, completed_at, request_binding, result_codec`, count: 2},
		{label: "seed/admin token invocations", needle: `--entrypoint /usr/local/bin/trstctl demo-seed token create`, count: 3},
	} {
		if count := strings.Count(code, exact.needle); count != exact.count {
			return fmt.Errorf("AUD-68 proof: %s appear %d times, want %d", exact.label, count, exact.count)
		}
	}
	for _, forbidden := range []string{
		"docker compose down",
		"docker compose -f deploy/demo/docker-compose.yml down --volumes",
		"proof_project=trstctl-demo-custody-proof\n",
		"Authorization: Bearer $token\" https://",
		`IFS= read -r token <"${path}"`,
		`"${compose[@]}" run -T --rm --no-deps --user 0:0`,
		`--user=0:0`,
		`SELECT token_hash`,
		"ctlplne-demo-control:local\"\nexport TRSTCTL_DEMO_CONTROL_IMAGE",
	} {
		if strings.Contains(code, forbidden) {
			return fmt.Errorf("AUD-68 proof: unsafe live source %q", forbidden)
		}
	}
	if err := requireSourceOrder(code, []string{
		"assert_project_is_fresh\n",
		"proof_namespace_owned=1\n",
		`"${compose[@]}" up -d --build`,
		`"${compose[@]}" stop trstctl`,
		`before_sql="$(snapshot_sql_state)"`,
		`before_event_head="$(snapshot_event_head)"`,
		`docker volume create`,
		`docker run --rm --network none --read-only`,
		`"wrong read-only custody mount" "seal: decrypt failed"`,
		`assert_state_unchanged "wrong read-only custody mount"`,
		`"missing deployment KEK" "bootstrap: provision credential KEK"`,
		`assert_state_unchanged "missing deployment KEK"`,
		`"${compose[@]}" restart signer`,
		`assert_registration_authority_unchanged "control and signer restart"`,
		`assert_scoped_read "${control_before_token}" "control-token-after-restart"`,
	}); err != nil {
		return fmt.Errorf("AUD-68 proof: freeze-before-failure order: %w", err)
	}
	if err := requireSourceOrder(code, []string{
		`if (( proof_started )); then`,
		`"${compose[@]}" down --volumes --remove-orphans`,
		`if (( proof_namespace_owned )); then`,
		`docker image rm "${proof_image}"`,
	}); err != nil {
		return fmt.Errorf("AUD-68 proof: containers-before-images cleanup order: %w", err)
	}
	initializerStart := strings.Index(code, `docker run --rm --network none --read-only`)
	if initializerStart < 0 {
		return fmt.Errorf("AUD-68 proof: missing bounded wrong-KEK initializer block")
	}
	initializerEnd := strings.Index(code[initializerStart:], "\n  '\n")
	if initializerEnd < 0 {
		return fmt.Errorf("AUD-68 proof: unterminated wrong-KEK initializer block")
	}
	initializer := code[initializerStart : initializerStart+initializerEnd]
	if strings.Count(initializer, "--mount ") != 1 {
		return fmt.Errorf("AUD-68 proof: wrong-KEK initializer must have exactly one explicit mount")
	}
	if !strings.Contains(initializer, `--entrypoint /bin/sh "${proof_seed_image}"`) {
		return fmt.Errorf("AUD-68 proof: wrong-KEK initializer must use the project-unique seed image")
	}
	if !strings.Contains(initializer, `--user 65532:65532`) {
		return fmt.Errorf("AUD-68 proof: wrong-KEK initializer must use the signer nonroot identity")
	}
	if strings.Contains(initializer, "--cap-add") {
		return fmt.Errorf("AUD-68 proof: wrong-KEK initializer must not regain an added capability")
	}
	for _, forbidden := range []string{"${compose[@]}", "/data/secrets", "/data/audit", "/run/trstctl", "/wrong-kek", "signerkeys", "trstctldata", "chown "} {
		if strings.Contains(initializer, forbidden) {
			return fmt.Errorf("AUD-68 proof: wrong-KEK initializer crosses custody through %q", forbidden)
		}
	}
	if count := strings.Count(code, "--user 65532:65532"); count != 1 {
		return fmt.Errorf("AUD-68 proof: nonroot initializer identity appears %d times, want exactly one", count)
	}
	if count := strings.Count(code, "--user 0:0"); count != 0 {
		return fmt.Errorf("AUD-68 proof: root identity appears %d times, want zero", count)
	}
	return nil
}

func activeShellSource(body string) string {
	lines := strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n")
	active := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		active = append(active, line)
	}
	return strings.Join(active, "\n")
}

func shellArrayValues(body, name string) ([]string, error) {
	code := activeShellSource(body)
	marker := "readonly -a " + name + "=("
	start := strings.Index(code, marker)
	if start < 0 {
		return nil, fmt.Errorf("AUD-68 proof: missing shell array %s", name)
	}
	rest := code[start+len(marker):]
	end := strings.Index(rest, "\n)")
	if end < 0 {
		return nil, fmt.Errorf("AUD-68 proof: unterminated shell array %s", name)
	}
	return strings.Fields(rest[:end]), nil
}

func requireSourceOrder(body string, needles []string) error {
	offset := 0
	for _, needle := range needles {
		next := strings.Index(body[offset:], needle)
		if next < 0 {
			return fmt.Errorf("missing or out-of-order live command %q", needle)
		}
		offset += next + len(needle)
	}
	return nil
}

func replaceExactlyOnce(t *testing.T, body, old, replacement string) string {
	t.Helper()
	if count := strings.Count(body, old); count != 1 {
		t.Fatalf("test mutation target %q occurs %d times, want exactly once", old, count)
	}
	return strings.Replace(body, old, replacement, 1)
}

func validateDemoSeedCustody(cf composeFile) error {
	cp, ok := cf.Services["trstctl"]
	if !ok {
		return fmt.Errorf("demo custody: missing trstctl service")
	}
	signer, ok := cf.Services["signer"]
	if !ok {
		return fmt.Errorf("demo custody: missing signer service")
	}
	seed, ok := cf.Services["demo-seed"]
	if !ok {
		return fmt.Errorf("demo custody: missing demo-seed service")
	}
	if signer.User != "65532:65532" {
		return fmt.Errorf("demo custody: signer user=%q, want exact signer/control identity 65532:65532", signer.User)
	}
	if cp.User != "65532:65532" {
		return fmt.Errorf("demo custody: trstctl user=%q, want exact signer/control identity 65532:65532", cp.User)
	}
	if seed.User != "65532:65532" {
		return fmt.Errorf("demo custody: demo-seed user=%q, want exact signer/control identity 65532:65532", seed.User)
	}
	const controlImage = "${TRSTCTL_DEMO_CONTROL_IMAGE:-ctlplne-demo-control:local}"
	if signer.Image != controlImage || cp.Image != controlImage {
		return fmt.Errorf("demo custody: signer/control image must use the project-overridable %q tag", controlImage)
	}
	if len(signer.Build) != 0 {
		return fmt.Errorf("demo custody: signer and trstctl share one nondeterministic demo image, so trstctl must be the single build owner")
	}
	if len(cp.Build) == 0 {
		return fmt.Errorf("demo custody: trstctl control image build is required for the single build owner")
	}
	if signer.PullPolicy != "never" {
		return fmt.Errorf("demo custody: signer pull policy=%q, want never so it uses the locally built shared image", signer.PullPolicy)
	}
	const seedImage = "${TRSTCTL_DEMO_SEED_IMAGE:-ctlplne-demo-seed:local}"
	if seed.Image != seedImage {
		return fmt.Errorf("demo custody: demo-seed image=%q, want project-overridable %q", seed.Image, seedImage)
	}

	for _, required := range []struct {
		key  string
		want string
	}{
		{key: "TRSTCTL_AUDIT_SIGNING_KEY_FILE", want: "/data/audit/signing-key.pem"},
		{key: "TRSTCTL_SIGNER_MODE", want: "external"},
		{key: "TRSTCTL_SIGNER_SOCKET", want: "/run/trstctl/signer.sock"},
		{key: "TRSTCTL_SIGNER_ALLOW_CO_RESIDENT_AUTHORIZER", want: "true"},
		{key: "TRSTCTL_SIGNER_AUTH_SECRET_FILE", want: "/data/secrets/sign-auth.bin"},
		{key: "TRSTCTL_SECRETS_KEK_FILE", want: "/data/secrets/kek.bin"},
	} {
		if got := stringValue(cp.Environment[required.key]); got != required.want {
			return fmt.Errorf("demo custody: trstctl %s=%q, want %q", required.key, got, required.want)
		}
		if got := stringValue(seed.Environment[required.key]); got != required.want {
			return fmt.Errorf("demo custody: demo-seed %s=%q, want exact trstctl value %q", required.key, got, required.want)
		}
	}

	wantSignerCommand := []string{
		"--socket=/run/trstctl/signer.sock",
		"--keystore=/data/signer/keys",
		"--kek=/data/secrets/kek.bin",
		"--auth-secret=/data/secrets/sign-auth.bin",
		"--legacy-audit-key=/data/audit/signing-key.pem",
		"--license=/etc/trstctl/demo-provider-license.json",
		"--license-deployment-id=trstctl-local-demo",
		"--license-environment=non_production",
		"--managed-keys-config=/demo-managed-keys/provider.json",
	}
	if !slices.Equal(signer.Command, wantSignerCommand) {
		return fmt.Errorf("demo custody: signer command=%v, want exact signer command %v", signer.Command, wantSignerCommand)
	}
	if got := seed.DependsOn["signer"].Condition; got != "service_started" {
		return fmt.Errorf("demo custody: demo-seed signer dependency=%q, want service_started", got)
	}
	if got := seed.DependsOn["trstctl"].Condition; got != "service_healthy" {
		return fmt.Errorf("demo custody: demo-seed trstctl dependency=%q, want service_healthy", got)
	}

	if !composeMountHasMode(signer.Volumes, "signersock", "/run/trstctl", "") ||
		!composeMountHasMode(cp.Volumes, "signersock", "/run/trstctl", "") ||
		!composeMountHasMode(seed.Volumes, "signersock", "/run/trstctl", "") {
		return fmt.Errorf("demo custody: signer, trstctl, and demo-seed must share the signersock volume at /run/trstctl")
	}
	if !composeMountHasMode(signer.Volumes, "secrets", "/data/secrets", "") ||
		!composeMountHasMode(cp.Volumes, "secrets", "/data/secrets", "") ||
		!composeMountHasMode(seed.Volumes, "secrets", "/data/secrets", "ro") {
		return fmt.Errorf("demo custody: signer/trstctl must share the secrets volume and demo-seed must mount it read-only at /data/secrets")
	}
	if !composeMountHasMode(cp.Volumes, "publictrust", "/public-trust", "") ||
		!composeMountHasMode(seed.Volumes, "publictrust", "/public-trust", "ro") {
		return fmt.Errorf("demo custody: trstctl must publish and demo-seed must read the public trust volume")
	}
	if got := stringValue(cp.Environment["TRSTCTL_SERVER_TLS_INTERNAL_TRUST_FILE"]); got != "/public-trust/control-plane.crt" {
		return fmt.Errorf("demo custody: control-plane public TLS trust path=%q, want /public-trust/control-plane.crt", got)
	}
	if got := stringValue(seed.Environment["NODE_EXTRA_CA_CERTS"]); got != "/public-trust/control-plane.crt" {
		return fmt.Errorf("demo custody: seed TLS trust path=%q, want exact control-plane public certificate", got)
	}
	if _, forbidden := seed.Environment["NODE_TLS_REJECT_UNAUTHORIZED"]; forbidden {
		return fmt.Errorf("demo custody: seed must not disable TLS verification")
	}
	wantSeedVolumes := []string{
		"signersock:/run/trstctl",
		"secrets:/data/secrets:ro",
		"publictrust:/public-trust:ro",
		"seedstate:/seed-state",
	}
	if !sameStringSet(seed.Volumes, wantSeedVolumes) {
		return fmt.Errorf("demo custody: demo-seed volumes=%v, want exact custody mount allowlist %v (no signerkeys or aliases)", seed.Volumes, wantSeedVolumes)
	}
	wantSignerVolumes := []string{
		"signersock:/run/trstctl",
		"signerkeys:/data/signer",
		"secrets:/data/secrets",
		"managedkeys:/demo-managed-keys:ro",
		"trstctldata:/data",
	}
	if !sameStringSet(signer.Volumes, wantSignerVolumes) {
		return fmt.Errorf("demo custody: signer volumes=%v, want exact signer custody mount allowlist %v", signer.Volumes, wantSignerVolumes)
	}
	wantControlVolumes := []string{
		"signersock:/run/trstctl",
		"secrets:/data/secrets",
		"trstctldata:/data",
		"publictrust:/public-trust",
		"demoidp:/demo-oidc:ro",
		"managedkeys:/demo-managed-keys:ro",
	}
	if !sameStringSet(cp.Volumes, wantControlVolumes) {
		return fmt.Errorf("demo custody: trstctl volumes=%v, want exact control custody mount allowlist %v (signerkeys forbidden)", cp.Volumes, wantControlVolumes)
	}
	return nil
}

func sameStringSet(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for _, value := range want {
		if !contains(got, value) {
			return false
		}
	}
	return true
}

func composeMountHasMode(volumes []string, source, target, wantMode string) bool {
	mode, ok := composeMountMode(volumes, source, target)
	return ok && mode == wantMode
}

func composeMountMode(volumes []string, source, target string) (string, bool) {
	for _, volume := range volumes {
		parts := strings.Split(volume, ":")
		if len(parts) >= 2 && parts[0] == source && parts[1] == target {
			if len(parts) >= 3 {
				return parts[2], true
			}
			return "", true
		}
	}
	return "", false
}

func withoutComposeMount(volumes []string, source, target string) []string {
	out := make([]string, 0, len(volumes))
	for _, volume := range volumes {
		parts := strings.Split(volume, ":")
		if len(parts) >= 2 && parts[0] == source && parts[1] == target {
			continue
		}
		out = append(out, volume)
	}
	return out
}

func withoutString(values []string, remove string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value != remove {
			out = append(out, value)
		}
	}
	return out
}

// The seeded cloud discovery sources must have a real local target: LocalStack
// serves Secrets Manager and ACM, an init script seeds the fixtures the
// collectors look for, the control plane holds the credential values the
// sources reference, and the AWS providers point at the emulator through the
// loopback proxy (the GCP references stay unset so a partial run is exercised).
func TestDemoLocalStackBacksTheSeededCloudDiscoverySources(t *testing.T) {
	cf := parseCompose(t)
	services := fmt.Sprint(cf.Services["localstack"].Environment["SERVICES"])
	for _, want := range []string{"kms", "secretsmanager", "acm"} {
		if !strings.Contains(services, want) {
			t.Fatalf("localstack SERVICES = %q, want %s enabled", services, want)
		}
	}
	mounted := false
	for _, v := range cf.Services["localstack"].Volumes {
		if v == "./localstack-init:/etc/localstack/init/ready.d:ro" {
			mounted = true
		}
	}
	if !mounted {
		t.Fatalf("localstack init directory is not mounted read-only: %v", cf.Services["localstack"].Volumes)
	}
	info, err := os.Stat(filepath.Join("localstack-init", "seed-discovery.sh"))
	if err != nil {
		t.Fatalf("localstack seed script: %v", err)
	}
	if info.Mode()&0o111 == 0 {
		t.Fatalf("localstack seed script mode = %v, want executable so LocalStack runs it on ready", info.Mode())
	}
	env := cf.Services["trstctl"].Environment
	for _, key := range []string{
		"TRSTCTL_DISCOVERY_AWS_ACCESS_KEY_ID", "TRSTCTL_DISCOVERY_AWS_SECRET_ACCESS_KEY",
		"TRSTCTL_DISCOVERY_AWS_SM_ACCESS_KEY_ID", "TRSTCTL_DISCOVERY_AWS_SM_SECRET_ACCESS_KEY",
	} {
		if got := fmt.Sprint(env[key]); got != "test" {
			t.Fatalf("trstctl %s = %q, want the emulator's placeholder credential", key, got)
		}
	}
	if _, set := env["TRSTCTL_DISCOVERY_GCP_SM_TOKEN"]; set {
		t.Fatal("demo must leave the GCP credential unset so the seeded partial run is honest")
	}
	seed := read(t, "seed.mjs")
	for _, provider := range []string{`provider: "aws-acm"`, `provider: "aws-secrets-manager"`} {
		i := strings.Index(seed, provider)
		if i < 0 {
			t.Fatalf("seed.mjs no longer declares %s", provider)
		}
		entry := seed[i : strings.Index(seed[i:], "}")+i]
		for _, want := range []string{`endpoint: "http://127.0.0.1:4566"`, `allow_private_endpoint: true`, `private_egress_cidrs: ["127.0.0.1/32"]`} {
			if !strings.Contains(entry, want) {
				t.Fatalf("seed.mjs %s does not point at the emulator (%s missing): %s", provider, want, entry)
			}
		}
	}
}

// The licensed partner-lab profile is the customer path for a license: the clean
// release image with the vendor's public key baked in, an operator-controlled file
// copied once for the service user, the same bound deployment ID and environment
// for the control plane and the isolated signer, and a provider-operator IdP pinned
// offline. It must never fall back to the demo target's self-minted license.
func TestPartnerLabLicensedProfileDeliversAnOperatorLicenseTheCustomerWay(t *testing.T) {
	cf := parseComposeAt(t, "lab", "docker-compose.licensed.yml")
	cp := cf.Services["trstctl"]
	if got := stringValue(cp.Build["target"]); got != "release" {
		t.Fatalf("licensed control plane build target = %q, want release (not the demo target's self-minted license)", got)
	}
	args, _ := cp.Build["args"].(map[string]any)
	if !strings.Contains(fmt.Sprint(args["LICENSE_KEYS_B64"]), "TRSTCTL_LAB_LICENSE_KEYS_B64") {
		t.Fatalf("licensed control plane must bake the vendor public key from TRSTCTL_LAB_LICENSE_KEYS_B64, got %v", args)
	}
	for key, want := range map[string]string{
		"TRSTCTL_LICENSE_FILE":                  "/lab-runtime/license.json",
		"TRSTCTL_PROVIDER_OIDC_JWKS_FILE":       "/demo-oidc/jwks.json",
		"TRSTCTL_PROVIDER_OIDC_ADMIN_VALUES":    "provider-admin",
		"TRSTCTL_PROVIDER_OIDC_OPERATOR_VALUES": "provider-operator",
	} {
		if got := fmt.Sprint(cp.Environment[key]); got != want {
			t.Fatalf("licensed control plane %s = %q, want %q", key, got, want)
		}
	}
	if _, viaURL := cp.Environment["TRSTCTL_PROVIDER_OIDC_JWKS_URL"]; viaURL {
		t.Fatal("provider IdP keys must be pinned offline (file), never fetched from a URL")
	}
	for _, key := range []string{"TRSTCTL_LICENSE_DEPLOYMENT_ID", "TRSTCTL_LICENSE_ENVIRONMENT"} {
		if got := fmt.Sprint(cp.Environment[key]); !strings.Contains(got, "TRSTCTL_LAB_LICENSE_") {
			t.Fatalf("licensed control plane %s = %q, want the operator-bound value", key, got)
		}
	}
	signer := cf.Services["signer"]
	for _, want := range []string{"--license=/lab-runtime/license.json", "--license-deployment-id=${TRSTCTL_LAB_LICENSE_DEPLOYMENT_ID:-partner-lab}", "--license-environment=${TRSTCTL_LAB_LICENSE_ENVIRONMENT:-non_production}", "--managed-keys-config=/demo-managed-keys/provider.json"} {
		if !contains(signer.Command, want) {
			t.Fatalf("licensed signer command %v lacks %q", signer.Command, want)
		}
	}
	if contains(signer.Command, "--license=/etc/trstctl/demo-provider-license.json") {
		t.Fatal("licensed signer must not read the demo target's self-minted license")
	}
	if !containsPrefix(signer.Volumes, "labruntime:/lab-runtime:ro") {
		t.Fatalf("licensed signer must read the runtime volume read-only: %v", signer.Volumes)
	}
	init := cf.Services["lab-init"]
	if got := fmt.Sprint(init.Environment["TRSTCTL_LAB_LICENSE_IN"]); got != "/license-in/license.json" {
		t.Fatalf("lab-init license input = %q", got)
	}
	mounted := false
	for _, v := range init.Volumes {
		if strings.HasPrefix(v, "${TRSTCTL_LAB_LICENSE_FILE") && strings.HasSuffix(v, ":/license-in/license.json:ro") {
			mounted = true
		}
	}
	if !mounted {
		t.Fatalf("lab-init must bind-mount the operator's license file read-only: %v", init.Volumes)
	}
	idp := cf.Services["demo-oidc"]
	if got := fmt.Sprint(idp.Environment["OIDC_PROVIDER_CLIENT_ID"]); got != fmt.Sprint(cp.Environment["TRSTCTL_PROVIDER_OIDC_AUDIENCE"]) {
		t.Fatalf("provider IdP client %q must equal the pinned audience %q", got, cp.Environment["TRSTCTL_PROVIDER_OIDC_AUDIENCE"])
	}

	initScript := read(t, "lab", "lab-init.mjs")
	for _, want := range []string{"TRSTCTL_LAB_LICENSE_IN", "/lab-runtime/license.json", "mode: 0o400", "chownSync(licenseOut, 65532, 65532)"} {
		if !strings.Contains(initScript, want) {
			t.Fatalf("lab-init.mjs must copy the license for the service user (%s missing)", want)
		}
	}
	script := read(t, "lab", "run.sh")
	for _, want := range []string{"TRSTCTL_LAB_LICENSE_FILE", "TRSTCTL_LAB_LICENSE_KEYS_B64", "docker-compose.licensed.yml", "600|400)", "refusing a group- or world-readable license"} {
		if !strings.Contains(script, want) {
			t.Fatalf("run.sh licensed profile lacks %q", want)
		}
	}
	dockerfile := read(t, "..", "docker", "Dockerfile")
	for _, want := range []string{"ARG LICENSE_KEYS_B64=\"\"", "builtinPubKeysB64=${LICENSE_KEYS_B64}\" -o /out/trstctl ", "builtinPubKeysB64=${LICENSE_KEYS_B64}\" -o /out/trstctl-signer"} {
		if !strings.Contains(dockerfile, want) {
			t.Fatalf("Dockerfile must bake LICENSE_KEYS_B64 into the release control plane and signer (%q missing)", want)
		}
	}
	if !strings.Contains(dockerfile, "${LICENSE_KEYS_B64:+${LICENSE_KEYS_B64},}${license_keys_b64}") {
		t.Fatal("demo target must keep an operator-supplied key beside its throw-away key instead of discarding it")
	}
	release := read(t, "..", "..", ".github", "workflows", "release.yml")
	if strings.Count(release, "LICENSE_KEYS_B64=${{ vars.TRSTCTL_LICENSE_KEYS_B64 }}") < 2 {
		t.Fatal("release pipeline must bake the vendor public key into both release image builds")
	}
}

func containsPrefix(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

// The provider journey's customer listener is real and isolated: a separate
// NGINX server block on 10449 whose certificate lives in a directory only the
// customer tenant's agent may touch, a front-door entrypoint that starts that
// agent from a staged enrollment, and a one-shot enroll helper that needs the
// customer's own API token.
func TestPartnerLabServesAnIsolatedCustomerListenerForTheProviderJourney(t *testing.T) {
	nginx := read(t, "lab", "frontdoors", "nginx.conf")
	for _, want := range []string{"listen 10449 ssl;", "server_name customer-edge.acme-robotics.example.com;", "/lab/tls/customer-edge/edge.crt", "/lab/tls/customer-edge/edge.key"} {
		if !strings.Contains(nginx, want) {
			t.Fatalf("nginx.conf lacks the customer listener element %q", want)
		}
	}
	profile := read(t, "lab", "frontdoors", "host-exec-profile-customer.json")
	if !strings.Contains(profile, `"allowed_roots": ["/lab/tls/customer-edge"]`) || strings.Contains(profile, "apachectl") || strings.Contains(profile, "pg_ctl") {
		t.Fatalf("customer host profile must allow only the customer directory and an nginx reload: %s", profile)
	}
	entrypoint := read(t, "lab", "frontdoors", "entrypoint.sh")
	for _, want := range []string{"/lab/state/customer/args", "--host-exec-profile=/lab/host-exec-profile-customer.json", "--host-rollback-dir=/lab/state/customer/rollbacks", "/lab/tls/customer-edge/edge.crt"} {
		if !strings.Contains(entrypoint, want) {
			t.Fatalf("front-door entrypoint lacks the customer agent element %q", want)
		}
	}
	dockerfile := read(t, "lab", "frontdoors", "Dockerfile")
	if !strings.Contains(dockerfile, "host-exec-profile-customer.json") || !strings.Contains(dockerfile, "EXPOSE 10443 10444 10445 10446 10447 10448 10449") {
		t.Fatal("front-door image must ship the customer profile and expose the customer listener")
	}
	cf := parseComposeAt(t, "lab", "docker-compose.yml")
	if !contains(cf.Services["trstctl"].Ports, "127.0.0.1:10449:10449") {
		t.Fatalf("lab must publish the customer listener on loopback: %v", cf.Services["trstctl"].Ports)
	}
	enroll, ok := cf.Services["lab-customer-enroll"]
	if !ok {
		t.Fatal("lab must ship the one-shot customer enroll helper")
	}
	if !contains(enroll.Profiles, "partner-lab-customer") {
		t.Fatalf("customer enroll helper must sit behind its own profile so a plain lab start never runs it: %v", enroll.Profiles)
	}
	mounted := false
	for _, v := range enroll.Volumes {
		if strings.HasPrefix(v, "${TRSTCTL_LAB_CUSTOMER_TOKEN_FILE") && strings.HasSuffix(v, ":/customer/token:ro") {
			mounted = true
		}
	}
	if !mounted {
		t.Fatalf("customer enroll helper must read the customer token from a read-only mounted file, never an environment value: %v", enroll.Volumes)
	}
	for _, key := range enroll.Environment {
		if strings.Contains(fmt.Sprint(key), "TRSTCTL_LAB_CUSTOMER_TOKEN=") {
			t.Fatal("customer token must not be passed as an environment value")
		}
	}
	helper := read(t, "lab", "customer-enroll.mjs")
	for _, want := range []string{"/api/v1/agents/enrollment-tokens", `roles: ["host"]`, "flag: \"wx\"", "chownSync(path, 65532, 65532)"} {
		if !strings.Contains(helper, want) {
			t.Fatalf("customer enroll helper lacks %q", want)
		}
	}
}

// The partner lab owns its teardown (OPP-C04). A profile-filtered
// `docker compose --profile partner-lab stop` skips out-of-profile services —
// the control plane — which keeps 9443 and 10443-10449 bound and breaks the next
// bring-up. deploy/demo/lab/down.sh must tear down exactly one Compose project
// across every profile, prove nothing of it survives, and be the teardown the
// README points at.
func TestPartnerLabTeardownIsOwnedAndProven(t *testing.T) {
	info, err := os.Stat(filepath.Join("lab", "down.sh"))
	if err != nil {
		t.Fatalf("deploy/demo/lab/down.sh must exist: %v", err)
	}
	if info.Mode()&0o111 == 0 {
		t.Fatal("deploy/demo/lab/down.sh must be executable")
	}
	down := read(t, "lab", "down.sh")
	for _, want := range []string{
		"TRSTCTL_LAB_PROJECT:-trstctl-partner-lab", `[!a-z0-9]*`,
		"--profile partner-lab --profile partner-lab-customer down --volumes --remove-orphans",
		`label=com.docker.compose.project=$lab_project`, "docker rm -f", "docker volume rm",
		"remaining_containers", "remaining_volumes", "remaining_networks",
		"Teardown incomplete", "exit 1",
	} {
		if !strings.Contains(down, want) {
			t.Errorf("partner lab teardown script is missing contract marker %q", want)
		}
	}
	labReadme := read(t, "lab", "README.md")
	for _, want := range []string{"deploy/demo/lab/down.sh", "profile-filtered `stop` is not a teardown", "exits non-zero if anything of that\nproject survives"} {
		if !strings.Contains(labReadme, want) {
			t.Errorf("partner lab README must document the owned teardown marker %q", want)
		}
	}
}
