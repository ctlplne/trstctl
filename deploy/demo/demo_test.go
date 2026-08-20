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
}

type composeService struct {
	Image       string                       `yaml:"image"`
	Build       map[string]any               `yaml:"build"`
	PullPolicy  string                       `yaml:"pull_policy"`
	User        string                       `yaml:"user"`
	Environment map[string]any               `yaml:"environment"`
	Command     []string                     `yaml:"command"`
	Ports       []string                     `yaml:"ports"`
	DependsOn   map[string]composeDependency `yaml:"depends_on"`
	NetworkMode string                       `yaml:"network_mode"`
	Volumes     []string                     `yaml:"volumes"`
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
	var cf composeFile
	if err := yaml.Unmarshal([]byte(read(t, "docker-compose.yml")), &cf); err != nil {
		t.Fatalf("demo docker-compose.yml is not valid YAML: %v", err)
	}
	return cf
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
	if !contains(cp.Ports, "9443:8443") || contains(cp.Ports, "19081:19081") {
		t.Fatalf("demo trstctl ports = %v, want only the browser/API port 9443:8443", cp.Ports)
	}
	for k, want := range map[string]string{ // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
		"TRSTCTL_AGENT_CHANNEL_CA_CERT_FILE":               "/data/ca/agent-ca.crt",
		"TRSTCTL_CA_CERT_FILE":                             "/data/ca/issuing-ca.crt",
		"TRSTCTL_CA_PUBLIC_CERT_FILE":                      "/public-trust/issuing-ca.crt",
		"TRSTCTL_AUTH_OIDC_ENABLED":                        "true",
		"TRSTCTL_AUTH_OIDC_REDIRECT_URI":                   "https://localhost:9443/auth/callback",
		"TRSTCTL_AUTH_OIDC_AUTH_ENDPOINT":                  "http://127.0.0.1:19081/authorize",
		"TRSTCTL_AUTH_OIDC_TOKEN_ENDPOINT":                 "http://127.0.0.1:19081/token",
		"TRSTCTL_OUTBOUND_ENV_CREDENTIAL_REFS":             "env:TRSTCTL_DISCOVERY_AWS_ACCESS_KEY_ID,env:TRSTCTL_DISCOVERY_AWS_SECRET_ACCESS_KEY,env:TRSTCTL_DISCOVERY_GCP_TOKEN,env:TRSTCTL_DISCOVERY_AWS_SM_ACCESS_KEY_ID,env:TRSTCTL_DISCOVERY_AWS_SM_SECRET_ACCESS_KEY,env:TRSTCTL_DISCOVERY_GCP_SM_TOKEN",
		"TRSTCTL_SECRETS_ENABLE_API":                       "true",
		"TRSTCTL_SECRETS_AUTH_SECRET_FILE":                 "/data/secrets/machine-auth.bin",
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
	if !contains(idp.Ports, "19081:19081") {
		t.Fatalf("demo OIDC IdP ports = %v, want browser SSO port 19081:19081", idp.Ports)
	}
	if got := cf.Services["oidc-loopback"].NetworkMode; got != "service:trstctl" {
		t.Fatalf("demo OIDC loopback proxy network_mode = %q, want service:trstctl for the validated loopback token endpoint", got)
	}
	if got := cf.Services["localstack-loopback"].NetworkMode; got != "service:trstctl" {
		t.Fatalf("demo LocalStack loopback proxy network_mode = %q, want service:trstctl for the SSRF-guarded KMS endpoint", got)
	}
	if got := cf.Services["localstack-signer-loopback"].NetworkMode; got != "service:signer" {
		t.Fatalf("demo signer LocalStack proxy network_mode = %q, want service:signer for the signer-local SSRF-guarded KMS endpoint", got)
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
		"https://localhost:9443",
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
		"audit",
		"notifications",
		"no secret material",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("demo seed --check output missing %q:\n%s", want, body)
		}
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
