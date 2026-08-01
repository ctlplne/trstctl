// SPDX-License-Identifier: MPL-2.0

package demo

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

type composeFile struct {
	Name     string `yaml:"name"`
	Services map[string]struct {
		Image       string         `yaml:"image"`
		Build       map[string]any `yaml:"build"`
		Environment map[string]any `yaml:"environment"`
		Command     []string       `yaml:"command"`
		Ports       []string       `yaml:"ports"`
		DependsOn   map[string]struct {
			Condition string `yaml:"condition"`
		} `yaml:"depends_on"`
		NetworkMode string   `yaml:"network_mode"`
		Volumes     []string `yaml:"volumes"`
	} `yaml:"services"`
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
		"TRSTCTL_LIFECYCLE_RENEW_BEFORE":                   "168h",
		"TRSTCTL_PROTOCOLS_ACME_TENANT_ID":                 "11111111-1111-4111-8111-111111111111",
		"TRSTCTL_PROTOCOLS_EST_TENANT_ID":                  "11111111-1111-4111-8111-111111111111",
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
	if got := stringValue(signer.Build["target"]); got != "demo" {
		t.Fatalf("demo signer build target = %q, want demo", got)
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
		`"demo-key-custodian-one"`,
		`"demo-key-custodian-two"`,
		`rotateKey, [403]`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("demo managed-key seed missing dual-control proof %q", want)
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
