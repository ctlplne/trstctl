// SPDX-License-Identifier: MPL-2.0

package helm_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPublishedHelmInstallBlocksRender(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		path   string
		marker string
	}{
		{name: "install guide", path: filepath.Join("..", "..", "docs", "install.md"), marker: "helm-doc-render: production-install"},
		{name: "chart readme", path: filepath.Join("trstctl", "README.md"), marker: "helm-doc-render: chart-production"},
		{name: "air-gap guide", path: filepath.Join("..", "..", "docs", "airgap.md"), marker: "helm-doc-render: airgap-install"},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			body, err := os.ReadFile(tc.path)
			if err != nil {
				t.Fatal(err)
			}
			block := markedShellBlock(t, string(body), tc.marker)
			for _, required := range []string{
				"postgres.dsn=",
				"nats.url=",
				"signer.auth.tokenCommand=",
			} {
				if !strings.Contains(block, required) {
					t.Fatalf("%s block is missing %q:\n%s", tc.marker, required, block)
				}
			}
			render := strings.Replace(block, "helm upgrade --install trstctl", "helm template trstctl", 1)
			render = strings.Replace(render, "helm install trstctl", "helm template trstctl", 1)
			render = strings.ReplaceAll(render, "charts/trstctl", "trstctl")
			render = strings.ReplaceAll(render, "deploy/helm/trstctl", "trstctl")
			render = strings.ReplaceAll(render, "manifests/values-airgap.yaml", "trstctl/values-airgap.yaml")
			render = strings.ReplaceAll(render, "--create-namespace", "")
			cmd := exec.Command("/bin/sh", "-c", render)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("published command does not render with its exact values: %v\n%s\ncommand:\n%s", err, output, render)
			}
		})
	}
}

func TestAirGapOverlayRendersTelemetryExplicitlyDisabled(t *testing.T) {
	t.Parallel()

	cmd := exec.Command(
		"helm", "template", "trstctl", "trstctl",
		"-f", "trstctl/values-airgap.yaml",
		"--set", "image.repository=registry.airgap.local/trstctl",
		"--set", "image.tag=v0.5.4",
		"--set", "postgres.dsn=postgres://user:pass@pg.internal:5432/trstctl?sslmode=require",
		"--set", "nats.url=nats://nats.internal:4222",
		"--set", "kek.existingSecret=trstctl-kek",
		"--set", "signer.auth.tokenCommand=/usr/local/bin/trstctl-sign-approve",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("render air-gap overlay: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "TRSTCTL_TELEMETRY_ENABLED: \"false\"") {
		t.Fatalf("air-gap ConfigMap must explicitly disable telemetry; rendered output omitted it")
	}
}

func TestPublishedHelmEvaluationBlocksRenderOnlyWithExplicitSingleReplicaOverrides(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		path   string
		marker string
	}{
		{name: "install guide", path: filepath.Join("..", "..", "docs", "install.md"), marker: "helm-doc-render: evaluation-install"},
		{name: "chart readme", path: filepath.Join("trstctl", "README.md"), marker: "helm-doc-render: chart-evaluation"},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			body, err := os.ReadFile(tc.path)
			if err != nil {
				t.Fatal(err)
			}
			block := markedShellBlock(t, string(body), tc.marker)
			for _, required := range []string{
				"nats.replicas=1",
				"nats.allowSingleReplica=true",
				"signer.auth.allowCoResidentAuthorizer=true",
			} {
				if !strings.Contains(block, required) {
					t.Fatalf("%s block is missing %q:\n%s", tc.marker, required, block)
				}
			}
			if strings.Contains(block, "signer.auth.tokenCommand=") {
				t.Fatalf("%s mixes production token-command and eval co-resident authorization", tc.marker)
			}
			render := strings.Replace(block, "helm install trstctl-eval", "helm template trstctl-eval", 1)
			render = strings.ReplaceAll(render, "deploy/helm/trstctl", "trstctl")
			render = strings.ReplaceAll(render, "--create-namespace", "")
			cmd := exec.Command("/bin/sh", "-c", render)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("published eval command does not render with its exact values: %v\n%s\ncommand:\n%s", err, output, render)
			}
		})
	}
}

func TestEveryPublishedExternalNATSHelmBlockDeclaresSignerAuthorization(t *testing.T) {
	t.Parallel()

	for _, path := range []string{
		filepath.Join("..", "..", "docs", "install.md"),
		filepath.Join("..", "..", "docs", "airgap.md"),
		filepath.Join("trstctl", "README.md"),
	} {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for index, block := range shellBlocks(string(body)) {
			if !strings.Contains(block, "helm ") || !strings.Contains(block, "nats.url=") {
				continue
			}
			production := strings.Contains(block, "signer.auth.tokenCommand=")
			evaluation := strings.Contains(block, "signer.auth.allowCoResidentAuthorizer=true") &&
				strings.Contains(block, "nats.replicas=1") &&
				strings.Contains(block, "nats.allowSingleReplica=true")
			if !production && !evaluation {
				t.Errorf("%s bash block %d configures external NATS without production token-command or complete eval-only overrides:\n%s", path, index+1, block)
			}
		}
	}
}

func markedShellBlock(t *testing.T, document, marker string) string {
	t.Helper()
	start := strings.Index(document, "<!-- "+marker+" -->")
	if start < 0 {
		t.Fatalf("missing docs-reality marker %q", marker)
	}
	after := document[start:]
	fence := strings.Index(after, "```bash")
	if fence < 0 {
		t.Fatalf("marker %q is not followed by a bash block", marker)
	}
	after = after[fence+len("```bash"):]
	end := strings.Index(after, "```")
	if end < 0 {
		t.Fatalf("bash block after %q is unterminated", marker)
	}
	return strings.TrimSpace(after[:end])
}

func shellBlocks(document string) []string {
	var out []string
	for {
		start := strings.Index(document, "```bash")
		if start < 0 {
			return out
		}
		document = document[start+len("```bash"):]
		end := strings.Index(document, "```")
		if end < 0 {
			return out
		}
		out = append(out, strings.TrimSpace(document[:end]))
		document = document[end+len("```"):]
	}
}
