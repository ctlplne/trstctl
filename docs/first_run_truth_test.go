// SPDX-License-Identifier: MPL-2.0

package docs

import (
	"strings"
	"testing"
)

func TestColdFirstRunDocumentationMatchesTheSafeBlankStack(t *testing.T) {
	gettingStarted := read(t, "getting-started.md")
	dockerReadme := read(t, "../deploy/docker/README.md")
	install := read(t, "install.md")
	tlsGuide := read(t, "local-evaluation-tls.md")
	demoWalkthrough := read(t, "demo-click-through.html")
	allCustomerDocs := strings.Join([]string{gettingStarted, dockerReadme, tlsGuide, demoWalkthrough}, "\n")

	for _, unsafe := range []string{
		"accept the self-signed evaluation certificate",
		"inspect and accept it for this evaluation only",
		"click through the warning",
	} {
		if strings.Contains(strings.ToLower(allCustomerDocs), unsafe) {
			t.Errorf("local evaluation documentation still teaches an unsafe TLS shortcut %q", unsafe)
		}
	}

	for _, want := range []string{
		"docker compose -f deploy/docker/docker-compose.yml up --build --detach --wait --wait-timeout 180",
		"docker compose -f deploy/docker/docker-compose.yml cp trstctl:/public-trust/control-plane.crt",
		"eval-admin@trstctl.local",
		"loopback-only local identity provider",
		"curl",
		"openssl",
		"jq",
		"trstctl-agent",
		"trstctl-cli",
		"8 GB",
	} {
		if !strings.Contains(gettingStarted, want) {
			t.Errorf("getting-started.md is missing cold-run truth %q", want)
		}
	}
	for _, want := range []string{
		"separate **signer** service",
		"loopback-only **eval-oidc** service",
		"one-shot **oidc-keys** service",
	} {
		if !strings.Contains(dockerReadme, want) {
			t.Errorf("deploy/docker/README.md is missing real Compose topology %q", want)
		}
	}
	if strings.Contains(dockerReadme, "This brings up three services") {
		t.Fatal("deploy/docker/README.md still understates the blank Compose topology")
	}
	for _, binary := range []string{
		"trstctl", "trstctl-signer", "trstctl-agent", "trstctl-cli",
		"trstctl-operator", "trstctl-license", "terraform-provider-trstctl",
		"trstctl-spire-upstream-authority",
	} {
		if !strings.Contains(install, binary) {
			t.Errorf("install.md does not name make build output %q", binary)
		}
	}
	for _, want := range []string{
		"curl --cacert",
		"Never use `curl -k`",
		"Remove the local trust entry",
		"trstctl-eval-control-plane.crt",
	} {
		if !strings.Contains(tlsGuide, want) {
			t.Errorf("local evaluation TLS guide is missing %q", want)
		}
	}
	for _, want := range []string{
		"The 10-minute proof loop",
		"Owner",
		"Machine identity",
		"Credential",
		"Deployment target",
		"Rotate or revoke",
	} {
		if !strings.Contains(demoWalkthrough, want) {
			t.Errorf("demo walkthrough is missing beginner journey truth %q", want)
		}
	}
}
