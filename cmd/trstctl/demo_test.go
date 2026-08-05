// SPDX-License-Identifier: MPL-2.0

package main

import (
	"os"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

// --demo must produce a WORKING single box, or refuse (A5).
//
// The failure this guards against is subtle and is the one worth guarding: a
// demo that starts the control plane, fails to start the agent, and keeps
// serving. It looks like it worked. Every screen renders. Nothing the product
// is actually for — a deploy executing, an endpoint verifying, a renewal
// landing on a host — can happen, and the evaluator does not find out.

func TestDemoForcesTheSettingsWithoutWhichItSilentlyDoesNothing(t *testing.T) {
	t.Parallel()
	var cfg config.Config
	// Shipped defaults: the agent channel is OFF and the claimable allowlist is
	// EMPTY. Both are correct fail-closed defaults for production and both are
	// fatal to a demo.
	if cfg.AgentChannel.Enabled {
		t.Fatal("the agent channel now defaults to enabled; this test's premise is stale")
	}
	if len(cfg.AgentChannel.ClaimableJobKinds) != 0 {
		t.Fatal("the claimable allowlist now defaults non-empty; this test's premise is stale")
	}

	changed := ApplyDemoDefaults(&cfg)

	if !cfg.AgentChannel.Enabled {
		t.Error("demo did not enable the agent channel; the colocated agent would have nothing to dial")
	}
	if len(cfg.AgentChannel.ClaimableJobKinds) == 0 {
		t.Error("demo left the claimable allowlist empty. The job ledger is then served and hands " +
			"nothing out, so the agent enrols successfully and idles forever — the most misleading " +
			"possible demo, because every surface looks healthy")
	}
	// An agent that can mutate an appliance nobody meant to point it at is not a
	// safe default for an evaluation box.
	for _, kind := range cfg.AgentChannel.ClaimableJobKinds {
		if kind == "connector.deploy" {
			t.Error("demo enabled connector.deploy; an evaluation box must not be able to mutate " +
				"an appliance somebody pointed it at by accident")
		}
	}
	if len(changed) == 0 {
		t.Error("demo changed configuration and reported nothing. An operator reading the startup " +
			"summary would believe those settings were theirs")
	}
	for _, c := range changed {
		if !strings.Contains(c, "=") {
			t.Errorf("change note %q does not name the setting it changed", c)
		}
	}
}

// Settings an operator DID set must survive. --demo fills gaps; it does not
// overwrite decisions.
func TestDemoDoesNotOverrideExplicitOperatorSettings(t *testing.T) {
	t.Parallel()
	var cfg config.Config
	cfg.AgentChannel.Enabled = true
	cfg.AgentChannel.ClaimableJobKinds = []string{"discovery.run"}

	changed := ApplyDemoDefaults(&cfg)

	if len(cfg.AgentChannel.ClaimableJobKinds) != 1 || cfg.AgentChannel.ClaimableJobKinds[0] != "discovery.run" {
		t.Fatalf("demo overwrote an explicit claimable set: %v", cfg.AgentChannel.ClaimableJobKinds)
	}
	if len(changed) != 0 {
		t.Errorf("demo reported changes it did not make: %v", changed)
	}
}

// A listen address is not a dial address. ":9443" is what an operator writes and
// what the shipped manifests default to; an agent cannot dial it.
func TestTheAgentIsGivenADialableAddress(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ configured, want string }{
		{"", "127.0.0.1:9443"},
		{":9443", "127.0.0.1:9443"},
		{":19443", "127.0.0.1:19443"},
		{"10.0.0.5:9443", "10.0.0.5:9443"},
	} {
		if got := demoDialAddr(tc.configured); got != tc.want {
			t.Errorf("demoDialAddr(%q) = %q, want %q", tc.configured, got, tc.want)
		}
	}
}

// The base URL follows the server's TLS mode rather than assuming one.
func TestTheDemoBaseURLMatchesTheServersTLSMode(t *testing.T) {
	t.Parallel()
	var cfg config.Config
	cfg.Server.Addr = ":8443"
	cfg.Server.TLS.Mode = "manual"
	got, err := demoBaseURL(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://127.0.0.1:8443" {
		t.Fatalf("base = %q, want https for a TLS-enabled server", got)
	}

	cfg.Server.TLS.Mode = "off"
	got, err = demoBaseURL(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got != "http://127.0.0.1:8443" {
		t.Fatalf("base = %q, want http when TLS is off", got)
	}

	var empty config.Config
	if _, err := demoBaseURL(&empty); err == nil {
		t.Error("an unconfigured server address produced a dial URL instead of an error")
	}
}

// A missing agent binary must be an ERROR that names where it looked, not a
// warning the evaluator scrolls past.
func TestAMissingAgentBinaryIsAnErrorThatSaysWhereItLooked(t *testing.T) {
	// Not parallel: t.Setenv and t.Parallel are mutually exclusive, and this
	// case needs a controlled PATH.
	// Point PATH at an empty directory and run from a directory with no sibling
	// agent, so both resolution strategies fail.
	dir := t.TempDir()
	t.Setenv("PATH", dir)

	_, err := demoAgentPath()
	if err == nil {
		t.Skip("a trstctl-agent binary is present beside the test binary; this case cannot be exercised here")
	}
	msg := err.Error()
	for _, want := range []string{"trstctl-agent", "make build"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not mention %q — an evaluator needs to know what is missing "+
				"and how to get it", msg, want)
		}
	}
}

// The bootstrap token must land in a file, at 0600.
//
// The agent refuses an inline token because process arguments expose bearer
// credentials to anything that can read the process table. A demo that
// special-cased itself would be teaching the wrong thing on the one box an
// evaluator is most likely to copy from.
func TestTheDemoPassesTheTokenByFileNotArgument(t *testing.T) {
	t.Parallel()
	source, err := os.ReadFile("demo.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(source)
	if !strings.Contains(body, `"--bootstrap-token-file"`) {
		t.Error("the demo does not pass the token by file")
	}
	if strings.Contains(body, `"--bootstrap-token",`) {
		t.Error("the demo passes an inline bootstrap token; process arguments expose bearer " +
			"credentials, which is why the agent refuses them")
	}
	if !strings.Contains(body, "0o600") {
		t.Error("the token file is not written 0600")
	}
}

// The agent is exec'd, never linked.
//
// docs/agent_binary_import_boundary_test.go pins that the agent binary must not
// link the control plane. Importing the agent here to avoid a second process
// would put both on the same side of the boundary the whole architecture rests
// on, and the demo would stop exercising the real channel.
func TestTheDemoExecsTheAgentRatherThanImportingIt(t *testing.T) {
	t.Parallel()
	source, err := os.ReadFile("demo.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(source)
	if strings.Contains(body, `"trstctl.com/trstctl/internal/agent`) {
		t.Fatal("the demo imports the agent. It must exec the sibling binary: linking puts the " +
			"agent and the control plane on the same side of the import boundary the product's " +
			"architecture rests on, and the demo would no longer exercise the real channel")
	}
	if !strings.Contains(body, "exec.CommandContext") {
		t.Error("the demo does not exec the agent binary")
	}
}
