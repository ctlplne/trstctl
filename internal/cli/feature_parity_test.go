// SPDX-License-Identifier: MPL-2.0

package cli_test

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/cli"
	"trstctl.com/trstctl/internal/featureparity"
)

func TestFeatureParityMapsCatalogRowsToCLICommands(t *testing.T) {
	commands := cliCommandSet(t)

	for _, item := range loadFeatureParityCatalog(t).Items {
		if len(item.CLISurface) == 0 && strings.TrimSpace(item.CLINA) == "" {
			t.Errorf("%s (%s) has no cli_surface commands and no cli_na reason", item.FeatureID, item.Feature)
		}
		if len(item.CLISurface) > 0 && strings.TrimSpace(item.CLINA) != "" {
			t.Errorf("%s (%s) declares both cli_surface and cli_na", item.FeatureID, item.Feature)
		}
		for _, command := range item.CLISurface {
			if strings.TrimSpace(command) == "" {
				t.Errorf("%s (%s) has a blank cli_surface command", item.FeatureID, item.Feature)
				continue
			}
			if !commands[command] {
				t.Errorf("%s (%s) references missing CLI command %q", item.FeatureID, item.Feature, command)
			}
		}
	}
}

func TestEveryCLICommandMapsToFeature(t *testing.T) {
	commands := cliCommandSet(t)
	mapped := map[string][]string{}
	for _, item := range loadFeatureParityCatalog(t).Items {
		for _, command := range item.CLISurface {
			command = strings.TrimSpace(command)
			if command == "" {
				continue
			}
			mapped[command] = append(mapped[command], item.FeatureID)
		}
	}
	for command := range commands {
		if len(mapped[command]) == 0 {
			t.Errorf("CLI command %q is served but not mapped to a feature catalog row", command)
		}
	}
}

func TestACMEDNS01ProviderConfigCommandsExist(t *testing.T) {
	commands := cliCommandSet(t)
	for _, command := range []string{
		"acme dns-01 provider-configs create",
		"acme dns-01 provider-configs list",
		"acme dns-01 provider-configs get",
		"acme dns-01 provider-configs update",
		"acme dns-01 provider-configs delete",
		"acme dns-01 preflight",
	} {
		if !commands[command] {
			t.Fatalf("missing CLI command %q", command)
		}
	}
}

func TestACMEARIPostureCommandExists(t *testing.T) {
	if !cliCommandSet(t)["acme ari posture"] {
		t.Fatal(`missing CLI command "acme ari posture"`)
	}
}

func TestMDMSCEPPolicyCommandsExist(t *testing.T) {
	commands := cliCommandSet(t)
	for _, command := range []string{
		"mdm scep status",
		"mdm scep policies create",
		"mdm scep policies list",
		"mdm scep policies get",
		"mdm scep policies update",
		"mdm scep policies delete",
		"mdm scep policies rotate-challenge",
	} {
		if !commands[command] {
			t.Fatalf("missing CLI command %q", command)
		}
	}
}

func TestCTMonitoringCommandsExist(t *testing.T) {
	commands := cliCommandSet(t)
	for _, command := range []string{
		"discovery ct-monitoring get",
		"discovery ct-monitoring update",
	} {
		if !commands[command] {
			t.Fatalf("missing CLI command %q", command)
		}
	}
}

func TestDriftRemediationCommandsExist(t *testing.T) {
	commands := cliCommandSet(t)
	for _, command := range []string{
		"discovery drift-remediation",
		"discovery drift-remediation decide",
	} {
		if !commands[command] {
			t.Fatalf("missing CLI command %q", command)
		}
	}
}

func loadFeatureParityCatalog(t *testing.T) featureparity.Catalog {
	t.Helper()
	catalog, err := featureparity.Load()
	if err != nil {
		t.Fatalf("load feature parity catalog: %v", err)
	}
	return catalog
}

func cliCommandSet(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, command := range cli.Commands() {
		name := strings.Join(command.Name, " ")
		if out[name] {
			t.Fatalf("CLI command %q is duplicated", name)
		}
		out[name] = true
	}
	// B-1 (`operations bulkheads`), B-5 (`platform system`), B-2 (`ssh fleet`), B-4
	// (`code-signing identities`), B-3 (`migration plan`), and the five AWS
	// workload-identity source commands, the ARI posture read, and the four tenant
	// The discovery coverage command raised this to 308. A1's `operations jobs`
	// and B4's three `acme eab` commands raised it to 312: both epics added served
	// routes whose CLI parity was owed and had gone unpaid, which is precisely the
	// gap this ratchet and TestEveryAPIOperationHasACLICommand exist to catch.
	// F1's `posture adcs` raised it to 313; R2's `issuers capabilities` raised
	// it to 314 and is mapped onto the issuer feature rows; B7's
	// `acme dns-01 upstream-authorizations` raised it to 315 and is mapped onto
	// the DNS-01 feature row, whose provider configs it reports the freshness of;
	// D2's `endpoints verifications` raised it to 316 and is mapped onto F7.
	// M2's `graph crypto-readiness` raised it to 325 and is mapped onto the same
	// graph feature row as blast-radius and reachable: it reads the same edges to
	// answer a different question — not who is reachable from a node, but who
	// depends on the crypto a node exhibits.
	// Like the OpenAPI count, it is a ratchet: a new command must be
	// mapped to a feature row in the same change.
	// I2's `owners import`, `owners ownership-conflicts`, and the two
	// `owners cmdb-schedule` commands raised it to 329, mapped onto the same
	// owners row as the rest of the ownership surface.
	// I3's five `issuance-requests` commands raised it to 334, mapped onto the
	// same certificates row as the rest of the issuance surface.
	// I5's `mdm devices` and `mdm trace` raised it to 336, on the same
	// certificates row as the rest of the issuance-to-endpoint surface.
	// A5's five `agents upgrade-*` commands raised it to 341, on the same agents
	// row as the rest of the fleet surface.
	if len(out) != 341 {
		t.Fatalf("CLI commands = %d, want 341", len(out))
	}
	return out
}
