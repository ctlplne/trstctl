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

func TestRevocationCacheCommandExistsAUD39(t *testing.T) {
	if !cliCommandSet(t)["revocation caches"] {
		t.Fatal(`missing CLI command "revocation caches"`)
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
	// I3's five original `issuance-requests` commands raised it to 334, mapped onto the
	// same certificates row as the rest of the issuance surface.
	// I5's `mdm devices` and `mdm trace` raised it to 336, on the same
	// certificates row as the rest of the issuance-to-endpoint surface.
	// A5's five `agents upgrade-*` commands raised it to 341, on the same agents
	// row as the rest of the fleet surface.
	// AUD-14's `brand show` raised it to 342.
	// `owners resolve-conflict` raised it to 343.
	// L2's `usage evidence` raised it to 344, on the multi-tenant topology row
	// with the rest of the managed-offering surface.
	// I5's two `mdm poll-schedule` commands raised it to 346, on the same
	// certificates row as the rest of the MDM correlation surface.
	// I3's two `issuance-requests intake-schedule` commands raised it to 348.
	// B6's seven `edge` commands raised it to 355, on the private-CA row: the
	// delegated edge sub-CA is that CA's one bounded exception, not a product.
	// F4's two `adcs ca-database` commands raised it to 357, on the discovery
	// row: ingesting an AD CS CA database is lifecycle visibility, not issuance.
	// AUD-104's `incidents outbox-reconciliation-conflicts list` raises it to
	// 358 and maps the AUD-97 quarantine onto the incident-response row.
	// AUD-77's three `approval-requests` commands raise it to 361 and map the
	// genuine immutable request list plus exact request-ID/digest approve and deny
	// decisions onto the JIT approval-flow feature row. AUD-105 removes the
	// application-secret bulk-import command because that compatibility route is
	// explicitly unavailable, leaving 360 commands. AUD-38's read-only
	// `revocation health` command raises it to 361 and exposes the same signed
	// relay evidence as the API and console. AUD-39's read-only `revocation
	// caches` command raises it to 362 and exposes the signed segment-local cache
	// evidence without moving protocol bytes or upstream locations. AUD-40's six `migrations`
	// start/list/show/pause/resume/rollback commands raise it to 367 and map the
	// complete durable CA-wave control surface onto F48. AUD-118's `discovery
	// segments create` raises it to 368 and closes the prerequisite already
	// served by GUI-F002's createDiscoverySegment API operation. AUD-42's
	// destructive `ca keys retire` raises it to 369 and keeps the signer-gated
	// operation usable from a headless recovery terminal. AUD-44's owner attest
	// plus exception list/grant/revoke commands raise it to 373 and expose the
	// ownership-readiness gate from a headless incident terminal. AUD-49's
	// exact endpoint result, redacted diagnostic addendum, and prove-fixed
	// mutation raise it to 377. AUD-52's audit feed set/list commands raise it
	// to 379 and expose the same standing collector state as the API and console.
	// The parity sweep also closes the already-served AD CS drift read, yielding
	// 380. AUD-53 adds the served verification-key download and the server-free
	// offline verifier, yielding 382. AUD-65 adds graph-bound readiness action
	// creation plus the signed canonical JSON/CSV/NDJSON export, yielding 384.
	// The approved-request prepare and evidence-backed complete commands close
	// I3's missing issuance bridge, yielding 386. The event-backed ownership
	// assignment command raises it to 387 and keeps browser/headless parity. The
	// notification routing-preview read raises it to 388. The shared typed
	// discovery capability contract raises it to 389 so terminal and console
	// operators inspect the same fields, prerequisites, and dispositions. The
	// state-free plan preview raises it to 390 with the same server oracle.
	if len(out) != 390 {
		t.Fatalf("CLI commands = %d, want 390", len(out))
	}
	return out
}
