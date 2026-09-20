// SPDX-License-Identifier: BUSL-1.1

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

func TestTSAQualificationCommandMapsOnlyToF51(t *testing.T) {
	var owners []string
	for _, item := range loadFeatureParityCatalog(t).Items {
		for _, command := range item.CLISurface {
			if strings.TrimSpace(command) == "protocols tsa qualify" {
				owners = append(owners, item.FeatureID)
			}
		}
	}
	if len(owners) != 1 || owners[0] != "F51" {
		t.Fatalf("protocols tsa qualify owners = %v, want [F51]", owners)
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
		"acme dns-01 provider-configs qualification preview",
		"acme dns-01 provider-configs qualification run",
		"acme dns-01 provider-configs qualification history",
		"acme dns-01 qualification retry-cleanup",
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
	// state-free plan preview raises it to 390 with the same server oracle. The
	// saved-source preflight raises it to 391 so a headless operator gets the
	// same current execution blocker as the source table. The read-only
	// `transit keys list` command raises it to 392 and exposes the same safe key
	// metadata the API and console use for purpose-compatible selection. The
	// authenticated `capabilities list` read raises it to 393 and maps to F8 so
	// headless clients see the same route/RBAC preflight as the console. The
	// first-class Discovery recovery command raises it to 394 and maps to F2. The
	// effect-free agent enrollment preview raises it to 395 and maps to F3.
	// The issuance-request preview raises it to 396 and gives headless operators
	// the same effect-free owner/profile/CSR admission answer as the console.
	// F5's `acme readiness` raises it to 397 so browser and headless operators
	// consume the same tenant-bound, effect-free ACME plan.
	// F48's ceremony and rotation previews raise it to 399 so headless operators
	// get the same effect-free CA trust-change receipts as the console.
	// F53's profile restore preview and append-only recovery raise it to 401.
	// F59's effect-free lifecycle transition preview raises it to 402. F9's
	// headless audit collector-feed preview raises it to 403; the secret-free
	// managed-key custody read and effect-free preview raise it to 405. F55's
	// F56's effect-free create, update, and rotation previews raise it to 409.
	// F52's effect-free CBOM review command raises it to 410.
	// F24's effect-free SPIFFE Workload API qualification raises it to 411.
	// F25's exact, effect-free JIT credential preview raises it to 412.
	// F43's SSH certificate preview and issue commands raise it to 414. F69's
	// effect-free provider review, real probe, sanitized history, and bounded
	// cleanup recovery commands raise it to 418. F6's lifecycle automation-plan
	// read raises it to 419 so headless and browser operators share one oracle.
	// F51's effect-free TSA readiness command raises it to 420.
	// F30's exact, effect-free attested issuance preview raises it to 421.
	// F61 adds the read-only agent-identity preview; issuance remains separate.
	// F61 adds read-only durable history list and certificate detail commands.
	// F45 adds the read-only attested SSH user-certificate preview command.
	// F37 adds the read-only, effect-free secret-rotation preview command.
	// F63 adds the read-only, effect-free native secret-create preview command.
	// F64 adds the read-only, effect-free developer secret-access preview command.
	// F58 adds the read-only machine-login plan command so headless operators
	// use the same review oracle as the console before presenting a credential.
	// F60 adds the value-free one-time-share preview command.
	// F38 adds the read-only, effect-free ephemeral API-key preview command.
	// F39 adds the read-only, effect-free secret-scan preview command.
	// F65 adds the read-only configured-provider catalog and effect-free lease
	// preview commands; issue, read, renew, and revoke were already catalogued.
	// F66 adds read-only complete key-version history plus effect-free sealed
	// restore and KMIP runtime posture, then F68 added the effect-free
	// `secrets syncs preview` command, raising the catalog to 438. F50's managed
	// and keyless effect-free signing previews raised it to 440. F34's
	// effect-free emergency issuance preview raises it to 441. F29's exact,
	// effect-free unsaved routing-policy review raises it to 442. F62's exact
	// F79's subject-erasure and retention reviews raise it to 447. F6's exact,
	// effect-free endpoint-binding review raises it to 448.
	// DP2-057's three `profiles approvals` commands (list, get, approve) raised
	// it to 451, mapped onto the certificate-profile row F53 beside the rest of
	// the profile surface whose governed edits they review.
	// F4's issuance-result read completes asynchronous certificate retrieval.
	// F4's bounded issuance retry and F6's historical deployment evidence
	// complete the headless recovery and post-retirement inspection paths.
	if len(out) != 454 {
		t.Fatalf("CLI commands = %d, want 454", len(out))
	}
	return out
}
