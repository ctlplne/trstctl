// SPDX-License-Identifier: MPL-2.0

package demo

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// AUD-66 is a production-assembly contract, not a unit claim. The literal seed
// must converge before CI is allowed to call the demo healthy.
func TestAUD66SeedIsVersionedStateAwareAndResumeSafe(t *testing.T) {
	body := read(t, "seed.mjs")
	for _, want := range []string{
		`const seedCheckpointSubject = "trstctl-demo-seed-checkpoint"`,
		`function stableDemoValue(label)`,
		`async function readSeedCheckpoint`,
		`async function writeSeedCheckpoint`,
		`async function collectSeedInventory`,
		`function seedInventoryDigest`,
		`function findUniqueLogicalRecord`,
		`async function ensureOwner`,
		`async function ensureIdentity`,
		`async function advanceIdentity`,
		`await validateCompletedSeed`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("AUD-66 demo seed missing convergence authority %q", want)
		}
	}
	if strings.Contains(body, `runtimeDemoValue(`) {
		t.Fatal("AUD-66 demo seed still changes request bodies on process restart")
	}
	if strings.Contains(body, "await api(\"POST\", `/api/v1/identities/${identities[item.key].id}/transitions`") {
		t.Fatal("AUD-66 demo seed still blindly replays requested -> issued after the identity already advanced")
	}
	if err := requireSourceOrder(body, []string{
		`const checkpoint = await readSeedCheckpoint`,
		`await validateCompletedSeed`,
		`return;`,
		`await writeSeedCheckpoint`,
	}); err != nil {
		t.Fatalf("AUD-66 terminal checkpoint order: %v", err)
	}
	cf := parseCompose(t)
	seed := cf.Services["demo-seed"]
	if got := stringValue(seed.Environment["TRSTCTL_DEMO_BOOTSTRAP_TOKEN_FILE"]); got != "/seed-state/bootstrap.token" {
		t.Fatalf("AUD-66 persisted bootstrap token file = %q", got)
	}
	if !contains(seed.Volumes, "seedstate:/seed-state") {
		t.Fatalf("AUD-66 seed volumes do not preserve the bootstrap token: %v", seed.Volumes)
	}
	dockerfile := read(t, "Dockerfile.seed")
	if !strings.Contains(dockerfile, "install -d -o 65532 -g 65532 -m 0700 /seed-state") {
		t.Fatal("AUD-66 seed-state volume is not initialized for the nonroot seed identity")
	}
	controlDockerfile := read(t, "..", "docker", "Dockerfile")
	for _, want := range []string{
		"--production-deployment-id trstctl-local-provider-demo-production",
		"--non-production-deployment-ids trstctl-local-demo",
	} {
		if !strings.Contains(controlDockerfile, want) {
			t.Fatalf("AUD-66 literal demo image cannot mint its bound license: missing %q", want)
		}
	}
	for _, want := range []string{
		"--license-deployment-id=trstctl-local-demo",
		"--license-environment=non_production",
	} {
		if !contains(seedStringSlice(cf.Services["signer"].Command), want) {
			t.Fatalf("AUD-66 signer does not bind the demo license to %q", want)
		}
	}
	control := cf.Services["trstctl"]
	if got := stringValue(control.Environment["TRSTCTL_LICENSE_DEPLOYMENT_ID"]); got != "trstctl-local-demo" {
		t.Fatalf("AUD-66 control license deployment id = %q", got)
	}
	if got := stringValue(control.Environment["TRSTCTL_LICENSE_ENVIRONMENT"]); got != "non_production" {
		t.Fatalf("AUD-66 control license environment = %q", got)
	}
	if got := stringValue(control.Environment["TRSTCTL_LIFECYCLE_RENEW_BEFORE"]); got != "5m" {
		t.Fatalf("AUD-66 demo renewal window = %q, want below the shortest 1h seeded profile", got)
	}
}

func seedStringSlice(value any) []string {
	switch typed := value.(type) {
	case []string:
		return typed
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			out = append(out, stringValue(item))
		}
		return out
	default:
		return nil
	}
}

func TestAUD66CIProvesTwoPreservedVolumeRuns(t *testing.T) {
	path := filepath.Join("..", "..", "scripts", "ci", "demo-seed-convergence.sh")
	bodyBytes, err := os.ReadFile(path) // #nosec G304 -- fixed repository test path (CWE-22)
	if err != nil {
		t.Fatalf("AUD-66 convergence proof is absent: %v", err)
	}
	body := string(bodyBytes)
	for _, want := range []string{
		`docker compose -f "$compose_file" wait demo-seed`,
		`docker compose -f "$compose_file" run --rm demo-seed`,
		`count(*) FROM owners`,
		`count(DISTINCT (name, email)) FROM owners`,
		`count(*) FROM outbox`,
		`count(*) FROM api_tokens`,
		`/jsz?streams=true`,
		`seed snapshot changed across the preserved-volume rerun`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("AUD-66 convergence proof missing %q", want)
		}
	}
	workflow := read(t, "..", "..", ".github", "workflows", "ci.yml")
	if !strings.Contains(workflow, "scripts/ci/demo-seed-convergence.sh") {
		t.Fatal("AUD-66 CI starts a healthy API but never waits for and repeats the complete seed")
	}
}
