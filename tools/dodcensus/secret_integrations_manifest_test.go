// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestSecretIntegrationManifestMatchesProductionAssemblyAndRuntimeBinding(t *testing.T) {
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := loadManifest(filepath.Join(repo, "tools", "dodcensus", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	profile := manifest.BuildProfiles[manifest.DefaultBuildProfile]
	wantByCapability := map[string]int{"dynamic_secret": 9, "secret_sync": 9}
	seen := map[string]int{}
	for _, entry := range manifest.Entries {
		if _, ok := wantByCapability[entry.Capability]; !ok {
			continue
		}
		seen[entry.Capability]++
		if entry.Enforcement != enforcementRequired {
			t.Errorf("%s enforcement=%q, want required", entry.ID, entry.Enforcement)
		}
		if evidence := inspectAssembly(repo, entry, profile); !evidence.OK {
			t.Errorf("%s assembly: %s; required=%v found=%v", entry.ID, evidence.Detail, evidence.Required, evidence.Found)
		}
		if evidence := inspectRuntimeBinding(repo, entry, manifest.Substrates); !evidence.OK {
			t.Errorf("%s runtime: %s; required=%v found=%v", entry.ID, evidence.Detail, evidence.Required, evidence.Found)
		}
	}
	for capability, want := range wantByCapability {
		if seen[capability] != want {
			t.Errorf("%s manifest entries=%d, want %d (registry + full provider catalog)", capability, seen[capability], want)
		}
	}
}

func TestSecretResidualManifestPinsNativeSyncAssemblyAndRuntime(t *testing.T) {
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := loadManifest(filepath.Join(repo, "tools", "dodcensus", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	profile := manifest.BuildProfiles[manifest.DefaultBuildProfile]
	want := map[string]struct {
		card string
		call string
	}{
		"secrets_residuals.terraform_opentofu_native_sync": {
			card: "COMPLETE-SECRETS-103", call: "secretsync.NewTerraformCloudOpenTofuPusher",
		},
		"secrets_residuals.vault_kv_outbound_sync": {
			card: "COMPLETE-SECRETS-104", call: "secretsync.NewVaultKVV2Pusher",
		},
	}
	seen := map[string]bool{}
	for _, entry := range manifest.Entries {
		expected, ok := want[entry.ID]
		if !ok {
			continue
		}
		seen[entry.ID] = true
		if entry.CardID != expected.card || entry.Capability != "secrets_residuals" || entry.Enforcement != enforcementRequired {
			t.Errorf("%s card/capability/enforcement=%q/%q/%q, want %q/secrets_residuals/required",
				entry.ID, entry.CardID, entry.Capability, entry.Enforcement, expected.card)
		}
		if entry.Inventory == nil || !*entry.Inventory {
			t.Errorf("%s inventory=%v, want explicit true because this residual is also an advertised native sync target", entry.ID, entry.Inventory)
		}
		if entry.Assembly.File != "internal/server/run.go" || entry.Assembly.Function != "buildRunDeps" ||
			entry.Assembly.Binding != "returned-field" || entry.Assembly.Field != "TenantSecretSyncTargets" ||
			!slices.Contains(entry.Assembly.Calls, expected.call) {
			t.Errorf("%s assembly=%+v, want buildRunDeps returned TenantSecretSyncTargets calling %s",
				entry.ID, entry.Assembly, expected.call)
		}
		if entry.Runtime.Package != "./internal/server" || entry.Runtime.Test != "TestDODSecretSyncProductionAssembly" ||
			entry.Runtime.File != "internal/server/dod_secret_integrations_runtime_test.go" ||
			entry.Runtime.Mode != "assembled-handler" || entry.Runtime.Method != "POST" ||
			entry.Runtime.Path != "/api/v1/secrets/syncs" || entry.Runtime.SubstrateID != "secret_integrations_sync" {
			t.Errorf("%s runtime=%+v, want focused assembled secret-sync proof", entry.ID, entry.Runtime)
		}
		if evidence := inspectAssembly(repo, entry, profile); !evidence.OK {
			t.Errorf("%s assembly closure: %s; required=%v found=%v", entry.ID, evidence.Detail, evidence.Required, evidence.Found)
		}
		if evidence := inspectRuntimeBinding(repo, entry, manifest.Substrates); !evidence.OK {
			t.Errorf("%s runtime closure: %s; required=%v found=%v", entry.ID, evidence.Detail, evidence.Required, evidence.Found)
		}
	}
	for id := range want {
		if !seen[id] {
			t.Errorf("manifest is missing native secret residual %s", id)
		}
	}
}

func TestSecretIntegrationDatabaseTimeoutPreservesContainerDiagnostics(t *testing.T) {
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(repo, "tools", "dodcensus", "substrates", "secret_integrations.py")) // #nosec G304 -- test reads the exact committed substrate source (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	for _, required := range []string{
		`"mongodb": "mongo:7.0.39-jammy@sha256:04582c3a144d088f841c446abfc19f79adcefa8bd00ad4a7fb18e27b9585c5d6"`,
		"last_database_error = str(exc)",
		"self._database_failure_diagnostics(last_database_error)",
		`args = ["docker", "run", "-d", "--name", self.container`,
		`["docker", "inspect", "--format"`,
		`["docker", "logs", "--tail", "80", self.container]`,
		`run(["docker", "rm", "-f", self.container], timeout=20, check=False)`,
		"database did not become healthy",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("secret-integration database timeout omits %q", required)
		}
	}
	if strings.Contains(source, `args = ["docker", "run", "-d", "--rm"`) {
		t.Fatal("database fixture auto-removes failed containers before diagnostics can read their state and logs")
	}
	if strings.Contains(source, `"mongodb": "mongo:8.`) {
		t.Fatal("MongoDB 8.x fixture is incompatible with Docker Desktop Linux kernel 6.19")
	}
}

func TestDynamicSecretFullProofStartsDatabaseSubstratesThroughBoundedHelper(t *testing.T) {
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(repo, "internal", "server", "dod_secret_integrations_runtime_test.go")) // #nosec G304 -- test reads the exact committed runtime proof source (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	for _, required := range []string{
		`dynamicRegistry, registryDB := dodStartDatabaseSecretSubstrate(t, "dynamic_secret.registry")`,
		`dynamicPostgres, postgresDB := dodStartDatabaseSecretSubstrate(t, "dynamic_secret.postgresql")`,
		`dynamicMySQL, mysqlDB := dodStartDatabaseSecretSubstrate(t, "dynamic_secret.mysql")`,
		`dynamicMongo, mongoDB := dodStartDatabaseSecretSubstrate(t, "dynamic_secret.mongodb")`,
		`dynamicRedis, redisDB := dodStartDatabaseSecretSubstrate(t, "dynamic_secret.redis")`,
		`func dodStartDatabaseSecretSubstrate(t *testing.T, entryID string) (*proof.ExternalSubstrate, dodSubstrateConfig)`,
	} {
		if !strings.Contains(source, required) {
			t.Errorf("full dynamic-secret proof omits bounded database start %q", required)
		}
	}
	for _, forbidden := range []string{
		`dynamicRegistry = proof.StartCommand(t, "dynamic_secret.registry")`,
		`dynamicPostgres = proof.StartCommand(t, "dynamic_secret.postgresql")`,
		`dynamicMySQL = proof.StartCommand(t, "dynamic_secret.mysql")`,
		`dynamicMongo = proof.StartCommand(t, "dynamic_secret.mongodb")`,
		`dynamicRedis = proof.StartCommand(t, "dynamic_secret.redis")`,
	} {
		if strings.Contains(source, forbidden) {
			t.Errorf("full dynamic-secret proof retains unbounded database launch %q", forbidden)
		}
	}
}
