// SPDX-License-Identifier: MPL-2.0

package main

import (
	"path/filepath"
	"slices"
	"testing"
)

func TestBreakglassRotationManifestClosesProductionSignerAndOpenSSLRuntime(t *testing.T) {
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := loadManifest(filepath.Join(repo, "tools", "dodcensus", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	profile := manifest.BuildProfiles[manifest.DefaultBuildProfile]
	const entryID = "breakglass_rotation.cross_sign_rekey"
	var found *Entry
	for index := range manifest.Entries {
		if manifest.Entries[index].ID == entryID {
			found = &manifest.Entries[index]
			break
		}
	}
	if found == nil {
		t.Fatalf("manifest is missing %s", entryID)
	}
	entry := *found
	if entry.CardID != "COMPLETE-BREAKGLASS-001" || entry.Capability != "breakglass_rotation" || entry.Enforcement != enforcementRequired {
		t.Fatalf("card/capability/enforcement=%q/%q/%q, want COMPLETE-BREAKGLASS-001/breakglass_rotation/required",
			entry.CardID, entry.Capability, entry.Enforcement)
	}
	if entry.Inventory == nil || *entry.Inventory {
		t.Fatalf("inventory=%v, want explicit false residual", entry.Inventory)
	}
	wantDependencies := []string{
		"trstctl.com/trstctl/internal/breakglass",
		"trstctl.com/trstctl/internal/ca/hierarchy",
		"trstctl.com/trstctl/internal/crypto",
	}
	if !slices.Equal(entry.Dependencies, wantDependencies) {
		t.Fatalf("dependencies=%v, want exact break-glass, CA hierarchy, and crypto-boundary packages %v", entry.Dependencies, wantDependencies)
	}
	if entry.Assembly.File != "internal/server/run.go" || entry.Assembly.Function != "buildRunDeps" ||
		entry.Assembly.Binding != "returned-field" || entry.Assembly.Field != "BreakglassIssuer" ||
		!slices.Equal(entry.Assembly.Calls, []string{"breakglassRotationFromConfig"}) {
		t.Fatalf("assembly=%+v, want buildRunDeps returned BreakglassIssuer through breakglassRotationFromConfig", entry.Assembly)
	}
	if entry.Runtime.Package != "./internal/server" || entry.Runtime.Test != "TestDODBreakglassRotationProductionAssembly" ||
		entry.Runtime.File != "internal/server/dod_breakglass_rotation_runtime_test.go" ||
		entry.Runtime.Mode != "assembled-handler" || entry.Runtime.Method != "POST" ||
		entry.Runtime.Path != "/api/v1/breakglass/cross-sign" || entry.Runtime.SubstrateID != "breakglass_openssl" {
		t.Fatalf("runtime=%+v, want exact assembled break-glass/OpenSSL proof", entry.Runtime)
	}
	substrate, ok := manifest.Substrates[entry.Runtime.SubstrateID]
	if !ok {
		t.Fatalf("manifest is missing substrate %q", entry.Runtime.SubstrateID)
	}
	if substrate.Kind != "vendor-emulator" || substrate.Verifier != "interop" || substrate.Execution != "command" ||
		!slices.Equal(substrate.Command, []string{"tools/dodcensus/substrates/breakglass_openssl.py"}) ||
		!slices.Equal(substrate.IdentityFiles, []string{"tools/dodcensus/substrates/breakglass_openssl.py"}) ||
		substrate.ContractFile != "tools/dodcensus/contracts/breakglass-rotation-openssl-v1.json" || substrate.ContractSHA256 == "" {
		t.Fatalf("substrate=%+v, want digest-pinned independent OpenSSL command and contract", substrate)
	}
	if evidence := inspectAssembly(repo, entry, profile); !evidence.OK {
		t.Fatalf("assembly closure: %s; required=%v found=%v", evidence.Detail, evidence.Required, evidence.Found)
	}
	if evidence := inspectRuntimeBinding(repo, entry, manifest.Substrates); !evidence.OK {
		t.Fatalf("runtime closure: %s; required=%v found=%v", evidence.Detail, evidence.Required, evidence.Found)
	}
}
