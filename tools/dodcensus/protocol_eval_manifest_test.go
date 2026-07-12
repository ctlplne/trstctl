// SPDX-License-Identifier: MPL-2.0

package main

import (
	"path/filepath"
	"slices"
	"testing"
)

func TestEvalProtocolProfileManifestClosesProductionAssemblyAndInteropRuntime(t *testing.T) {
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := loadManifest(filepath.Join(repo, "tools", "dodcensus", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	profile := manifest.BuildProfiles[manifest.DefaultBuildProfile]
	const entryID = "protocol_ergonomics.eval_profile"
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
	if entry.CardID != "COMPLETE-PROTO-ERGO-001" || entry.Capability != "protocol_ergonomics" || entry.Enforcement != enforcementRequired {
		t.Fatalf("card/capability/enforcement=%q/%q/%q, want COMPLETE-PROTO-ERGO-001/protocol_ergonomics/required",
			entry.CardID, entry.Capability, entry.Enforcement)
	}
	if entry.Inventory == nil || *entry.Inventory {
		t.Fatalf("inventory=%v, want explicit false residual", entry.Inventory)
	}
	wantDependencies := []string{
		"trstctl.com/trstctl/internal/protocols/acme",
		"trstctl.com/trstctl/internal/protocols/est",
		"trstctl.com/trstctl/internal/protocols/scep",
		"trstctl.com/trstctl/internal/protocols/cmp",
		"trstctl.com/trstctl/internal/protocols/ssh",
		"trstctl.com/trstctl/internal/protocols/spiffe",
		"trstctl.com/trstctl/internal/tsa",
	}
	if !slices.Equal(entry.Dependencies, wantDependencies) {
		t.Fatalf("dependencies=%v, want exact seven served protocol implementations %v", entry.Dependencies, wantDependencies)
	}
	if entry.Assembly.File != "internal/server/run.go" || entry.Assembly.Function != "buildRunDeps" ||
		entry.Assembly.Binding != "returned-field" || entry.Assembly.Field != "Protocols" ||
		!slices.Equal(entry.Assembly.Calls, []string{"evalProtocolProfileFromConfig"}) {
		t.Fatalf("assembly=%+v, want buildRunDeps returned Protocols through evalProtocolProfileFromConfig", entry.Assembly)
	}
	if entry.Runtime.Package != "./internal/server" || entry.Runtime.Test != "TestDODEvalProtocolProfileProductionAssembly" ||
		entry.Runtime.File != "internal/server/dod_eval_protocol_profile_runtime_test.go" ||
		entry.Runtime.Mode != "assembled-handler" || entry.Runtime.Method != "POST" ||
		entry.Runtime.Path != "/api/v1/setup/protocols/activate" || entry.Runtime.SubstrateID != "eval_protocol_interop_v1" {
		t.Fatalf("runtime=%+v, want exact eval-profile activation runtime proof", entry.Runtime)
	}
	substrate, ok := manifest.Substrates[entry.Runtime.SubstrateID]
	if !ok {
		t.Fatalf("manifest is missing substrate %q", entry.Runtime.SubstrateID)
	}
	if substrate.Kind != "vendor-emulator" || substrate.Verifier != "interop" || substrate.Execution != "command" ||
		!slices.Equal(substrate.Command, []string{"tools/dodcensus/substrates/eval_protocol_interop.py"}) ||
		!slices.Equal(substrate.IdentityFiles, []string{"tools/dodcensus/substrates/eval_protocol_interop.py"}) ||
		substrate.ContractFile != "tools/dodcensus/contracts/eval-protocol-interop-v1.json" ||
		substrate.ContractSHA256 == "" {
		t.Fatalf("substrate=%+v, want digest-pinned independent interop command and contract", substrate)
	}
	if evidence := inspectAssembly(repo, entry, profile); !evidence.OK {
		t.Fatalf("assembly closure: %s; required=%v found=%v", evidence.Detail, evidence.Required, evidence.Found)
	}
	if evidence := inspectRuntimeBinding(repo, entry, manifest.Substrates); !evidence.OK {
		t.Fatalf("runtime closure: %s; required=%v found=%v", evidence.Detail, evidence.Required, evidence.Found)
	}
}
