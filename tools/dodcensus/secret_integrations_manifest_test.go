// SPDX-License-Identifier: MPL-2.0

package main

import (
	"path/filepath"
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
			t.Errorf("%s manifest entries=%d, want registry + 8 providers", capability, seen[capability])
		}
	}
}
