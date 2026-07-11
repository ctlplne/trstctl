// SPDX-License-Identifier: MPL-2.0

package main

import (
	"path/filepath"
	"testing"
)

func TestNotificationAndCodeSigningManifestMatchProductionAssemblyAndRuntimeBinding(t *testing.T) {
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := loadManifest(filepath.Join(repo, "tools", "dodcensus", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	profile := manifest.BuildProfiles[manifest.DefaultBuildProfile]
	want := map[string]bool{
		"code_signing.default":           true,
		"notification_channel.dispatch":  true,
		"notification_channel.pagerduty": true,
		"notification_channel.opsgenie":  true,
	}
	checked := 0
	for _, entry := range manifest.Entries {
		if !want[entry.ID] {
			continue
		}
		checked++
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
	if checked != len(want) {
		t.Fatalf("notification/code-signing manifest entries = %d, want %d", checked, len(want))
	}
}
