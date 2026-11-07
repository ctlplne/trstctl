// SPDX-License-Identifier: BUSL-1.1
package servicedependents

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSealedManifestIntentBindsOneAccountWithoutInlineArraysA267(t *testing.T) {
	header, entry := manifestFixture(t)
	digest, err := header.Digest()
	if err != nil {
		t.Fatal(err)
	}
	page, err := NewRotationManifestPage(header, 0, digest, []RotationManifestEntry{entry})
	if err != nil {
		t.Fatal(err)
	}
	seal, err := NewRotationManifestSeal(header, page, 1, 1, header.ExpiresAt.Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	intent, err := NewRotationIntentFromManifest(header, seal)
	if err != nil {
		t.Fatal(err)
	}
	if intent.Plan.Version != RotationManifestPlanVersion || intent.Plan.Manifest == nil || len(intent.Plan.Hosts) != 0 || len(intent.Plan.Order) != 0 || len(intent.Probes) != 0 || intent.Plan.Account != header.Account || intent.ExpectedVersion != header.ExpectedVersion || intent.ProviderBinding != header.ProviderBinding || !intent.Plan.ExpiresAt.Equal(seal.ExpiresAt) {
		t.Fatal("sealed root split or changed exact account authority")
	}
	if intent.Plan.Hosts == nil || intent.Plan.Order == nil || intent.Probes == nil {
		t.Fatal("server-derived sealed authority must retain the published array wire types")
	}
	if intent.Plan.Validate() != nil {
		t.Fatal("valid sealed plan refused")
	}
	if _, err := intent.Digest(); err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"inline-hosts", "inline-order", "manifest-id", "expiry", "version"} {
		altered := intent.Plan
		copied := *intent.Plan.Manifest
		altered.Manifest = &copied
		switch change {
		case "inline-hosts":
			altered.Hosts = []RotationHost{{Binding: entry.Host.Binding}}
		case "inline-order":
			altered.Order = []DependentRef{entry.Ref}
		case "manifest-id":
			altered.Manifest.ID = "58000000-0000-4000-8000-000000000001"
		case "expiry":
			altered.ExpiresAt = altered.ExpiresAt.Add(time.Second)
		case "version":
			altered.Version = RotationPlanVersion
		}
		if altered.Validate() == nil {
			t.Fatalf("mixed or changed sealed authority accepted: %s", change)
		}
	}
	legacy, _ := workflowFixture(t)
	raw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"manifest"`) {
		t.Fatal("legacy nil encoding widened")
	}
	if legacy.Plan.Validate() != nil {
		t.Fatal("old inline plan stopped validating")
	}
}
