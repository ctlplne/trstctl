// SPDX-License-Identifier: BUSL-1.1

package secretscan

import (
	"strings"
	"testing"
)

// N6-L3: an exported image scan's annotation names the image it came from;
// a collected scan's annotation names only its connection, so the scan has
// no configured object and its findings take the image the collection read.
func TestCollectedScanHasNoConfiguredObjectN6L3(t *testing.T) {
	digest := "sha256:" + strings.Repeat("ab", 32)
	exported := ThirdPartyScanConfig{Provider: "container_registry",
		Annotation: &AnnotationConfig{BaseURL: "https://registry.example.test", TokenRef: "env:N6L3_TEST", Repository: "team/app", Digest: digest}} // #nosec G101 -- an env: reference name, no credential value (CWE-798)
	if o := exported.ConfiguredObject(); o["repository"] != "team/app" || o["digest"] != digest {
		t.Fatalf("an exported image's configured object = %+v", o)
	}
	collected := ThirdPartyScanConfig{Provider: "container_registry",
		Annotation: &AnnotationConfig{BaseURL: "https://registry.example.test", TokenRef: "env:N6L3_TEST"}, // #nosec G101 -- an env: reference name, no credential value (CWE-798)
		Collect:    &CollectConfig{BaseURL: "https://registry.example.test", Repository: "team/app", Reference: "v1"}}
	if o := collected.ConfiguredObject(); o != nil {
		t.Fatalf("a collected image scan's configured object = %+v; want none (the collection names the image)", o)
	}
	if o, ok := collected.ProviderObject(t.TempDir(), "image-0/layer-0/app/.env", 1); ok || o != nil {
		t.Fatalf("a collected image finding's located object = %+v %v; want none here", o, ok)
	}
}
