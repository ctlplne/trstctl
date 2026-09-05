// SPDX-License-Identifier: MPL-2.0

package docs

import (
	"html"
	"regexp"
	"strings"
	"testing"
)

// TestPublicProductMapMatchesNavigationRegistry is the DP-005 drift guard.
// ELI5: the running console decides how many tools customers see. Public copy
// must repeat that exact list instead of maintaining an unrelated hand count.
func TestPublicProductMapMatchesNavigationRegistry(t *testing.T) {
	navigation := read(t, "../web/src/lib/navigation.ts")
	messages := read(t, "../web/src/i18n/messages.ts")
	readme := read(t, "../README.md")
	demo := read(t, "demo-click-through.html")

	start := strings.Index(navigation, "export const navSpaces: NavSpace[] = [")
	end := strings.Index(navigation, "export const navModules: NavModule[]")
	if start < 0 || end <= start {
		t.Fatal("DP-005: could not isolate the canonical navSpaces registry")
	}
	spaceKeys := regexp.MustCompile(`(?s)\{\s*id:\s*"[^"]+",\s*labelKey:\s*"([^"]+)"`).FindAllStringSubmatch(navigation[start:end], -1)
	if len(spaceKeys) == 0 {
		t.Fatal("DP-005: canonical navSpaces registry contains no tools")
	}

	labels := make([]string, 0, len(spaceKeys))
	for _, match := range spaceKeys {
		key := match[1]
		messageRE := regexp.MustCompile(`(?s)"` + regexp.QuoteMeta(key) + `"\s*:\s*\{\s*defaultMessage:\s*"([^"]+)"`)
		message := messageRE.FindStringSubmatch(messages)
		if len(message) != 2 {
			t.Fatalf("DP-005: navigation label %q has no English defaultMessage", key)
		}
		labels = append(labels, message[1])
	}

	var platformRow string
	for _, line := range strings.Split(readme, "\n") {
		if strings.HasPrefix(line, "| **Platform**") {
			platformRow = line
			break
		}
	}
	if platformRow == "" {
		t.Fatal("DP-005: README has no Platform capability row")
	}
	wantCount := "six operator tools"
	if !strings.Contains(platformRow, wantCount) {
		t.Errorf("DP-005: README Platform row must derive the console count as %q; canonical tools are %v", wantCount, labels)
	}
	if strings.Contains(strings.ToLower(platformRow), "five operator") {
		t.Error("DP-005: README still publishes the stale five-tool mental model")
	}
	for _, label := range labels {
		if !strings.Contains(platformRow, label) {
			t.Errorf("DP-005: README Platform row omits canonical tool %q", label)
		}
		if !strings.Contains(demo, "<strong>"+html.EscapeString(label)+"</strong>") {
			t.Errorf("DP-005: demo guide omits canonical tool label %q", label)
		}
	}
}
