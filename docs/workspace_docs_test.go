// SPDX-License-Identifier: BUSL-1.1

package docs

import (
	"strings"
	"testing"
)

// TestWorkspaceMentalModelIsDocumented keeps the documentation front door aligned
// with the console's product architecture. A feature catalog is useful reference,
// but it must not become the first mental model a new evaluator has to invent.
func TestWorkspaceMentalModelIsDocumented(t *testing.T) {
	index := read(t, "index.md")
	productMap := read(t, "product-map.md")
	console := read(t, "web-console.md")
	nav := read(t, "../mkdocs.yml")

	for _, name := range []string{
		"Home",
		"Certificate Lifecycle",
		"Machine & Workload Trust",
		"Secrets & Access",
		"Software Trust",
		"Trust Operations",
	} {
		for file, body := range map[string]string{
			"index.md":       index,
			"product-map.md": productMap,
			"web-console.md": console,
		} {
			if !strings.Contains(body, name) {
				t.Errorf("%s must explain the %q workspace", file, name)
			}
		}
	}

	for _, want := range []string{
		"Product map: product-map.md",
		"First evaluation: getting-started.md",
		"Daily operator",
		"On-call responder",
		"Auditor",
		"API and CLI integrator",
	} {
		if !strings.Contains(nav, want) {
			t.Errorf("mkdocs.yml must expose the reader path %q", want)
		}
	}

	for _, stale := range []string{
		"The single pane of glass: KPI tiles",
		"anything you can do here you can also do through",
	} {
		if strings.Contains(console, stale) {
			t.Errorf("web-console.md still contains stale or overbroad Home copy %q", stale)
		}
	}
}
