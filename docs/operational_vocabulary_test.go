// SPDX-License-Identifier: MPL-2.0

package docs

import (
	"strings"
	"testing"
)

// TestOperationalVocabularyIsDefinedAndLinked is the DP-006 cold-reader guard.
// ELI5: a new operator should not need source code to learn who is accountable,
// which system changes, or where the work actually executes.
func TestOperationalVocabularyIsDefinedAndLinked(t *testing.T) {
	glossary := read(t, "glossary.md")
	flatGlossary := strings.Join(strings.Fields(glossary), " ")
	for _, marker := range []string{
		"## The operational map",
		"### Owner",
		"### Service",
		"### Destination / deployment target",
		"### Connector",
		"### trstctl Edge (agent runtime)",
		"### Edge Collector",
		"### Network relay",
		"### Execution vantage",
		"Saving a destination does not contact or change it.",
		"The binary remains `trstctl-agent` and the API/CLI resource remains `agents`",
		"A customer AI agent is a caller; trstctl Edge is an execution runtime.",
	} {
		if !strings.Contains(flatGlossary, strings.Join(strings.Fields(marker), " ")) {
			t.Errorf("DP-006: glossary is missing operational-vocabulary marker %q", marker)
		}
	}

	linkedPages := map[string][]string{
		"getting-started.md": {
			"[owner](glossary.md#owner)",
			"[deployment target](glossary.md#destination-deployment-target)",
			"[trstctl Edge runtime](glossary.md#trstctl-edge-agent-runtime)",
		},
		"features/deployment-connectors.md": {
			"[deployment connector](../glossary.md#connector)",
			"[target](../glossary.md#destination-deployment-target)",
			"[execution vantage](../glossary.md#execution-vantage)",
		},
		"features/discovery-and-inventory.md": {
			"[trstctl Edge runtime](../glossary.md#trstctl-edge-agent-runtime)",
			"[network relay](../glossary.md#network-relay)",
		},
	}
	for page, markers := range linkedPages {
		body := read(t, page)
		for _, marker := range markers {
			if !strings.Contains(body, marker) {
				t.Errorf("DP-006: %s does not link first-use term %q", page, marker)
			}
		}
	}
}
