// SPDX-License-Identifier: BUSL-1.1

package docs

import (
	"strings"
	"testing"
)

func TestNarrative005SovereigntyProofBlockCarriesNHILabel(t *testing.T) {
	readme := read(t, "../README.md")
	start := strings.Index(readme, "Three choices set trstctl apart:")
	if start == -1 {
		t.Fatal("README.md missing the first proof block")
	}
	rest := readme[start:]
	end := strings.Index(rest, "## What it answers")
	if end == -1 {
		t.Fatal("README.md first proof block no longer ends before What it answers")
	}
	proofBlock := rest[:end]

	for _, want := range []string{
		"Self-hosted",
		"infrastructure you control",
		"No credential data ships to a vendor cloud",
		"data-sovereign NHI / Machine IAM",
	} {
		if !strings.Contains(proofBlock, want) {
			t.Errorf("README.md first proof block must keep NARRATIVE-005 sovereignty/NHI marker %q", want)
		}
	}
}

func TestNarrative006ProofBlockCitesServedNHIPostureAndMCPSurfaces(t *testing.T) {
	readme := read(t, "../README.md")
	start := strings.Index(readme, "Three choices set trstctl apart:")
	if start == -1 {
		t.Fatal("README.md missing the first proof block")
	}
	rest := readme[start:]
	end := strings.Index(rest, "## What it answers")
	if end == -1 {
		t.Fatal("README.md first proof block no longer ends before What it answers")
	}
	proofBlock := rest[:end]

	for _, want := range []string{
		"served NHI posture",
		"/api/v1/nhi/posture/overprivilege",
		"/api/v1/nhi/posture/stale",
		"/api/v1/mcp/tools",
		"/api/v1/ai/rca",
	} {
		if !strings.Contains(proofBlock, want) {
			t.Errorf("README.md first proof block must keep NARRATIVE-006 served NHI/MCP proof marker %q", want)
		}
	}
}
