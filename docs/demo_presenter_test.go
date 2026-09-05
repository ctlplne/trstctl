// SPDX-License-Identifier: MPL-2.0

package docs

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A presenter must be able to choose a customer outcome without mistaking a
// seeded tour, an adapter test, or a queued operation for an observed deployment.
func TestDemoPresenterTracksKeepProofAndPrerequisitesVisible(t *testing.T) {
	page := read(t, "demo-click-through.html")
	for _, marker := range []string{
		`id="demo-menu"`, `id="demo-preflight"`, `id="clm-5"`,
		`id="clm-15"`, `id="clm-40"`, `id="internal-ca-lab"`,
		`id="msp-demo"`, `id="device-demo"`, `id="machine-demo"`, `id="f5-demo"`,
		`id="lab-manifest"`, `id="pilot-scorecard"`, `id="demo-proof"`,
		"One scorecard decides whether the pilot proved value",
		"Keep your CA. Automate the lifecycle.",
		"IIS", "Apache", "F5", "5 minutes", "15 minutes", "40 minutes",
		"Prepared live lab", "Recorded evidence", "Read-only tour",
		"Not rehearsed on this candidate", "before and after",
		"A receipt is not a TLS handshake", "Customer A", "Customer B",
		"source fingerprint", "expected fingerprint", "observed fingerprint",
		"No silent switch to the built-in CA", "No zero-downtime claim",
		"one stable idempotency key", "Do not paste private keys",
		"Management readback is not traffic-path verification",
		"Prepared connector targets are not contacted targets.",
		"one active execution runtime", "Running-candidate boundary",
		"No alert channel is configured in the shipped seed",
		"The lifecycle issuer is not a pre-created CA hierarchy",
		`id="zero-to-sale"`, `id="rehearsal-proof"`, `id="byo-ai-agent"`,
		`id="edge-name"`, "Click", "Say", "Expected", "If it does not",
		"Home is the executive signal; Certificates is the exact queue",
		"No issuer is shown in this finding panel",
		"Target path ready — no changes made", "The request worked", "200 OK",
		"Your AI agent is the operator; trstctl is the governed control plane",
		"standard MCP transport is not claimed", "trstctl Edge",
		"binary remains trstctl-agent",
	} {
		if !strings.Contains(page, marker) {
			t.Errorf("presenter guide is missing %q", marker)
		}
	}
}

// TestDemoEvidenceCannotLoseItsCandidateLabel is the DP-007 cold-presenter
// guard. Every retained screenshot must identify its age, candidate,
// environment, and evidence level beside the picture—not only in a distant
// introduction a presenter may skip.
func TestDemoEvidenceCannotLoseItsCandidateLabel(t *testing.T) {
	page := read(t, "demo-click-through.html")
	for _, marker := range []string{
		`id="current-rehearsal-card"`,
		"Current rehearsal card",
		"Not current proof until you complete the checks below",
		`id="historical-evidence-appendix"`,
		"Historical evidence appendix",
	} {
		if !strings.Contains(page, marker) {
			t.Errorf("DP-007: demo guide is missing evidence-boundary marker %q", marker)
		}
	}

	figures := regexp.MustCompile(`(?s)<figure class="product-shot">.*?</figure>`).FindAllString(page, -1)
	if len(figures) == 0 {
		t.Fatal("DP-007: demo guide has no product screenshots to qualify")
	}
	for index, figure := range figures {
		for _, marker := range []string{
			`class="evidence-badge recorded"`,
			`data-evidence-level="recorded"`,
			`data-evidence-candidate="g211"`,
			`data-evidence-observed="2026-09-04"`,
			`data-evidence-environment="retained-local-demo"`,
			"Recorded · g211 · 4 Sep 2026 · retained local demo",
		} {
			if !strings.Contains(figure, marker) {
				t.Errorf("DP-007: product screenshot %d lacks adjacent marker %q", index+1, marker)
			}
		}
	}
}

func TestDemoScreenshotsAreLocalCandidateLabelledEvidence(t *testing.T) {
	page := read(t, "demo-click-through.html")
	matches := regexp.MustCompile(`<img\s+[^>]*src="(assets/demo/[^"]+\.png)"[^>]*alt="([^"]+)"`).FindAllStringSubmatch(page, -1)
	if len(matches) < 8 {
		t.Fatalf("presenter guide has %d local screenshots; want at least 8", len(matches))
	}
	for _, match := range matches {
		if strings.TrimSpace(match[2]) == "" {
			t.Errorf("screenshot %s has no useful alt text", match[1])
		}
		info, err := os.Stat(filepath.FromSlash(match[1]))
		if err != nil {
			t.Errorf("screenshot %s is missing: %v", match[1], err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("screenshot %s is empty", match[1])
		}
	}
	for _, marker := range []string{
		"g211", "f8a266242eab77737f88508f6cb7200d055d1cbe",
		"4 September 2026", "sanitized", "recorded screenshot evidence",
	} {
		if !strings.Contains(page, marker) {
			t.Errorf("screenshot provenance is missing %q", marker)
		}
	}
}

func TestDemoAppLinksPointAtMountedRoutes(t *testing.T) {
	routes := map[string]bool{"/": true}
	for _, match := range regexp.MustCompile(`path="([^"]+)"`).FindAllStringSubmatch(read(t, "../web/src/App.tsx"), -1) {
		routes["/"+strings.TrimPrefix(match[1], "/")] = true
	}
	for _, match := range regexp.MustCompile(`data-demo-path="([^"]+)"`).FindAllStringSubmatch(read(t, "demo-click-through.html"), -1) {
		path := strings.SplitN(match[1], "?", 2)[0]
		if !routes[path] {
			t.Errorf("demo links to %s but App.tsx mounts no such route", path)
		}
	}
}

func TestDemoReadingProgressIsCandidateScopedAndNotProductProof(t *testing.T) {
	page := read(t, "demo-click-through.html")
	for _, marker := range []string{
		"trstctl-demo-walkthrough-progress-v2", "${demoOrigin}",
		"${expectedCandidate || 'unverified'}", "Reading progress, not qualification",
		"Storage can be disabled", "tour stops reviewed",
	} {
		if !strings.Contains(page, marker) {
			t.Errorf("reading-progress boundary is missing %q", marker)
		}
	}
}
