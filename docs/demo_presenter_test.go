// SPDX-License-Identifier: MPL-2.0

package docs

import (
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
		`id="lab-manifest"`, `id="demo-proof"`,
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
		"zero enrolled agents",
		"No alert channel is configured in the shipped seed",
		"The lifecycle issuer is not a pre-created CA hierarchy",
	} {
		if !strings.Contains(page, marker) {
			t.Errorf("presenter guide is missing %q", marker)
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
