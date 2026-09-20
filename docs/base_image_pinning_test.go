// SPDX-License-Identifier: BUSL-1.1

package docs

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestReleaseBasesAreDigestPinned guards SUPPLY-001 at the release workflow.
//
// release.yml used to resolve every external base from a FLOATING tag at build
// time and validate only that the answer matched ^sha256:[0-9a-f]{64}$. That
// checks the shape of the digest, not its identity: if an upstream tag is
// repointed, or the registry account is compromised, between one release and the
// next, the release silently builds on a different image and every attestation
// faithfully attests the wrong thing. The step's own comment claimed it prevented
// exactly that.
//
// Each base must now be resolved through scripts/ci/resolve-pinned-base.sh, which
// compares against a digest committed in .github/base-image-digests.env and fails
// the build when it does not match. This test exists so that comparison cannot be
// quietly removed later.
func TestReleaseBasesAreDigestPinned(t *testing.T) {
	release := read(t, "../.github/workflows/release.yml")

	// Every external base the release builds on must go through the pinning
	// script. Naming them explicitly means a NEW base image cannot be added
	// unpinned without this list being updated too.
	for _, base := range []string{
		"node:22-bookworm-slim",
		"gcr.io/distroless/static-debian12:nonroot",
		"debian:bookworm-slim",
		`"golang:${go_version}-bookworm"`,
	} {
		idx := strings.Index(release, base)
		if idx < 0 {
			t.Errorf("release.yml no longer references base %s; if it was replaced, pin the replacement", base)
			continue
		}
		// The reference must appear as an argument to the pinning script, not as a
		// bare imagetools lookup.
		line := lineContaining(release, base)
		if !strings.Contains(line, "resolve-pinned-base.sh") {
			t.Errorf("base %s is resolved without the pinning script:\n    %s\n"+
				"an upstream tag that moves between releases would be inherited silently", base, strings.TrimSpace(line))
		}
	}

	// A bare imagetools inspect anywhere in the workflow means something slipped
	// past the script.
	for _, line := range strings.Split(release, "\n") {
		if strings.Contains(line, "imagetools inspect") && !strings.Contains(line, "resolve-pinned-base") {
			t.Errorf("release.yml resolves a base directly, bypassing the pin:\n    %s", strings.TrimSpace(line))
		}
	}
}

// TestBaseImagePinFileIsWellFormed keeps the pin file parseable by the shell
// script that reads it: a malformed entry would be silently skipped by the grep,
// which reads as "no pin recorded" and fails the release confusingly.
func TestBaseImagePinFileIsWellFormed(t *testing.T) {
	body, err := os.ReadFile("../.github/base-image-digests.env")
	if err != nil {
		t.Fatalf("the pin file is missing; the release must not build on unpinned bases: %v", err)
	}
	entry := regexp.MustCompile(`^[A-Z0-9_]+=sha256:[0-9a-f]{64}$`)
	for i, line := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !entry.MatchString(trimmed) {
			t.Errorf("line %d is neither a comment nor KEY=sha256:<64 hex>: %q", i+1, trimmed)
		}
	}
}

// TestPinningScriptRefusesUnpinnedAndMovedBases pins the script's contract in
// prose form, so a future edit that turns a failure into a warning is visible.
func TestPinningScriptRefusesUnpinnedAndMovedBases(t *testing.T) {
	script := read(t, "../scripts/ci/resolve-pinned-base.sh")
	for _, required := range []string{
		"set -euo pipefail",
		"HAS MOVED",
		"no pin recorded",
		"exit 1",
	} {
		if !strings.Contains(script, required) {
			t.Errorf("resolve-pinned-base.sh no longer contains %q; a moved or unpinned base "+
				"must fail the release, not warn", required)
		}
	}
	// Sourcing the pin file would let a stray line execute; it is read with grep.
	if strings.Contains(script, "source ") || strings.Contains(script, ". \"${pin_file}\"") {
		t.Error("the pin file must be read, not sourced — sourcing executes whatever it contains")
	}
}

func lineContaining(body, needle string) string {
	for _, line := range strings.Split(body, "\n") {
		if strings.Contains(line, needle) {
			return line
		}
	}
	return ""
}

// TestEveryRequiredBaseImagePinIsPresent closes the gap that made the first
// post-merge release fail by design while CI stayed green (AUD-201 follow-up
// M1/V12): the enforcement shipped with an EMPTY pin file — every entry
// commented out — and the well-formedness test above skips comments, so
// nothing noticed that resolve-pinned-base.sh would hard-fail all four image
// jobs on the next tag while sibling jobs still published a partial release.
// The four pins are now committed (resolved from the live registries, never
// fabricated); this test requires each to be PRESENT and uncommented, so
// "green CI, broken release" cannot recur. The Go pin's key tracks the
// toolchain in go.mod, so a toolchain bump fails here until the new base is
// deliberately pinned — which is the SUPPLY-001 design.
func TestEveryRequiredBaseImagePinIsPresent(t *testing.T) {
	gomod := read(t, "../go.mod")
	toolchain := regexp.MustCompile(`(?m)^toolchain go(\S+)$`).FindStringSubmatch(gomod)
	if toolchain == nil {
		t.Fatal("go.mod no longer declares a toolchain; the Go base-image pin key cannot be derived")
	}
	goKey := "GOLANG_" + strings.ReplaceAll(toolchain[1], ".", "_") + "_BOOKWORM"

	body := read(t, "../.github/base-image-digests.env")
	pinned := map[string]bool{}
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, _, ok := strings.Cut(trimmed, "=")
		if ok {
			pinned[key] = true
		}
	}
	for _, required := range []string{
		"NODE_22_BOOKWORM_SLIM",
		goKey,
		"DEBIAN_BOOKWORM_SLIM",
		"DISTROLESS_STATIC_DEBIAN12_NONROOT",
	} {
		if !pinned[required] {
			t.Errorf("required base-image pin %s is missing or commented out; the next tagged release fails "+
				"deterministically at resolve-pinned-base.sh while sibling jobs publish a partial release — "+
				"resolve the digest against the real registry and commit the pin", required)
		}
	}
}
