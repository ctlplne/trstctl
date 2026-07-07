// SPDX-License-Identifier: LicenseRef-trstctl-EE

package verify

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// wasm_parity_test.go is the WASM SMOKE TEST asserting native/WASM RESULT PARITY
// (AGID-09 WASM build parity / claim 28 INV-A7). It builds the ./wasm entrypoint
// for GOOS=js GOARCH=wasm, runs it under Node via Go's wasm exec shim, and asserts
// the offline decision it prints equals the decision the SAME sample produces
// natively (BuildAndVerifySample). If the native and wasm verifiers ever diverge
// -- a different accept/refuse, class, operation, or tool -- this fails.
//
// The test is skipped (not failed) when the toolchain's wasm exec shim or Node is
// unavailable, so it never blocks an environment that cannot run wasm; CI provides
// both. The verify path it exercises under wasm constructs no network client.

// TestRPVerify_WASMParity builds the wasm verifier, runs it under Node, and
// compares its printed decision to the native one.
func TestRPVerify_WASMParity(t *testing.T) {
	goroot := runtimeGOROOT(t)
	execShim := filepath.Join(goroot, "lib", "wasm", "go_js_wasm_exec")
	if _, err := os.Stat(execShim); err != nil {
		t.Skipf("wasm exec shim not present (%s): %v", execShim, err)
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not found; skipping wasm parity")
	}

	// Native decision.
	nres, ok := BuildAndVerifySample()
	if !ok {
		t.Fatal("native BuildAndVerifySample failed to build the sample")
	}
	wantLine := fmt.Sprintf("PARITY accepted=%v class=%s op=%s tool=%s refusal=%q",
		nres.Accepted, nres.AuthClass, nres.Operation, nres.Tool, nres.RefusalError)

	// Build the wasm entrypoint.
	tmp := t.TempDir()
	wasmOut := filepath.Join(tmp, "agidverify.wasm")
	build := exec.Command("go", "build", "-o", wasmOut, "./wasm")
	build.Env = append(os.Environ(), "GOOS=js", "GOARCH=wasm")
	if gt := os.Getenv("GOTMPDIR"); gt != "" {
		build.Env = append(build.Env, "GOTMPDIR="+gt)
	}
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("wasm build failed: %v\n%s", err, out)
	}

	// Run the wasm binary under Node via the exec shim.
	run := exec.Command(execShim, wasmOut)
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("wasm run failed: %v\n%s", err, out)
	}
	gotLine := extractParityLine(string(out))
	if gotLine == "" {
		t.Fatalf("no PARITY line in wasm output:\n%s", out)
	}
	if gotLine != wantLine {
		t.Fatalf("native/WASM parity mismatch:\n native: %s\n   wasm: %s", wantLine, gotLine)
	}
}

func runtimeGOROOT(t *testing.T) string {
	t.Helper()
	// Prefer the environment/go env GOROOT so the test uses the active toolchain.
	if gr := os.Getenv("GOROOT"); gr != "" {
		return gr
	}
	out, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		t.Skipf("cannot determine GOROOT: %v", err)
	}
	_ = runtime.Version()
	return strings.TrimSpace(string(out))
}

func extractParityLine(s string) string {
	for _, ln := range strings.Split(s, "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, "PARITY ") {
			return ln
		}
	}
	return ""
}
