// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// CORRECT-102 (15-CORRECT) PROTECT regression guard.
//
// Confirmed strength, two halves:
//
//  1. Profile gating runs BEFORE signing on the served issuance path. In
//     internal/server/issuance.go, mintServedLeafMaterialForSelection calls
//     enforceProfile (which validates the request against the bound certificate
//     profile and fails closed) BEFORE it calls issueEndpointCSR (the single
//     platform/private/external CA routing seam). An out-of-profile request is
//     therefore rejected before any CA can produce a signature.
//
//  2. ACME's AcceptAll challenge validator is test-only. AcceptAll accepts every
//     challenge without checking; it must never appear on a production path — the
//     served ACME mount uses the real, fail-closed validators (see
//     internal/server/protocols.go buildServedACME). The strength is that AcceptAll
//     is defined and referenced only from *_test.go files.
//
// Both halves are ANCHOR-LOCKS over the real source (PG-free, no signer, no network):
// half 1 reads issuance.go and asserts the call ORDER (enforceProfile precedes the
// selection-aware CA routing call within mintServedLeafMaterialForSelection); half
// 2 walks the entire module and asserts every file that mentions AcceptAll is a
// _test.go file. A future edit that signs before validating, or that wires AcceptAll
// into a production file, turns this guard RED.

// mintServedLeafSource returns the body of the selection-aware served mint from
// issuance.go, so the order check is scoped to the path every supported issuer uses.
func mintServedLeafSource(t *testing.T) string {
	t.Helper()
	src, err := os.ReadFile("issuance.go")
	if err != nil {
		t.Fatalf("CORRECT-102 anchor: cannot read issuance.go: %v", err)
	}
	body := string(src)
	const sig = "func (d *issuanceDispatcher) mintServedLeafMaterialForSelection("
	start := strings.Index(body, sig)
	if start < 0 {
		t.Fatalf("CORRECT-102 anchor: mintServedLeafMaterialForSelection no longer exists in issuance.go (the served issuance seam moved); re-point this guard")
	}
	// The next top-level func declaration bounds this function's body.
	rest := body[start+len(sig):]
	if end := strings.Index(rest, "\nfunc "); end >= 0 {
		return body[start : start+len(sig)+end]
	}
	return body[start:]
}

func TestProtectCORRECT102_ProfileValidatedBeforeSigning(t *testing.T) {
	fn := mintServedLeafSource(t)

	if err := profileValidationPrecedesCA(fn); err != nil {
		t.Fatal(err)
	}

	// Lock the fail-closed contract of enforceProfile itself: a configured-but-
	// unresolved profile must deny rather than silently mint.
	if !strings.Contains(fn, "leafProfile, err := d.enforceProfile(") {
		t.Errorf("CORRECT-102: selection-aware mint no longer binds enforceProfile's error return; a profile-validation failure may no longer reject the mint")
	}
}

func TestProtectCORRECT102_OracleRejectsSigningBeforeProfileValidation(t *testing.T) {
	broken := `func mint() {
		d.issueEndpointCSR()
		d.enforceProfile()
	}`
	if err := profileValidationPrecedesCA(broken); err == nil {
		t.Fatal("CORRECT-102 calibration: guard accepted a deliberately broken sign-before-profile control")
	}
}

func profileValidationPrecedesCA(fn string) error {
	enforceIdx := strings.Index(fn, "d.enforceProfile(")
	if enforceIdx < 0 {
		return fmt.Errorf("CORRECT-102: selection-aware mint no longer calls d.enforceProfile; profile gating before signing is no longer present")
	}
	signIdx := strings.Index(fn, "d.issueEndpointCSR(")
	if signIdx < 0 {
		return fmt.Errorf("CORRECT-102: selection-aware mint no longer calls d.issueEndpointCSR (the platform/private/external CA routing seam); re-point this guard")
	}
	if enforceIdx >= signIdx {
		return fmt.Errorf("CORRECT-102: profile validation (enforceProfile @%d) no longer precedes CA routing (issueEndpointCSR @%d); the served path can now sign before validating the profile (fail-open regression)", enforceIdx, signIdx)
	}
	return nil
}

func TestProtectCORRECT102_AcceptAllIsTestOnly(t *testing.T) {
	root := moduleRoot(t)
	const needle = "AcceptAll"
	var offenders []string
	seenInTest := false

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "node_modules" || name == "web" || name == "vendor" {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		b, rerr := os.ReadFile(path) // #nosec G122 G304 -- test reads its own fixture/tempdir path (CWE-22, CWE-367)
		if rerr != nil {
			return rerr
		}
		if !strings.Contains(string(b), needle) {
			return nil
		}
		if strings.HasSuffix(path, "_test.go") {
			seenInTest = true
			return nil
		}
		// A non-test Go file references AcceptAll: that is exactly the production-path
		// regression this guard exists to catch. (This guard file is itself a _test.go,
		// so its own mention of the needle does not count.)
		offenders = append(offenders, path)
		return nil
	})
	if err != nil {
		t.Fatalf("CORRECT-102: walking module for AcceptAll references failed: %v", err)
	}

	if len(offenders) > 0 {
		t.Fatalf("CORRECT-102: AcceptAll (accept-every-challenge validator) is referenced from non-test file(s) %v; it must remain test-only and never on a production issuance path", offenders)
	}
	if !seenInTest {
		t.Fatalf("CORRECT-102: AcceptAll was not found in any _test.go file; the test-only challenge validator the strength describes is missing — re-validate the anchor")
	}
}

// moduleRoot walks upward from the package dir to the directory holding go.mod, so the
// AcceptAll walk covers the whole module regardless of where `go test` is invoked.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("CORRECT-102: getwd: %v", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("CORRECT-102: could not locate go.mod above %s", dir)
		}
		dir = parent
	}
}

// INTEROP-003 (18-INTEROP) PROTECT regression guard.
//
// Confirmed strength: the served protocol mounts (ACME/EST/SCEP/CMP/TSA/SSH/SPIFFE)
// are each gated on per-protocol ENABLEMENT, and the whole served-protocol surface
// FAILS CLOSED when the issuing CA / signer is absent — protocols are then simply not
// served rather than backed by an in-process key. Anchor:
// internal/server/protocol_mounts.go (buildServedProtocols).
//
// This is an ANCHOR-LOCK over the real source (constructing the protocol surface
// requires a real signer child + CA, which is exactly the heavyweight setup this guard
// must avoid). It asserts (1) the early fail-closed return when no signer/CA, BEFORE
// any protocol is assembled, and (2) every protocol is mounted only inside an
// `if cfg.<Proto>.Enabled` block. If a future edit serves a protocol unconditionally,
// or drops the no-signer fail-closed guard, this guard goes RED.
func TestProtectINTEROP003_ProtocolMountsGatedAndFailClosed(t *testing.T) {
	src, err := os.ReadFile("protocol_mounts.go")
	if err != nil {
		t.Fatalf("INTEROP-003 anchor: cannot read protocol_mounts.go: %v", err)
	}
	body := string(src)

	// (1) Fail closed when no issuing CA / signer is provisioned, and this guard must
	// come BEFORE any protocol server is built.
	failClosed := "if s.caSigner == nil || len(s.caCertDER) == 0 {"
	failIdx := strings.Index(body, failClosed)
	if failIdx < 0 {
		t.Fatalf("INTEROP-003: protocol_mounts.go no longer fails closed when the signer/CA is absent (missing %q); protocols could be served without an out-of-process signer", failClosed)
	}
	// The early return must hand back (nil, nil) — no protocols, no error.
	tail := body[failIdx:]
	retIdx := strings.Index(tail, "return nil, nil")
	firstEnableIdx := strings.Index(tail, "Enabled {")
	if retIdx < 0 {
		t.Fatalf("INTEROP-003: the no-signer branch no longer returns (nil, nil); the fail-closed contract is broken")
	}
	if firstEnableIdx >= 0 && retIdx >= firstEnableIdx {
		t.Errorf("INTEROP-003: the no-signer fail-closed return (@%d) no longer precedes the first protocol enablement gate (@%d); a protocol could be assembled without a signer", retIdx, firstEnableIdx)
	}

	// (2) Each protocol is mounted only when its own enablement flag is set.
	for _, gate := range []string{
		"if cfg.ACME.Enabled {",
		"if cfg.EST.Enabled {",
		"if cfg.SCEP.Enabled {",
		"if cfg.CMP.Enabled {",
		"if cfg.SSH.Enabled {",
		"if cfg.TSA.Enabled {",
		"cfg.SPIFFE.Enabled", // SPIFFE additionally requires a non-empty trust domain
	} {
		if !strings.Contains(body, gate) {
			t.Errorf("INTEROP-003: protocol_mounts.go no longer gates a mount on %q; a served protocol may now mount unconditionally", gate)
		}
	}

	// SPIFFE must also require a configured trust domain (it is a gRPC UDS service);
	// lock that the gate is the conjunction, not just the enable flag.
	if !strings.Contains(body, `cfg.SPIFFE.Enabled && cfg.SPIFFE.TrustDomain != ""`) {
		t.Error("INTEROP-003: the SPIFFE mount no longer requires both Enabled AND a non-empty TrustDomain; it could mount without a trust domain")
	}
}
