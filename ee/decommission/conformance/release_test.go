// SPDX-License-Identifier: LicenseRef-trstctl-EE

package conformance

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

var vdecPackageDirs = []string{"ee/decommission"}

func TestEdition_CoreBuildLinksNoVDEC(t *testing.T) {
	goBin := filepath.Join(goRoot(t), "bin", "go")
	cmd := exec.Command(goBin, "list", "-tags", "trstctl_core", "-deps", "trstctl.com/trstctl/cmd/trstctl")
	cmd.Dir = moduleRoot(t)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list (core build graph): %v\n%s", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "trstctl.com/trstctl/ee/") {
			t.Fatalf("core-only build links an ee/ package: %q", line)
		}
	}
}

func TestEdition_AllVDECPackagesAreEE(t *testing.T) {
	root := moduleRoot(t)
	for _, d := range vdecPackageDirs {
		if !strings.HasPrefix(d, "ee/") {
			t.Fatalf("VDEC package tree %q is not under ee/", d)
		}
		err := filepath.WalkDir(filepath.Join(root, d), func(path string, de os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if de.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if !hasLicenseRefSPDXBeforePackage(string(b)) {
				t.Fatalf("VDEC file %s: missing LicenseRef-trstctl-EE SPDX header before package declaration", path)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", d, err)
		}
	}

	allowedAttach := map[string]bool{
		filepath.Join(root, "cmd/trstctl/ee_attach.go"):        true,
		filepath.Join(root, "cmd/trstctl-signer/ee_attach.go"): true,
	}
	err := filepath.WalkDir(root, func(path string, de os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if de.IsDir() {
			switch de.Name() {
			case ".git", "ee", "vendor", "web", "bin":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(b), "trstctl.com/trstctl/ee/decommission") && !allowedAttach[path] {
			t.Fatalf("MPL/core file %s imports VDEC directly outside tagged attach seam", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk core tree: %v", err)
	}
}

func TestZeroRemoval_BasicKeyDestructionIntact(t *testing.T) {
	root := moduleRoot(t)
	required := map[string][]string{
		"internal/crypto/secret/buffer.go": {
			"func (b *Buffer) Destroy()",
			"func Wipe(b []byte)",
			"runtime.KeepAlive(b)",
		},
		"internal/rotation/rotation.go": {
			"Retire(ctx context.Context, key, oldRef string) error",
		},
		"internal/rotation/rotators.go": {
			"func (r *BackendRotator) Retire",
			"secret.Wipe(",
		},
		"internal/lifecycle/lifecycle.go": {
			"func (m *Manager) Revoke(",
			"func (m *Manager) Rotate(",
		},
	}
	for rel, needles := range required {
		path := filepath.Join(root, rel)
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read zero-removal file %s: %v", rel, err)
		}
		text := string(b)
		if strings.Contains(text, "trstctl.com/trstctl/ee/decommission") ||
			strings.Contains(text, "FeatureVerifiableDecommission") ||
			strings.Contains(text, "lic.Has(") {
			t.Fatalf("free zero-removal substrate %s is gated or imports VDEC", rel)
		}
		for _, needle := range needles {
			if !strings.Contains(text, needle) {
				t.Fatalf("free zero-removal substrate %s no longer contains %q", rel, needle)
			}
		}
	}
}

func TestConformance_PublishedDestructionRecordVectors(t *testing.T) {
	if os.Getenv("UPDATE_VDEC_VECTORS") == "1" {
		writeVector(t)
	}
	for _, v := range loadVectors(t) {
		if v.Version != 1 || v.Vector.Version != 1 || v.Vector.Domain == "" || v.Vector.Name == "" {
			t.Fatalf("vector metadata = %+v, want versioned named destruction-record vector", v.Vector)
		}
		rec, err := decodePublishedRecord(v)
		if err != nil {
			t.Fatalf("%s: decode published record: %v", v.Vector.Name, err)
		}
		if got, want := sha(v.Vector.EncodedRecord), v.Vector.EncodedRecordDigest; !same(got, want) {
			t.Fatalf("%s: encoded record digest %x, want %x", v.Vector.Name, got, want)
		}
		if got, err := differentialCommitmentDigest(rec); err != nil {
			t.Fatalf("%s: differential commitment digest: %v", v.Vector.Name, err)
		} else if !same(got, rec.CommitmentDigest) {
			t.Fatalf("%s: differential commitment digest %x != record %x", v.Vector.Name, got, rec.CommitmentDigest)
		}
		if err := verifyVector(v); err != nil {
			t.Fatalf("%s: verify vector: %v", v.Vector.Name, err)
		}

		tampered := v.Request
		tampered.Record.Signature = append([]byte{0}, tampered.Record.Signature...)
		if _, err := verifyRequest(tampered); err == nil {
			t.Fatalf("%s: tampered signature verified", v.Vector.Name)
		}
	}
}

func TestConformance_GoWASMVerifierParity(t *testing.T) {
	for _, v := range loadVectors(t) {
		goVerdict, err := verifyRequest(v.Request)
		if err != nil {
			t.Fatalf("%s: Go verifier rejected vector: %v", v.Vector.Name, err)
		}
		wasmVerdict, err := wasmVerifyRequest(v.Request)
		if err != nil {
			t.Fatalf("%s: WASM verifier rejected vector: %v", v.Vector.Name, err)
		}
		if !reflect.DeepEqual(goVerdict, wasmVerdict) {
			t.Fatalf("%s: Go/WASM verdict mismatch:\nGo:   %+v\nWASM: %+v", v.Vector.Name, goVerdict, wasmVerdict)
		}
	}
}

func TestConformance_FuzzSeedCorpusPresent(t *testing.T) {
	root := moduleRoot(t)
	for _, corpus := range []string{
		"ee/decommission/conformance/testdata/fuzz/FuzzVDECRecordDecode/empty",
		"ee/decommission/conformance/testdata/fuzz/FuzzVDECRecordDecode/not_json",
		"ee/decommission/conformance/testdata/fuzz/FuzzVDECVerifyRequestJSON/empty_object",
		"ee/decommission/conformance/testdata/fuzz/FuzzVDECDepstateEventDecode/registered",
	} {
		if st, err := os.Stat(filepath.Join(root, corpus)); err != nil || st.Size() == 0 {
			t.Fatalf("missing committed VDEC fuzz seed corpus %s: size=%d err=%v", corpus, sizeOf(st), err)
		}
	}
	tests := mustReadAllGoTests(t, filepath.Join(root, "ee/decommission/conformance"))
	for _, fn := range []string{"FuzzVDECRecordDecode", "FuzzVDECVerifyRequestJSON", "FuzzVDECDepstateEventDecode"} {
		if !regexp.MustCompile(`func\s+` + fn + `\s*\(`).MatchString(tests) {
			t.Fatalf("missing VDEC fuzz target %s", fn)
		}
	}
}

func TestConformance_TraceabilityMatrixAllClaimsProven(t *testing.T) {
	// VDEC-TRACE-001. This assertion used to read a hand-edited manifest that said
	// every claim was "proven" -- the artifact deciding the question was the artifact
	// a human edited, so the test was true by construction and carried no information
	// about the code. Worse, it preferred an out-of-repo TRACEABILITY-MATRIX.md when
	// one existed, so it silently changed oracles between a developer machine and CI.
	//
	// It now cross-checks against ee/docs/claim-traceability.md, which is GENERATED
	// from the VDEC-claim-N citations in ee/ source and kept byte-fresh by
	// `make claim-traceability-check`. A claim counts as proven only when the
	// generated table carries a row for it with both an implementation and a test.
	root := moduleRoot(t)
	table, err := os.ReadFile(filepath.Join(root, "ee/docs/claim-traceability.md"))
	if err != nil {
		t.Fatalf("VDEC-TRACE-001: generated claim-traceability table unreadable: %v", err)
	}

	section := ""
	for _, part := range strings.Split(string(table), "\n## ") {
		if strings.HasPrefix(part, "VDEC") {
			section = part
			break
		}
	}
	if section == "" {
		t.Fatal("VDEC-TRACE-001: the generated table has no VDEC section; either the family lost every citation or the table format changed")
	}

	// Columns may carry SEVERAL comma-separated paths, so match the cells rather
	// than assuming one backticked path each. A claim counts as proven only when the
	// implementation cell AND the test cell each name at least one file.
	row := regexp.MustCompile(`(?m)^\| ([0-9]+) \| ([^|]*) \| ([^|]*) \|`)
	hasPath := regexp.MustCompile("`[^`]+`")
	proven := map[string]bool{}
	for _, mm := range row.FindAllStringSubmatch(section, -1) {
		if hasPath.MatchString(mm[2]) && hasPath.MatchString(mm[3]) {
			proven[mm[1]] = true
		}
	}

	var missing []string
	for _, claim := range claimIDs() {
		if !proven[claim] {
			missing = append(missing, claim)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("VDEC-TRACE-001: %d VDEC claim(s) have no generated row carrying BOTH an implementation and a test: %s. "+
			"Cite them from the ee/ code that practises them and regenerate with make claim-traceability-check -- "+
			"do not record them as proven by hand.", len(missing), strings.Join(missing, ", "))
	}
}

func TestConformance_AllInvariantGuardsPresent(t *testing.T) {
	if got := len(canonicalInvariantTests()); got != canonicalInvariantTestCount {
		t.Fatalf("canonical invariant guard list has %d entries, want %d: this list is a ratchet and must not shrink", got, canonicalInvariantTestCount)
	}
	root := moduleRoot(t)
	tests := mustReadAllGoTests(t, filepath.Join(root, "ee/decommission"))
	tests += mustReadAllGoTests(t, filepath.Join(root, "internal/signing"))
	for _, name := range canonicalInvariantTests() {
		if !regexp.MustCompile(`func\s+` + regexp.QuoteMeta(name) + `\s*\(`).MatchString(tests) {
			t.Fatalf("missing canonical invariant guard test %s", name)
		}
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the test working directory")
		}
		dir = parent
	}
}

func hasLicenseRefSPDXBeforePackage(s string) bool {
	for _, line := range strings.Split(s, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "package ") {
			return false
		}
		if trimmed == "// SPDX-License-Identifier: LicenseRef-trstctl-EE" {
			return true
		}
	}
	return false
}

func sizeOf(st os.FileInfo) int64 {
	if st == nil {
		return 0
	}
	return st.Size()
}

func mustReadAllGoTests(t *testing.T, root string) string {
	t.Helper()
	var b strings.Builder
	err := filepath.WalkDir(root, func(path string, de os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if de.IsDir() || !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		b.Write(raw)
		b.WriteByte('\n')
		return nil
	})
	if err != nil {
		t.Fatalf("read tests under %s: %v", root, err)
	}
	return b.String()
}

func claimIDs() []string {
	out := make([]string, 0, 24)
	for i := 1; i <= 24; i++ {
		out = append(out, strconvItoa(i))
	}
	return out
}

func strconvItoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// canonicalInvariantTestCount is a ratchet on canonicalInvariantTests: the list of
// canonical VDEC invariant guards may grow but must never shrink, so a guard cannot
// be quietly dropped while the release gate still reports green.
const canonicalInvariantTestCount = 41

func canonicalInvariantTests() []string {
	return []string{
		"TestGate_RefusesDestroyUntilAllDependentsReprotected",
		"TestGate_SetDifferenceEmptyRequired",
		"TestGate_VerifyBeforeDestroyOrdering",
		"TestDepState_AssociatesAllDependentClasses",
		"TestDepState_DeterministicReplayProjection",
		"TestDepState_ReprotectionJobsGeneratedFromState",
		"TestDepState_UnaccountedDependentBlocksDestroy",
		"TestReprotect_ReencryptInCryptoBoundaryNoKeyBytes",
		"TestReprotect_PlaintextZeroizedAfter",
		"TestReprotect_IdempotentAtMostOneCompletion",
		"TestReprotect_StagedCutoverHealthRollback",
		"TestReprotect_CredentialReissueSupersession",
		"TestReprotect_LeasedCredentialRevocationResumes",
		"TestRevokeFirst_FailClosedPermitsReprotectDecrypt",
		"TestRevokeFirst_IntentsSameTxnAsStateChange",
		"TestRevokeFirst_PerDestinationCompletionRequired",
		"TestDestroy_ZeroizeLockedBuffers",
		"TestDestroy_HSMDestroyReturnsAttestation",
		"TestDestroy_HSMTerminalEpochRefusesAtOrBelow",
		"TestDestroy_AttestationClassMinGate",
		"TestRecord_CommitmentBindsClaim1Fields",
		"TestRecord_MintedInsideSignerWithAttestationKey",
		"TestRecord_ControlPlaneHoldsNoAttestationKey",
		"TestRecord_BindsSuccessorAndAuditHead",
		"TestRecord_CanonicalEncodingStable",
		"TestVerify_OfflineFromRecordAndKeys",
		"TestVerify_InclusionProofAgainstLogHead",
		"TestVerify_FinalEpochNotBelowLastAccepted",
		"TestVerify_SuccessionChainCorrespondence",
		"TestVerify_RecomputeCompletionDigest",
		"TestAggregate_TenantScopeRecordOfflineVerifiable",
		"TestCampaign_KeyedToSuccessionEpoch",
		"TestErasure_SanitizationClaimBound",
		"TestRefusal_SignedArtifactNamesUnaccountedDependent",
		"TestQuorum_RequiredAndBound",
		"TestCeremony_BundleVerifiedAndReplayed",
		"TestCeremony_FailedBundleRejectedNotReplayed",
		"TestCountersign_DistinctAuthorityDoesNotAlterRecord",
		"TestEdition_CoreBuildLinksNoVDEC",
		"TestEdition_AllVDECPackagesAreEE",
		"TestZeroRemoval_BasicKeyDestructionIntact",
	}
}

// goRoot returns the toolchain's GOROOT by asking the go command rather than
// reading runtime.GOROOT(), which is deprecated since Go 1.24: it reports the
// root used at BUILD time, which is meaningless once a test binary is copied to
// another machine.
//
// It FAILS rather than skips when the toolchain cannot be located. This is a
// conformance gate (pcas-no-skip-gate / vdec equivalent enforce exactly this): a
// skipped edition check reports green while proving nothing about the boundary
// it exists to police.
func goRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "env", "GOROOT").Output() // #nosec G204 -- fixed argv, no user input (CWE-78)
	if err != nil {
		t.Fatalf("go env GOROOT: %v", err)
	}
	root := strings.TrimSpace(string(out))
	if root == "" {
		t.Fatal("go env GOROOT is empty")
	}
	return root
}
