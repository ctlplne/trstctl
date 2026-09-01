// SPDX-License-Identifier: MPL-2.0

package crypto_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// fuzzFuncNameRE matches a Go fuzz target declaration and captures its name, so
// the guard can require specific decoders to stay fuzzed (not just "some target
// in this dir").
var fuzzFuncNameRE = regexp.MustCompile(`(?m)^func (Fuzz\w+)\(`)

// TestEveryUntrustedParserIsFuzzed makes TEST-FUZZASSERT-001 ("fuzz every parser that
// touches untrusted input") executable: it enumerates the packages that parse
// attacker-controlled bytes and fails if any lacks at least one Go fuzz target.
// It was RED before R4.3 (ctlog, certinfo, sshkeys, and the CSR parser here had
// none) and is GREEN after. A new untrusted parser added without a fuzz target
// trips this guard.
//
// Paths are relative to this package directory (internal/crypto), which is the
// test's working directory.
func TestEveryUntrustedParserIsFuzzed(t *testing.T) {
	// TEST-FUZZASSERT-001: discover untrusted-input parser ENTRY POINTS by AST
	// rather than a hand-maintained list, so a newly-added parser cannot dodge
	// the denominator. The walker finds every exported function across the
	// security-boundary package roots whose first parameter is a raw []byte and
	// whose name begins with a parse/decode verb — the shape of "turn
	// attacker-controlled bytes into structure". Each such parser's package must
	// carry a Go fuzz target.
	roots := []string{".", "../protocols", "../tsa", "../signing", "../secretscan", "../attest", "../../ee/kmip"}
	discovered := discoverUntrustedParsers(t, roots)

	// The walker must not silently regress to finding nothing: pin a few
	// entry points it MUST always surface.
	for _, sentinel := range []string{"Inspect", "ParseSCEPRequest", "ParseTTLV", "ParseOrderRequest"} {
		if _, ok := discovered[sentinel]; !ok {
			t.Fatalf("AST parser discovery did not surface the sentinel entry point %q — the walker is broken or the boundary roots changed", sentinel)
		}
	}

	// Every discovered parser's package must have a fuzz target.
	for fn, dir := range discovered {
		if !dirHasFuzzTarget(t, dir) {
			t.Errorf("untrusted parser %s (in %s) has no Go fuzz target — TEST-FUZZASSERT-001 requires every parser that touches untrusted input to be fuzzed", fn, dir)
		}
	}

	// A few boundary parsers take io.Reader / a protobuf message / a string
	// rather than a leading []byte, so the []byte-first heuristic above cannot
	// classify them. Pin their packages explicitly so their coverage cannot be
	// lost (est enroll body reads an io.Reader; the signer parses a protobuf
	// SignRequest; ARI CertID parses a string path segment).
	for dir, what := range map[string]string{
		"../protocols/est": "EST enroll body (io.Reader → base64 PKCS#10)",
		"../protocols/ari": "ARI CertID (string path segment)",
		"../signing":       "signer SignRequest (protobuf)",
	} {
		if !dirHasFuzzTarget(t, dir) {
			t.Errorf("untrusted parser package %s (%s) has no Go fuzz target (non-[]byte signature, pinned explicitly)", dir, what)
		}
	}

	// The "some fuzz target lives in this dir" check above is too coarse for the
	// CMS/PKCS7 decoder family: a single SCEP-request target satisfied it while
	// the sibling decoders that share the same (panic-prone) smallstep/pkcs7
	// BER decoder — and that parse UNTRUSTED bytes before any verification —
	// were left unfuzzed (FUZZ-001/002). Require those CMS boundary targets by
	// NAME so dropping one trips this guard, not just deleting the whole file.
	requireFuzzFuncByName(t, ".", map[string]string{
		"FuzzParsePublicKeyPEM":  "exact single public-key PEM used by broker and workload issuance (verify.go)",
		"FuzzParseSCEPRequest":   "SCEP pkiMessage CMS (scep.go ParseSCEPRequest)",
		"FuzzParseSCEPResponse":  "SCEP CertRep CMS (scep.go ParseSCEPResponse) — shares the FUZZ-001 decoder",
		"FuzzVerifyCMSSignature": "cloud IID CMS (verify.go VerifyCMSSignature) — parses untrusted bytes pre-verification",
		// CMP (RFC 4210) PKIMessage parsing is another untrusted-ASN.1 boundary
		// (cmp.go ParseCMPRequest) that shares the CMS/PKCS7 decoder family. Pin it by
		// name so the SCEP/CMP/EST denominator the guard claims to police is complete
		// and dropping the CMP harness trips this guard (FUZZ-004).
		"FuzzParseCMPRequest":        "CMP PKIMessage (cmp.go ParseCMPRequest) — untrusted ASN.1 enrollment envelope",
		"FuzzParseOCSPRequestSerial": "served RFC 6960 OCSP request DER (revocation.go ParseOCSPRequestSerial)",
		// crypto.InspectCSR (csr.go) is the profile-validation CSR-inspection seam and
		// runs its own EKU extension ASN.1 decode (eku.go); certinfo.Inspect being
		// fuzzed (FuzzInspect) did not cover it. Pin FuzzInspectCSR by name so the
		// CSR-inspection + EKU-decode boundary stays fuzzed and dropping its harness
		// trips this guard (FUZZ-002).
		"FuzzInspectCSR": "profile-validation CSR inspection + EKU ASN.1 decode (csr.go InspectCSR, eku.go)",
	})
	requireFuzzFuncByName(t, "deviceattest", map[string]string{
		"FuzzParseAndVerifyTPMDeviceAttestation": "ACME device-attest-01 WebAuthn/CBOR/COSE/TPM envelope (deviceattest/tpm.go)",
	})

	// The cloud instance-identity attesters parse the same untrusted CMS family at
	// their pre-verification entry point (Attest). VerifyCMSSignature is fuzzed at
	// the boundary above; require the end-to-end attester harnesses too so the JSON
	// document decode + selector extraction that runs on a verified-but-attacker-
	// shaped document is covered, and so dropping one attester's harness trips this
	// guard (FUZZ-002).
	requireFuzzFuncByName(t, "../attest/awsiid", map[string]string{
		"FuzzAWSIIDAttest": "AWS IID attester Attest (awsiid.go) — untrusted CMS document pre-verification",
	})
	requireFuzzFuncByName(t, "../attest/azureimds", map[string]string{
		"FuzzAzureIMDSAttest": "Azure IMDS attester Attest (azureimds.go) — untrusted CMS document pre-verification",
	})
	requireFuzzFuncByName(t, "../../ee/kmip", map[string]string{
		"FuzzParseTTLV": "KMIP TTLV wire frame decoder (kmip ttlv.go) — enterprise key-management client bytes",
	})

	// The binary sealed-blob decoder (seal.Open) parses an at-rest/backup container —
	// magic, version dispatch, the 2-byte wrappedLen, and stored-byte slices — before
	// any AEAD verification (FUZZ-001). Pin FuzzOpenSeal by name so the container
	// decode stays fuzzed and dropping its harness trips this guard.
	requireFuzzFuncByName(t, "seal", map[string]string{
		"FuzzOpenSeal": "binary seal container decode (seal.go Open) — at-rest/backup bytes, pre-AEAD",
	})
	requireFuzzFuncByName(t, "tenantwrap", map[string]string{
		"FuzzParseWrappedDomainKEK": "tenant-domain wrapped-KEK container (tenantwrap.go parseWrappedDomainKEK) — persisted/event bytes, pre-AEAD",
	})

	// The served RFC 3161 timestamp endpoint accepts attacker-controlled DER
	// TimeStampReq bytes at /tsa before minting a TimeStampResp. Pin the exact
	// parser harness so a future unrelated TSA fuzz target cannot accidentally
	// satisfy the denominator guard.
	requireFuzzFuncByName(t, "../tsa", map[string]string{
		"FuzzParseTimeStampReq": "served RFC 3161 TimeStampReq DER (http.go parseTimeStampReq)",
	})

	// The non-CMS instance/workload attesters each parse an UNTRUSTED token/envelope
	// at their Attest entry point before trust is established (FUZZ-003): the GCP/
	// GitHub/k8s attesters take an attacker-supplied JWT and JSON-decode its claims,
	// and the TPM attester JSON-decodes a quote envelope. Pin each harness by name so
	// the JWT/JSON parse + selector extraction stays fuzzed and dropping any one trips
	// this guard.
	requireFuzzFuncByName(t, "../attest/gcpmeta", map[string]string{
		"FuzzGCPMetaAttest": "GCP IIT attester Attest (gcpmeta.go) — untrusted JWT + JSON claims",
	})
	requireFuzzFuncByName(t, "../attest/githuboidc", map[string]string{
		"FuzzGitHubOIDCAttest": "GitHub Actions OIDC attester Attest (githuboidc.go) — untrusted JWT + JSON claims",
	})
	requireFuzzFuncByName(t, "../attest/k8ssat", map[string]string{
		"FuzzK8sSATAttest": "Kubernetes projected SAT attester Attest (k8ssat.go) — untrusted JWT + JSON claims",
	})
	requireFuzzFuncByName(t, "../attest/tpmquote", map[string]string{
		"FuzzTPMQuoteAttest": "TPM 2.0 quote attester Attest (tpmquote.go) — untrusted JSON quote envelope",
	})
}

// requireFuzzFuncByName fails if any of the named Fuzz targets is missing from
// the *_test.go files in dir. It pins the exact untrusted decoders that must
// stay fuzzed (TEST-FUZZASSERT-001), closing the false-"all parsers fuzzed" assurance a
// directory-level check gives when one decoder in a multi-decoder package loses
// its harness.
func requireFuzzFuncByName(t *testing.T, dir string, want map[string]string) {
	t.Helper()
	found := fuzzTargetNamesForPackage(t, dir)
	for name, what := range want {
		if !found[name] {
			t.Errorf("required fuzz target %s (%s) is missing — FUZZ-001/002 require it; do not remove it", name, what)
		}
	}
}

// untrustedParseVerbs prefixes the name of a function that turns
// attacker-controlled bytes into structure.
var untrustedParseVerbs = []string{"Parse", "Inspect", "Decode", "Open", "Unmarshal"}

// discoverUntrustedParsers AST-walks the given boundary roots and returns every
// exported function whose first parameter is a raw []byte and whose name begins
// with a parse/decode verb, mapped to the directory it lives in. This is the
// executable denominator for "fuzz every untrusted parser": a newly-added
// []byte parser is discovered automatically, so it cannot dodge the guard
// (TEST-FUZZASSERT-001).
func discoverUntrustedParsers(t *testing.T, roots []string) map[string]string {
	t.Helper()
	found := map[string]string{}
	firstParamIsByteSlice := func(fn *ast.FuncDecl) bool {
		if fn.Type.Params == nil || len(fn.Type.Params.List) == 0 {
			return false
		}
		at, ok := fn.Type.Params.List[0].Type.(*ast.ArrayType)
		if !ok || at.Len != nil {
			return false
		}
		id, ok := at.Elt.(*ast.Ident)
		return ok && id.Name == "byte"
	}
	for _, root := range roots {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			file, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return nil // unparseable file is not a parser entry point
			}
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Recv != nil || !fn.Name.IsExported() {
					continue
				}
				verbMatched := false
				for _, v := range untrustedParseVerbs {
					if strings.HasPrefix(fn.Name.Name, v) {
						verbMatched = true
						break
					}
				}
				if verbMatched && firstParamIsByteSlice(fn) {
					found[fn.Name.Name] = filepath.Dir(path)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk boundary root %q: %v", root, err)
		}
	}
	if len(found) == 0 {
		t.Fatal("AST parser discovery found no untrusted parsers — the walker or the boundary roots are broken")
	}
	return found
}

func dirHasFuzzTarget(t *testing.T, dir string) bool {
	t.Helper()
	return len(fuzzTargetNamesForPackage(t, dir)) != 0
}

// fuzzTargetNamesForPackage includes native targets beside the parser and an
// isolated ClusterFuzz bridge only when that bridge imports the exact source
// package. The stock OSS-Fuzz helper cannot compile an external `package x_test`
// target in a mixed test directory, but moving the entrypoint must not let the
// parser denominator degrade into a repository-wide "some fuzzer exists" check.
func fuzzTargetNamesForPackage(t *testing.T, dir string) map[string]bool {
	t.Helper()
	found := map[string]bool{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read parser dir %q: %v", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name())) // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		for _, match := range fuzzFuncNameRE.FindAllStringSubmatch(string(b), -1) {
			found[match[1]] = true
		}
	}

	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	parserDir, err := filepath.Abs(dir)
	if err != nil {
		t.Fatalf("resolve parser dir %q: %v", dir, err)
	}
	rel, err := filepath.Rel(repoRoot, parserDir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		t.Fatalf("parser dir %q is outside repository root %q", parserDir, repoRoot)
	}
	parserImport := `"trstctl.com/trstctl/` + filepath.ToSlash(rel) + `"`
	for _, bridgeRoot := range []string{"clusterfuzz", "../clusterfuzz", "../../ee/clusterfuzz"} {
		err := filepath.Walk(bridgeRoot, func(path string, info os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if info.IsDir() || !strings.HasSuffix(path, "_test.go") {
				return nil
			}
			body, readErr := os.ReadFile(path) // #nosec G304,G122 -- test walks repository-owned bridge fixtures (CWE-22, CWE-367)
			if readErr != nil {
				return readErr
			}
			if !strings.Contains(string(body), parserImport) {
				return nil
			}
			for _, match := range fuzzFuncNameRE.FindAllStringSubmatch(string(body), -1) {
				found[match[1]] = true
			}
			return nil
		})
		if err != nil && !os.IsNotExist(err) {
			t.Fatalf("walk ClusterFuzz bridge root %q: %v", bridgeRoot, err)
		}
	}
	return found
}
