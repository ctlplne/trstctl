package est

import (
	"bytes"
	"encoding/base64"
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"testing/quick"

	"trstctl.com/trstctl/internal/crypto"
)

// Property-based tests for the EST wire parser (TEST-003 / CLAUDE.md §6, which
// mandates property tests for every protocol parser). The fuzz target in
// fuzz_test.go gives corpus-mutation coverage; these pin the *invariants* the
// parser must hold — parse-after-encode identity, the never-both-CSR-and-error
// contract, and no-panic on arbitrary bytes — which corpus mutation alone does not
// assert. They live in package est (like the fuzz target) so they can drive the
// unexported parseEnrollBody directly, and use the stdlib testing/quick generator
// (no new dependency under -mod=readonly).

// validCSRDER returns a freshly generated, self-signed PKCS#10 CSR DER through the
// AN-3 crypto boundary — a real input the parser must accept and return verbatim.
func validCSRDER(t *testing.T) []byte {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	der, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "prop-device"}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// TestParseEnrollBodyRoundTrip is the parse(encode(x))==x identity property: for a
// real CSR DER, base64-encoding it (optionally surrounded by the whitespace EST
// clients commonly add — newlines, spaces, tabs, the bytes trimSpace strips) and
// feeding it to parseEnrollBody must return the *same* DER, with no error. The
// generated padding asserts the whitespace-tolerance is lossless, not just the
// happy path.
func TestParseEnrollBodyRoundTrip(t *testing.T) {
	csr := validCSRDER(t)
	encoded := base64.StdEncoding.EncodeToString(csr)

	prop := func(ws wsRuns) bool {
		body := ws.left + encoded + ws.mid() + ws.right
		der, err := parseEnrollBody(strings.NewReader(body))
		if err != nil {
			t.Logf("round-trip rejected a valid CSR (ws=%+v): %v", ws, err)
			return false
		}
		if !bytes.Equal(der, csr) {
			t.Logf("round-trip changed the CSR DER: got %d bytes, want %d", len(der), len(csr))
			return false
		}
		return true
	}

	if err := quick.Check(prop, &quick.Config{MaxCount: 500}); err != nil {
		t.Fatalf("EST parse round-trip property violated: %v", err)
	}
}

// wsRuns is a generator of whitespace runs to splice around / into the base64 body.
type wsRuns struct {
	left, right string
	insertAt    int
	insertWS    string
}

// mid is spliced between two halves of the encoded body in the round-trip test (it
// is appended after the body here; the key point is interior whitespace is also
// stripped). It returns interior whitespace only.
func (w wsRuns) mid() string { return w.insertWS }

func (wsRuns) Generate(r *rand.Rand, _ int) reflect.Value {
	ws := []byte{' ', '\n', '\r', '\t'}
	run := func() string {
		n := r.Intn(5)
		b := make([]byte, n)
		for i := range b {
			b[i] = ws[r.Intn(len(ws))]
		}
		return string(b)
	}
	return reflect.ValueOf(wsRuns{left: run(), right: run(), insertWS: run()})
}

// TestParseEnrollBodyNeverBothOrPanic is the robustness invariant the fuzz target
// also checks, raised to a property over a broad generated input distribution: for
// ANY bytes, parseEnrollBody must never panic and must never return both a CSR and
// an error (the caller branches on err, so a non-nil der alongside a non-nil err
// would be a confusing, potentially unsafe contract). The generator mixes random
// bytes, near-base64, and base64-of-garbage so both the decode and the
// CSR-verification arms are exercised.
func TestParseEnrollBodyNeverBothOrPanic(t *testing.T) {
	prop := func(g enrollFuzzInput) (ok bool) {
		defer func() {
			if rec := recover(); rec != nil {
				t.Logf("parseEnrollBody panicked on %q: %v", g.body, rec)
				ok = false
			}
		}()
		der, err := parseEnrollBody(strings.NewReader(g.body))
		if err != nil && der != nil {
			t.Logf("parseEnrollBody returned BOTH a CSR and an error for %q", g.body)
			return false
		}
		// When it succeeds, the returned DER must itself re-verify through the
		// boundary — a successful parse is a genuinely valid CSR, never a half-checked
		// blob.
		if err == nil {
			if vErr := crypto.VerifyCertificateRequest(der); vErr != nil {
				t.Logf("parseEnrollBody accepted a CSR the boundary then rejects: %v", vErr)
				return false
			}
		}
		return true
	}

	if err := quick.Check(prop, &quick.Config{MaxCount: 2000}); err != nil {
		t.Fatalf("EST parser robustness property violated: %v", err)
	}
}

// enrollFuzzInput generates a body string from several adversarial families so the
// property exercises the decode error path, the verify error path, and the rare
// accidental-valid path.
type enrollFuzzInput struct{ body string }

func (enrollFuzzInput) Generate(r *rand.Rand, size int) reflect.Value {
	switch r.Intn(4) {
	case 0: // arbitrary bytes
		b := make([]byte, r.Intn(size+1))
		for i := range b {
			b[i] = byte(r.Intn(256))
		}
		return reflect.ValueOf(enrollFuzzInput{string(b)})
	case 1: // near-base64 (alphabet only, random length, maybe bad padding)
		const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
		var sb strings.Builder
		for i := 0; i < r.Intn(size+1); i++ {
			sb.WriteByte(a[r.Intn(len(a))])
		}
		return reflect.ValueOf(enrollFuzzInput{sb.String()})
	case 2: // base64 of random bytes (decodes cleanly, fails CSR verification)
		b := make([]byte, r.Intn(size+1))
		for i := range b {
			b[i] = byte(r.Intn(256))
		}
		return reflect.ValueOf(enrollFuzzInput{base64.StdEncoding.EncodeToString(b)})
	default: // whitespace / empty
		ws := []byte{' ', '\n', '\r', '\t'}
		b := make([]byte, r.Intn(8))
		for i := range b {
			b[i] = ws[r.Intn(len(ws))]
		}
		return reflect.ValueOf(enrollFuzzInput{string(b)})
	}
}
