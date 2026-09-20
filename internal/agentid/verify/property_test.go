// SPDX-License-Identifier: BUSL-1.1

package verify

import (
	"errors"
	"testing"
	"trstctl.com/trstctl/internal/proptest"

	"trstctl.com/trstctl/internal/crypto"
)

// property_test.go asserts structural PROPERTIES of the offline verifier that must
// hold across randomized inputs (AGID-09 property-test requirement):
//
//   P1 tool-manifest digest is order- and duplicate-INDEPENDENT (canonicalization).
//   P2 a tool IN the manifest is accepted; a tool NOT in it is refused -- for random
//      manifests and random query tools (AGID-claim-29 membership is exact).
//   P3 the validity window decision is MONOTONE in the clock: accepted at some
//      instant t implies accepted for every instant within [NotBefore,NotAfter], and
//      refused strictly outside (AGID-claim-7 short-TTL from the credential alone).
//   P4 REFUSAL IS STABLE: re-running Verify on the same refused input refuses the
//      same way (determinism / no hidden state, no network dependence).

// TestProperty_ToolManifestDigestCanonicalization (P1).
func TestProperty_ToolManifestDigestCanonicalization(t *testing.T) {
	rng := proptest.New(1)
	vocab := []string{"a", "b", "c", "read", "write", "list", "delete", "exec"}
	for i := 0; i < 200; i++ {
		n := rng.Intn(len(vocab)) + 1
		base := make([]string, n)
		for j := range base {
			base[j] = vocab[rng.Intn(len(vocab))]
		}
		// A shuffled + duplicated + case/space-perturbed variant must hash equal.
		variant := append([]string(nil), base...)
		variant = append(variant, base...) // duplicates
		rng.Shuffle(len(variant), func(a, b int) { variant[a], variant[b] = variant[b], variant[a] })
		perturbed := make([]string, len(variant))
		for j, s := range variant {
			perturbed[j] = "  " + s + " "
		}
		if !bytesEq(toolManifestDigest(base), toolManifestDigest(perturbed)) {
			t.Fatalf("case %d: tool-manifest digest not canonicalization-invariant for %v vs %v", i, base, perturbed)
		}
	}
}

// TestProperty_ToolManifestMembership (P2).
func TestProperty_ToolManifestMembership(t *testing.T) {
	rng := proptest.New(2)
	class, op := "reader", "read-object"
	for i := 0; i < 60; i++ {
		tools := randomTools(rng, 1, 6)
		repr := buildRepr(t, "prompt", tools)
		policy := approvePolicy(repr, class, op, tools)
		clk := FixedClock(unixToTime(testNow))

		// A tool IN the manifest (and a granted op) must accept.
		inTool := tools[rng.Intn(len(tools))]
		credIn, rootIn := tokenCred(t, fullBinding(repr, class, nil), testNow-60, testNow+60)
		if _, err := Verify(credIn, rootIn, policy, Action{Operation: op, Tool: inTool}, clk); err != nil {
			t.Fatalf("case %d: in-manifest tool %q refused: %v", i, inTool, err)
		}

		// A tool NOT in the manifest must refuse with ErrToolAbsentFromManifest.
		outTool := "definitely-not-" + randToken(rng)
		if containsNorm(tools, outTool) {
			continue
		}
		credOut, rootOut := tokenCred(t, fullBinding(repr, class, nil), testNow-60, testNow+60)
		if _, err := Verify(credOut, rootOut, policy, Action{Operation: op, Tool: outTool}, clk); !errors.Is(err, ErrToolAbsentFromManifest) {
			t.Fatalf("case %d: out-of-manifest tool %q = %v, want ErrToolAbsentFromManifest", i, outTool, err)
		}
	}
}

// TestProperty_ValidityMonotone (P3).
func TestProperty_ValidityMonotone(t *testing.T) {
	tools := []string{"read-object"}
	repr := buildRepr(t, "prompt", tools)
	class, op := "reader", "read-object"
	policy := approvePolicy(repr, class, op, tools)
	action := Action{Operation: op, Tool: "read-object"}

	nbf, exp := testNow, testNow+3600
	rng := proptest.New(3)
	for i := 0; i < 120; i++ {
		// Pick an instant anywhere in a wide band around the window.
		at := nbf - 1800 + int64(rng.Intn(3600+3600))
		cred, root := tokenCred(t, fullBinding(repr, class, nil), nbf, exp)
		_, err := Verify(cred, root, policy, action, FixedClock(unixToTime(at)))
		inWindow := at >= nbf && at <= exp
		if inWindow && err != nil {
			t.Fatalf("case %d: instant %d in [%d,%d] refused: %v", i, at, nbf, exp, err)
		}
		if !inWindow && !errors.Is(err, ErrCredentialExpired) {
			t.Fatalf("case %d: instant %d outside [%d,%d] = %v, want ErrCredentialExpired", i, at, nbf, exp, err)
		}
	}
}

// TestProperty_RefusalStable (P4): a refused input refuses identically on repeat.
func TestProperty_RefusalStable(t *testing.T) {
	tools := []string{"read-object"}
	repr := buildRepr(t, "prompt", tools)
	class, op := "reader", "read-object"
	policy := approvePolicy(repr, class, op, tools)
	clk := FixedClock(unixToTime(testNow))

	// An over-authority action (delete not granted).
	cred, root := tokenCred(t, fullBinding(repr, class, nil), testNow-60, testNow+60)
	action := Action{Operation: "delete-object", Tool: "read-object"}
	var firstErr error
	for i := 0; i < 5; i++ {
		_, err := Verify(cred, root, policy, action, clk)
		if err == nil {
			t.Fatalf("iter %d: over-authority action accepted, want refuse", i)
		}
		if firstErr == nil {
			firstErr = err
		} else if err.Error() != firstErr.Error() {
			t.Fatalf("iter %d: refusal changed: %v vs %v", i, err, firstErr)
		}
	}
}

// ---- small property helpers ----

func randomTools(rng *proptest.Rand, min, max int) []string {
	n := min + rng.Intn(max-min+1)
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, randToken(rng))
	}
	return out
}

func randToken(rng *proptest.Rand) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, 4+rng.Intn(4))
	for i := range b {
		b[i] = letters[rng.Intn(len(letters))]
	}
	return string(b)
}

func containsNorm(xs []string, want string) bool {
	w := normTool(want)
	for _, x := range xs {
		if normTool(x) == w {
			return true
		}
	}
	return false
}

func bytesEq(a, b []byte) bool { return crypto.ConstantTimeEqual(a, b) }
