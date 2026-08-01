// SPDX-License-Identifier: LicenseRef-trstctl-EE

package verify

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/agentid/delegation/carriage"
	"trstctl.com/trstctl/ee/agentid/taskenv"
	"trstctl.com/trstctl/internal/crypto"
)

// verify_test.go holds the AGID-09 canonical tests (verbatim names) plus the
// shared, in-package harness that builds REAL AGID credentials across the three
// carriage forms with genuine signatures and genuine bound values, so the tests
// exercise the true offline relying-party path (not hand-rolled shortcuts). Every
// case is OFFLINE: no network client is constructed anywhere in the verify path.

const testNow = int64(1_000_000_000) // fixed evaluation instant (Unix seconds)

// reprBuilder assembles AGID-03-canonical agent-stack representation bytes in the
// exact framing decodeBoundRepr accepts (mirrors agentstack.Representation.
// CanonicalBytes for a provider-id model), so tests can bind a representation with
// a known tool manifest WITHOUT importing agentstack (keeping the verifier lean).
func buildRepr(t *testing.T, prompt string, tools []string) []byte {
	t.Helper()
	var b bytes.Buffer
	writeS := func(s string) {
		var x [8]byte
		binary.BigEndian.PutUint64(x[:], uint64(len(s)))
		b.Write(x[:])
		b.WriteString(s)
	}
	writeB := func(p []byte) {
		var x [8]byte
		binary.BigEndian.PutUint64(x[:], uint64(len(p)))
		b.Write(x[:])
		b.Write(p)
	}
	b.WriteString(reprCanonicalPrefix)
	writeS("system_prompt_digest")
	writeB(crypto.SHA256Sum([]byte(prompt)))
	writeS("tool_manifest_digest")
	writeB(toolManifestDigest(tools))
	writeS("model")
	b.WriteByte(byte(modelFormProviderID))
	writeS("provider_model_id")
	writeS("anthropic/claude-x")
	writeS("model_version")
	writeS("2026-01-01")
	writeS("orchestrator")
	writeS("orch-1")
	writeS("runtime")
	writeS("rt-1")
	return b.Bytes()
}

// tokenCred builds a real signed-token credential carrying bv, signed by a fresh
// issuer key, plus a pinned JWKS trust root. exp/nbf standard claims are added so
// the credential carries its own short-TTL window.
func tokenCred(t *testing.T, bv carriage.BoundValues, nbf, exp int64) (Credential, TrustRoot) {
	t.Helper()
	issuer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("issuer key: %v", err)
	}
	t.Cleanup(issuer.Destroy)
	// Build claims by hand so we can add nbf/exp alongside the AGID binding claim.
	token := signTokenWithClaims(t, issuer, "kid-1", bv, nbf, exp)
	jwks := jwksJSON(t, issuer.Public(), "kid-1")
	return Credential{Form: FormSignedToken, Bytes: []byte(token)}, TrustRoot{JWKSJSON: jwks}
}

// signTokenWithClaims signs a compact JWS whose claims carry the AGID binding
// claim under "agid_binding" plus optional nbf/exp, using the crypto boundary. It
// mirrors carriage.EncodeSignedToken's claim placement so carriage.DecodeToken
// reads it, while letting the test add standard validity claims.
func signTokenWithClaims(t *testing.T, signer crypto.DigestSigner, kid string, bv carriage.BoundValues, nbf, exp int64) string {
	t.Helper()
	// carriage marshals BoundValues digests as base64url via its bindingClaim; the
	// simplest faithful path is to encode the full binding claim exactly as carriage
	// does by round-tripping through EncodeSignedToken, then splice nbf/exp in. But
	// carriage's claim shape is unexported. Instead, build the claims object with the
	// binding claim as the carriage workload-doc marshals it (identical wire shape).
	bindingJSON := carriageBindingClaimJSON(t, bv)
	claims := map[string]json.RawMessage{
		"sub":          json.RawMessage(`"spiffe://agent"`),
		"agid_binding": bindingJSON,
	}
	if nbf != 0 {
		claims["nbf"] = json.RawMessage(itoa(nbf))
	}
	if exp != 0 {
		claims["exp"] = json.RawMessage(itoa(exp))
	}
	tok, err := crypto.SignJWT(signer, kid, claims)
	if err != nil {
		t.Fatalf("SignJWT: %v", err)
	}
	return tok
}

// carriageBindingClaimJSON extracts the exact "agid_binding" claim JSON the
// carriage package produces for bv, by encoding a workload-identity document and
// pulling the claim out. This guarantees the test's token carries byte-identical
// binding bytes to what carriage.DecodeToken expects.
func carriageBindingClaimJSON(t *testing.T, bv carriage.BoundValues) json.RawMessage {
	t.Helper()
	doc, err := carriage.EncodeWorkloadDoc(bv, "", "", "")
	if err != nil {
		t.Fatalf("EncodeWorkloadDoc: %v", err)
	}
	var env map[string]json.RawMessage
	if err := json.Unmarshal(doc, &env); err != nil {
		t.Fatalf("unmarshal doc: %v", err)
	}
	raw, ok := env["agid_binding"]
	if !ok {
		t.Fatal("no agid_binding in encoded workload doc")
	}
	return raw
}

func itoa(v int64) []byte {
	return []byte(strconv.FormatInt(v, 10))
}

// jwksJSON builds a pinned JWKS document for a public key.
func jwksJSON(t *testing.T, pub crypto.PublicKey, kid string) []byte {
	t.Helper()
	jwk, err := crypto.PublicJWK(pub, kid)
	if err != nil {
		t.Fatalf("PublicJWK: %v", err)
	}
	b, err := json.Marshal(crypto.JWKS{Keys: []crypto.JWK{jwk}})
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return b
}

// fullBinding builds bound values for a full binding (agent-stack repr + class +
// optional task-envelope digest), with the AgentStackDigest consistent with the
// repr bytes (so the verifier's defense-in-depth digest check passes).
func fullBinding(repr []byte, class string, taskEnvDigest []byte) carriage.BoundValues {
	return carriage.BoundValues{
		AgentStackDigest:   reprDigest(repr),
		AgentStackRepr:     repr,
		DesignatedClass:    class,
		ComparatorVersion:  "v1",
		TaskEnvelopeDigest: taskEnvDigest,
	}
}

// approvePolicy builds a policy that approves the repr's agent stack, permits the
// class + operation, and carries the tool manifest.
func approvePolicy(repr []byte, class, op string, tools []string) LocalPolicy {
	return NewLocalPolicy().
		ApproveAgentStack(reprDigest(repr)).
		PermitClass(class).
		GrantOperations(class, op).
		WithToolManifest(tools...)
}

// ---- CANONICAL TEST 1 (AGID-claim-28 / INV-A7) ----

// TestRPVerify_OfflineAcceptsValid proves a valid credential verifies OFFLINE
// against the trust root -- across all three carriage forms -- with no
// control-plane network access, and is accepted when the bound agent stack is in
// policy, the action is within authority, and the credential is unexpired.
func TestRPVerify_OfflineAcceptsValid(t *testing.T) {
	tools := []string{"read-object", "list-bucket"}
	repr := buildRepr(t, "prompt-A", tools)
	class := "reader"
	op := "read-object"
	policy := approvePolicy(repr, class, op, tools)
	action := Action{Operation: op, Tool: "read-object"}
	clk := FixedClock(unixToTime(testNow))

	t.Run("signed-token", func(t *testing.T) {
		cred, root := tokenCred(t, fullBinding(repr, class, nil), testNow-60, testNow+60)
		res, err := Verify(cred, root, policy, action, clk)
		if err != nil {
			t.Fatalf("Verify(token) = %v, want accept", err)
		}
		if res.AuthorityClass != class || res.Operation != op {
			t.Fatalf("result = %+v, want class=%s op=%s", res, class, op)
		}
	})

	t.Run("x509", func(t *testing.T) {
		// An X.509 credential carries its validity as the certificate's real-time
		// NotBefore/NotAfter, so evaluate it at real "now" (nil clk => system clock),
		// not the fixed 2001 instant the token/workload cases use.
		cred, root := x509Cred(t, fullBinding(repr, class, nil), time.Hour)
		res, err := Verify(cred, root, policy, action, nil)
		if err != nil {
			t.Fatalf("Verify(x509) = %v, want accept", err)
		}
		if res.Form != FormX509 {
			t.Fatalf("form = %s, want x509", res.Form)
		}
	})

	t.Run("workload-identity", func(t *testing.T) {
		cred, root := workloadCred(t, fullBinding(repr, class, nil), testNow-60, testNow+60)
		if _, err := Verify(cred, root, policy, action, clk); err != nil {
			t.Fatalf("Verify(workload) = %v, want accept", err)
		}
	})
}

// ---- CANONICAL TEST 2 (AGID-claim-28 / INV-A7) ----

// TestRPVerify_AgentStackVsLocalPolicy proves the bound agent-stack representation
// is compared against local policy: an in-policy representation is accepted and an
// out-of-policy representation (its digest not in the approved set) is REFUSED
// fail-closed, WITHOUT any network access.
func TestRPVerify_AgentStackVsLocalPolicy(t *testing.T) {
	tools := []string{"read-object"}
	inPolicyRepr := buildRepr(t, "approved-prompt", tools)
	outOfPolicyRepr := buildRepr(t, "rogue-prompt", tools)
	class := "reader"
	op := "read-object"
	action := Action{Operation: op, Tool: "read-object"}
	clk := FixedClock(unixToTime(testNow))

	// Policy approves ONLY the in-policy representation.
	policy := approvePolicy(inPolicyRepr, class, op, tools)

	// In-policy credential accepts.
	credOK, rootOK := tokenCred(t, fullBinding(inPolicyRepr, class, nil), testNow-60, testNow+60)
	if _, err := Verify(credOK, rootOK, policy, action, clk); err != nil {
		t.Fatalf("in-policy Verify = %v, want accept", err)
	}

	// Out-of-policy credential (different, unapproved agent stack) refuses.
	credBad, rootBad := tokenCred(t, fullBinding(outOfPolicyRepr, class, nil), testNow-60, testNow+60)
	if _, err := Verify(credBad, rootBad, policy, action, clk); !errors.Is(err, ErrAgentStackNotApproved) {
		t.Fatalf("out-of-policy Verify = %v, want ErrAgentStackNotApproved", err)
	}
}

// ---- CANONICAL TEST 3 (AGID-claim-28 / INV-A7) ----

// TestRPVerify_RefusesActionExceedingAuthorityOrTaskScope proves an action that
// EXCEEDS the bound authority is refused, AND an action that falls OUTSIDE the
// bound task scope is refused EVEN WHEN the broader authority would permit it
// (additive task binding).
func TestRPVerify_RefusesActionExceedingAuthorityOrTaskScope(t *testing.T) {
	tools := []string{"read-object", "delete-object"}
	repr := buildRepr(t, "prompt-A", tools)
	class := "reader"
	clk := FixedClock(unixToTime(testNow))

	// (a) Action exceeds authority: policy grants only "read-object" to the class, but
	// the action requests "delete-object".
	policyReadOnly := approvePolicy(repr, class, "read-object", tools)
	credA, rootA := tokenCred(t, fullBinding(repr, class, nil), testNow-60, testNow+60)
	if _, err := Verify(credA, rootA, policyReadOnly, Action{Operation: "delete-object", Tool: "delete-object"}, clk); !errors.Is(err, ErrActionExceedsAuthority) {
		t.Fatalf("over-authority Verify = %v, want ErrActionExceedsAuthority", err)
	}

	// (b) Action outside task scope though authority WOULD permit it. Grant BOTH ops in
	// authority, bind a task envelope whose scope authorizes only "read-object", then
	// request "delete-object": authority permits it, but task binding refuses.
	env := buildTaskEnvelope(t, []taskenv.Commitment{
		{Name: "op:read-object", Digest: []byte("x")}, // "op:" convention => authorized op
	})
	envDig, err := env.Digest()
	if err != nil {
		t.Fatalf("env digest: %v", err)
	}
	policyBothOps := approvePolicy(repr, class, "read-object", tools).
		GrantOperations(class, "delete-object") // authority now permits delete too
	policyBothOps.ExpectedTaskEnvelope = &env

	credB, rootB := tokenCred(t, fullBinding(repr, class, envDig), testNow-60, testNow+60)
	// Sanity: read-object (in task scope + authority) is accepted.
	if _, err := Verify(credB, rootB, policyBothOps, Action{Operation: "read-object", Tool: "read-object"}, clk); err != nil {
		t.Fatalf("in-scope read Verify = %v, want accept", err)
	}
	// delete-object: authority permits, task scope does NOT -> refuse.
	credB2, rootB2 := tokenCred(t, fullBinding(repr, class, envDig), testNow-60, testNow+60)
	if _, err := Verify(credB2, rootB2, policyBothOps, Action{Operation: "delete-object", Tool: "delete-object"}, clk); !errors.Is(err, ErrActionOutsideTaskScope) {
		t.Fatalf("out-of-task-scope Verify = %v, want ErrActionOutsideTaskScope", err)
	}
}

// ---- CANONICAL TEST 4 (AGID-claim-29 / INV-A7) ----

// TestRPVerify_RefusesToolAbsentFromManifest proves an action whose tool is absent
// from the bound tool manifest is refused fail-closed, while a tool present in the
// manifest is accepted.
func TestRPVerify_RefusesToolAbsentFromManifest(t *testing.T) {
	tools := []string{"read-object", "list-bucket"}
	repr := buildRepr(t, "prompt-A", tools)
	class := "reader"
	op := "read-object"
	clk := FixedClock(unixToTime(testNow))
	policy := approvePolicy(repr, class, op, tools)

	// Present tool accepts.
	credOK, rootOK := tokenCred(t, fullBinding(repr, class, nil), testNow-60, testNow+60)
	if _, err := Verify(credOK, rootOK, policy, Action{Operation: op, Tool: "list-bucket"}, clk); err != nil {
		t.Fatalf("in-manifest tool Verify = %v, want accept", err)
	}

	// A tool NOT in the bound manifest refuses.
	credBad, rootBad := tokenCred(t, fullBinding(repr, class, nil), testNow-60, testNow+60)
	if _, err := Verify(credBad, rootBad, policy, Action{Operation: op, Tool: "spawn-shell"}, clk); !errors.Is(err, ErrToolAbsentFromManifest) {
		t.Fatalf("absent-tool Verify = %v, want ErrToolAbsentFromManifest", err)
	}
}

// ---- CANONICAL TEST 5 (AGID-claim-7 / INV-A7) ----

// TestCredential_ShortTTLNoStatusQuery proves a short-TTL credential's validity is
// determinable from the credential ALONE: an unexpired credential is accepted and
// an expired one refused, with NO revocation-status query and -- asserted via the
// no-network guard -- NO network client constructed in the verify path.
func TestCredential_ShortTTLNoStatusQuery(t *testing.T) {
	tools := []string{"read-object"}
	repr := buildRepr(t, "prompt-A", tools)
	class := "reader"
	op := "read-object"
	policy := approvePolicy(repr, class, op, tools)
	action := Action{Operation: op, Tool: "read-object"}

	// Unexpired: clock inside the window -> accept.
	credLive, rootLive := tokenCred(t, fullBinding(repr, class, nil), testNow-60, testNow+60)
	if _, err := Verify(credLive, rootLive, policy, action, FixedClock(unixToTime(testNow))); err != nil {
		t.Fatalf("unexpired Verify = %v, want accept", err)
	}

	// Expired: clock past NotAfter -> refuse from the credential alone.
	credExp, rootExp := tokenCred(t, fullBinding(repr, class, nil), testNow-120, testNow-60)
	if _, err := Verify(credExp, rootExp, policy, action, FixedClock(unixToTime(testNow))); !errors.Is(err, ErrCredentialExpired) {
		t.Fatalf("expired Verify = %v, want ErrCredentialExpired", err)
	}

	// Not yet valid: clock before NotBefore -> refuse.
	credFuture, rootFuture := tokenCred(t, fullBinding(repr, class, nil), testNow+60, testNow+120)
	if _, err := Verify(credFuture, rootFuture, policy, action, FixedClock(unixToTime(testNow))); !errors.Is(err, ErrCredentialExpired) {
		t.Fatalf("not-yet-valid Verify = %v, want ErrCredentialExpired", err)
	}

	// No network client / status query in the verify path: this is asserted
	// statically (no net import) and structurally by the source-guard test
	// TestNoNetworkClientInVerifyPath (see nonetwork_test.go). The three refusals /
	// acceptance above were all decided from the credential + the injected clock
	// alone -- no revocation-status query was issued.
}
