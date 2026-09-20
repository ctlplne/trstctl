// SPDX-License-Identifier: BUSL-1.1

package delegation

import (
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// TestHopMustSignWithTheKeyItsParentDelegatedTo is the regression guard for the
// residual the verifier used to carry, in its own words, as INCOMPLETE BINDING.
//
// A chain bound its hops as PRINCIPALS — each hop's DelegatorID had to equal the
// previous hop's DelegateID — but nothing bound them as KEYS. A record named its
// delegate only by DelegateID, and KeyRef.ID was an opaque identifier rather than
// a key thumbprint, so an attacker who set DelegatorID to the parent's DelegateID
// could sign with a key of their own choosing and the chain still verified. The
// ID check constrained who a hop CLAIMED to be, never what it could prove.
//
// The parent now commits to its delegate's key thumbprint inside its signed
// canonical bytes, so a substituted signing key is caught.
func TestHopMustSignWithTheKeyItsParentDelegatedTo(t *testing.T) {
	reg := (*ToolRegistry)(nil)
	const tenantID = "t-keybind"

	// verifyChain is the unit under test; a Gate with just a tool registry and the
	// anchors is all it needs.
	verify := func(t *testing.T, envs []RecordEnvelope, anchors map[string]RootAnchor) verifyResult {
		t.Helper()
		g := &Gate{cfg: Config{Tools: reg, Roots: NewTrustStore(anchors), Revocations: NeverRevoked{}}}
		return g.verifyChain(tenantID, envs, time.Now())
	}

	t.Run("the delegated key verifies", func(t *testing.T) {
		envs, anchors, _ := singleAnchorChain(t, reg, tenantID, "fido2:root")
		if d := verify(t, envs, anchors); d.refused {
			t.Fatalf("a chain signed by the delegated key was refused: %s / %s", d.check, d.detail)
		}
	})

	t.Run("a substituted signing key is refused", func(t *testing.T) {
		envs, anchors, _ := singleAnchorChain(t, reg, tenantID, "fido2:root")

		// The attacker keeps the name the root delegated to — "mid" — and every
		// other field, and simply re-signs the head hop with their OWN key. Before
		// the binding this satisfied every check: the principal names line up, the
		// parent digest is untouched, and the signature verifies against the key
		// the attacker attached.
		attackerSigner, attackerDER := signerWithDER(t)
		resigned, err := envs[1].Record.Sign(attackerSigner, reg)
		if err != nil {
			t.Fatalf("attacker sign: %v", err)
		}
		envs[1].Record = resigned
		envs[1].DelegatorPublicDER = attackerDER

		d := verify(t, envs, anchors)
		if !d.refused {
			t.Fatal("a hop signed with a key the parent never delegated to was accepted; " +
				"naming yourself as the parent's delegate would be enough to inherit its authority")
		}
		if !strings.Contains(strings.ToLower(d.detail), "key") {
			t.Errorf("the refusal should name the key mismatch, got check=%s detail=%q", d.check, d.detail)
		}
	})

	t.Run("an unbound parent is refused rather than skipped", func(t *testing.T) {
		// A record issued before this field existed commits to no delegate key.
		// That hop cannot be checked, and "cannot be checked" must not read as
		// "passed" — otherwise an attacker just omits the field.
		rootSigner, rootDER := signerWithDER(t)
		midSigner, midDER := signerWithDER(t)
		hops := []hop{
			{delegatorID: "root", delegatorKeyID: "root-key", delegateID: "mid", authority: wideAuthority(), depthRemaining: 3, validity: openWindow()},
			{delegatorID: "mid", delegatorKeyID: "mid-key", delegateID: "leaf", authority: narrowerAuthority(), depthRemaining: 2, validity: openWindow()},
		}
		bc := buildChain(t, reg, tenantID, hops, []crypto.Signer{rootSigner, midSigner}, [][]byte{rootDER, midDER})
		envs := bc.envelopes

		// Strip the root's commitment and re-sign it, so the chain is internally
		// consistent and differs from the valid one only in carrying no binding.
		envs[0].Record.DelegateKeyThumbprint = nil
		rootResigned, err := envs[0].Record.Sign(rootSigner, reg)
		if err != nil {
			t.Fatalf("re-sign root: %v", err)
		}
		envs[0].Record = rootResigned
		rootDigest, err := rootResigned.Digest(reg)
		if err != nil {
			t.Fatalf("root digest: %v", err)
		}
		envs[1].Record.ParentDigest = rootDigest
		leafResigned, err := envs[1].Record.Sign(midSigner, reg)
		if err != nil {
			t.Fatalf("re-sign leaf: %v", err)
		}
		envs[1].Record = leafResigned

		anchors := map[string]RootAnchor{"root-key": {PublicDER: rootDER, AuthRef: "fido2:root"}}
		if d := verify(t, envs, anchors); !d.refused {
			t.Fatal("a chain whose parent commits to no delegate key was accepted; the binding " +
				"would be silently optional and an attacker would simply omit it")
		}
	})
}
