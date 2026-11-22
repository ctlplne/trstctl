// SPDX-License-Identifier: BUSL-1.1

package delegation

import (
	"bytes"
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/agentid/agentstack"
	"trstctl.com/trstctl/internal/signing"
)

func TestCR054AuthorityClassGrantIsSignedAndNarrows(t *testing.T) {
	parent := wideAuthority()
	parent.AuthorityClasses = []string{"reader"}
	child := narrowerAuthority()
	child.AuthorityClasses = []string{"tenant-admin"}
	if WithinParent(child, parent, nil) {
		t.Fatal("child widened the credential authority class")
	}
	signer, _ := signerWithDER(t)
	record, err := (Record{TenantID: "tenant", DelegatorID: "root", DelegateID: "leaf", Authority: parent, RootAnchor: true}).Sign(signer, nil)
	if err != nil {
		t.Fatal(err)
	}
	record.Authority.AuthorityClasses = []string{"tenant-admin"}
	if err := record.Verify(signer.Public(), nil); err == nil {
		t.Fatal("tampering with a signed authority-class grant preserved its signature")
	}
}

func TestCR054SignerToolDigestMatchesAgentStack(t *testing.T) {
	for _, tools := range [][]string{{}, {"search"}, {" Search ", "search", "email"}} {
		got := declaredToolManifestDigest(tools)
		want := agentstack.NewToolManifest(tools...).Digest()
		if !bytes.Equal(got, want) {
			t.Fatalf("signer and agent-stack tool digests diverged for %q", tools)
		}
	}
}

// CR-054: the requester's designated class is not delegated by a signed
// read/search chain. An attestation or a local relying-party policy cannot
// promote the chain to a class its head never received.
func TestCR054SignerRefusesClassAbsentFromSignedHead(t *testing.T) {
	const tenant = "cr054-tenant"
	chain, roots, _ := singleAnchorChain(t, nil, tenant, "fido2:root")
	f := newGateFixture(t, roots, nil, nil, nil)
	preconditions, err := EncodePreconditionsBody(PreconditionsBody{
		Chain: chain, DesignatedClass: "tenant-admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := f.gate.VerifyIssuancePreconditions(backgroundCtx(), signing.IssuancePreconditions{
		TenantID: tenant, TrustAnchorRef: "leaf", Preconditions: preconditions,
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Approved {
		t.Fatal("signer approved a caller-asserted tenant-admin class absent from the signed chain head")
	}
}

// The same signed chain delegates only search. A representation whose tool
// manifest includes shell.exec must not acquire that tool through its digest.
func TestCR054SignerRefusesToolOutsideSignedHead(t *testing.T) {
	const tenant = "cr054-tools-tenant"
	chain, roots, _ := singleAnchorChain(t, nil, tenant, "fido2:root")
	f := newGateFixture(t, roots, nil, nil, nil)
	preconditions, err := EncodePreconditionsBody(PreconditionsBody{
		Chain: chain, DeclaredTools: []string{"search", "shell.exec"},
	})
	if err != nil {
		t.Fatal(err)
	}
	repr, err := json.Marshal(mustRepr(t, "cr054 prompt", "search", "shell.exec"))
	if err != nil {
		t.Fatal(err)
	}
	decision, err := f.gate.VerifyIssuancePreconditions(backgroundCtx(), signing.IssuancePreconditions{
		TenantID: tenant, TrustAnchorRef: "leaf", Preconditions: preconditions, SubjectRepr: repr,
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Approved {
		t.Fatal("signer approved an agent-stack tool manifest containing shell.exec outside the signed chain head")
	}
}

func TestCR054SignerRejectsFalseToolDeclaration(t *testing.T) {
	const tenant = "cr054-manifest-tenant"
	chain, roots, _ := singleAnchorChain(t, nil, tenant, "fido2:root")
	f := newGateFixture(t, roots, nil, nil, nil)
	repr, err := json.Marshal(mustRepr(t, "cr054 prompt", "search", "shell.exec"))
	if err != nil {
		t.Fatal(err)
	}
	for _, declared := range [][]string{nil, {"search"}} {
		preconditions, err := EncodePreconditionsBody(PreconditionsBody{Chain: chain, DeclaredTools: declared})
		if err != nil {
			t.Fatal(err)
		}
		decision, err := f.gate.VerifyIssuancePreconditions(backgroundCtx(), signing.IssuancePreconditions{
			TenantID: tenant, TrustAnchorRef: "leaf", Preconditions: preconditions, SubjectRepr: repr,
		})
		if err != nil {
			t.Fatal(err)
		}
		if decision.Approved {
			t.Fatalf("signer approved undeclared shell.exec with declared tools %q", declared)
		}
		if got := decodeRefusalForTest(t, decision.RefusalRecord).FailedCheck; got != CheckAgentStack {
			t.Fatalf("refusal check = %q, want %q", got, CheckAgentStack)
		}
	}
}
