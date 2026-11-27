// SPDX-License-Identifier: BUSL-1.1

package agentupgrade_test

import (
	"strings"
	"testing"

	fleet "trstctl.com/trstctl/internal/agentupgrade"
	"trstctl.com/trstctl/internal/crypto"
)

// A68: an artifact may carry its publisher's Ed25519 signature over the pinned
// sha256. With a publisher key pinned, an unsigned, malformed or foreign
// signature is refused by name; without a key, staged campaigns fail closed.
func TestArtifactPublisherSignatureVerifiesAgainstThePinnedKey(t *testing.T) {
	privPEM, pubPEM, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := crypto.ParsePublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	artifact := fleet.Artifact{OS: "linux", Arch: "amd64", URL: "https://mirror.example.test/agent", SHA256: strings.Repeat("ab", 32)}
	signature, err := fleet.SignArtifact(artifact, privPEM)
	if err != nil {
		t.Fatal(err)
	}
	signed := artifact
	signed.Signature = signature
	if err := fleet.VerifyArtifactSignature(signed, pub.DER); err != nil {
		t.Fatalf("a signature by the pinned publisher was refused: %v", err)
	}
	if err := fleet.ValidateArtifactSignatures([]fleet.Artifact{signed}, pub.DER); err != nil {
		t.Fatalf("validate signed artifacts: %v", err)
	}

	for name, altered := range map[string]fleet.Artifact{
		"unsigned":            artifact,
		"not base64":          {OS: "linux", Arch: "amd64", URL: artifact.URL, SHA256: artifact.SHA256, Signature: "not-base64!"},
		"other digest":        {OS: "linux", Arch: "amd64", URL: artifact.URL, SHA256: strings.Repeat("cd", 32), Signature: signature},
		"truncated signature": {OS: "linux", Arch: "amd64", URL: artifact.URL, SHA256: artifact.SHA256, Signature: signature[:len(signature)-8]},
	} {
		if err := fleet.VerifyArtifactSignature(altered, pub.DER); err == nil {
			t.Fatalf("%s artifact verified against the pinned key", name)
		}
		if err := fleet.ValidateArtifactSignatures([]fleet.Artifact{altered}, pub.DER); err == nil || !strings.Contains(err.Error(), "publisher") {
			t.Fatalf("%s artifact passed campaign validation: %v", name, err)
		}
	}
	// A different publisher's key is a foreign signature.
	_, otherPubPEM, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	other, err := crypto.ParsePublicKeyPEM(otherPubPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := fleet.VerifyArtifactSignature(signed, other.DER); err == nil {
		t.Fatal("a signature verified against a different publisher's key")
	}
	// A digest supplied by the campaign opener does not authenticate the
	// executable. Even a signature is meaningless without a trusted key.
	for _, candidate := range []fleet.Artifact{artifact, signed} {
		if err := fleet.ValidateArtifactSignatures([]fleet.Artifact{candidate}, nil); err == nil || !strings.Contains(err.Error(), "publisher key") {
			t.Fatalf("artifact without a pinned publisher key passed campaign validation: %v", err)
		}
	}
	if err := fleet.ValidateArtifactSignatures(nil, nil); err != nil {
		t.Fatalf("observe-only campaign without artifacts needs no publisher key: %v", err)
	}
}
