// SPDX-License-Identifier: LicenseRef-trstctl-EE

package verify

import (
	"bytes"
	"testing"

	"trstctl.com/trstctl/ee/agentid/agentstack"
	"trstctl.com/trstctl/internal/crypto"
)

// differential_test.go proves the WASM-lean re-implementation in this package
// agrees BYTE-FOR-BYTE with the real ee/agentid/agentstack package (AGID-03) it
// deliberately avoids importing in the shipped verify path. agentstack is imported
// HERE, in a test file only -- so it never enters the package's runtime dependency
// surface (the WASM build and the offline verify path stay lean) while a drift in
// the canonical framing between the two is caught immediately.
//
// It asserts:
//   - toolManifestDigest(tools) == agentstack.ToolManifest{tools}.Digest()
//   - decodeBoundRepr(rep.CanonicalBytes()) recovers the SAME digests agentstack
//     bound (system-prompt digest, tool-manifest digest, model block)
//   - reprDigest(rep.CanonicalBytes()) == rep.Digest()

// TestDifferential_ToolManifestDigestMatchesAgentstack proves the tool-manifest
// digest this package recomputes equals the one agentstack produces, for several
// tool sets (including order/dup variations, which must canonicalize equal).
func TestDifferential_ToolManifestDigestMatchesAgentstack(t *testing.T) {
	cases := [][]string{
		nil,
		{"read-object"},
		{"read-object", "list-bucket"},
		{"list-bucket", "read-object"}, // different order -> same digest
		{"Read-Object", " read-object ", "list-BUCKET"}, // case/space/dup -> canonicalizes
		{"a", "b", "c", "d", "e"},
	}
	for i, tools := range cases {
		want := agentstack.NewToolManifest(tools...).Digest()
		got := toolManifestDigest(tools)
		if !bytes.Equal(got, want) {
			t.Fatalf("case %d %v: toolManifestDigest mismatch\n got=%x\nwant=%x", i, tools, got, want)
		}
	}
}

// TestDifferential_ReprDecodeMatchesAgentstack builds a real agentstack
// Representation, takes its canonical bytes, and proves decodeBoundRepr recovers
// the exact bound digests + model block, and that reprDigest equals rep.Digest.
func TestDifferential_ReprDecodeMatchesAgentstack(t *testing.T) {
	tools := []string{"read-object", "list-bucket"}

	// Provider-id model form.
	repPID, err := agentstack.New(
		[]byte("a canonical system prompt"),
		agentstack.NewToolManifest(tools...),
		agentstack.Model{Form: agentstack.ModelFormProviderID, ProviderModelID: "anthropic/claude-x", ModelVersion: "2026-01-01"},
	)
	if err != nil {
		t.Fatalf("agentstack.New(provider): %v", err)
	}
	repPID.Orchestrator = "orch-1"
	repPID.Runtime = "rt-1"
	assertReprMatches(t, repPID, tools)

	// Weights-digest model form.
	repW, err := agentstack.New(
		[]byte("another prompt"),
		agentstack.NewToolManifest(tools...),
		agentstack.Model{Form: agentstack.ModelFormWeightsDigest, WeightsDigest: crypto.SHA256Sum([]byte("weights"))},
	)
	if err != nil {
		t.Fatalf("agentstack.New(weights): %v", err)
	}
	assertReprMatches(t, repW, tools)
}

func assertReprMatches(t *testing.T, rep agentstack.Representation, tools []string) {
	t.Helper()
	cb, err := rep.CanonicalBytes()
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	got, err := decodeBoundRepr(cb)
	if err != nil {
		t.Fatalf("decodeBoundRepr(agentstack canonical bytes) = %v, want success", err)
	}
	if !bytes.Equal(got.SystemPromptDigest, rep.SystemPromptDigest) {
		t.Fatalf("system-prompt digest mismatch\n got=%x\nwant=%x", got.SystemPromptDigest, rep.SystemPromptDigest)
	}
	if !bytes.Equal(got.ToolManifestDigest, rep.ToolManifestDigest) {
		t.Fatalf("tool-manifest digest mismatch\n got=%x\nwant=%x", got.ToolManifestDigest, rep.ToolManifestDigest)
	}
	// The tool-manifest digest must also equal what THIS package computes from the
	// tool list, closing the loop end-to-end.
	if !bytes.Equal(got.ToolManifestDigest, toolManifestDigest(tools)) {
		t.Fatalf("bound tool-manifest digest != recomputed from tool list")
	}
	// Model block round-trips.
	if got.ModelForm != uint8(rep.Model.Form) {
		t.Fatalf("model form mismatch got=%d want=%d", got.ModelForm, rep.Model.Form)
	}
	switch rep.Model.Form {
	case agentstack.ModelFormProviderID:
		if got.ModelProviderID != rep.Model.ProviderModelID || got.ModelVersion != rep.Model.ModelVersion {
			t.Fatalf("provider model mismatch got=(%q,%q) want=(%q,%q)", got.ModelProviderID, got.ModelVersion, rep.Model.ProviderModelID, rep.Model.ModelVersion)
		}
	case agentstack.ModelFormWeightsDigest:
		if !bytes.Equal(got.ModelWeightsDigest, rep.Model.WeightsDigest) {
			t.Fatalf("weights digest mismatch")
		}
	}
	// reprDigest == rep.Digest (the value AGID-04 binds as AgentStackDigest).
	wantDig, err := rep.Digest()
	if err != nil {
		t.Fatalf("rep.Digest: %v", err)
	}
	if !bytes.Equal(reprDigest(cb), wantDig) {
		t.Fatalf("reprDigest mismatch\n got=%x\nwant=%x", reprDigest(cb), wantDig)
	}
}
