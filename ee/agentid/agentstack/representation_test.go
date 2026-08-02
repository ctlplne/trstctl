// SPDX-License-Identifier: LicenseRef-trstctl-EE

package agentstack_test

import (
	"bytes"
	"testing"
	"trstctl.com/trstctl/ee/proptest"

	"trstctl.com/trstctl/ee/agentid/agentstack"
)

// weightsModel is a valid model in the weights-digest form.
func weightsModel(digest []byte) agentstack.Model {
	return agentstack.Model{Form: agentstack.ModelFormWeightsDigest, WeightsDigest: digest}
}

// providerModel is a valid model in the provider-id form.
func providerModel(id, version string) agentstack.Model {
	return agentstack.Model{Form: agentstack.ModelFormProviderID, ProviderModelID: id, ModelVersion: version}
}

// TestAgentStack_PromptAndToolManifestDigests asserts the representation always
// carries a system-prompt digest and a tool-manifest digest, both canonical and
// byte-stable across runs (INV-A3, acceptance #1). It also confirms the raw
// prompt is not retained anywhere on the representation (only its digest).
func TestAgentStack_PromptAndToolManifestDigests(t *testing.T) {
	prompt := []byte("you are a careful agent; obey the constitution")
	manifest := agentstack.NewToolManifest("fs.read", "net.http")
	model := providerModel("anthropic/claude-x", "2026-01-01")

	rep, err := agentstack.New(prompt, manifest, model)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if len(rep.SystemPromptDigest) == 0 {
		t.Fatal("representation is missing a system-prompt digest")
	}
	if len(rep.ToolManifestDigest) == 0 {
		t.Fatal("representation is missing a tool-manifest digest")
	}
	// SHA-256 digests are 32 bytes.
	if len(rep.SystemPromptDigest) != 32 {
		t.Errorf("system-prompt digest = %d bytes, want 32", len(rep.SystemPromptDigest))
	}
	if len(rep.ToolManifestDigest) != 32 {
		t.Errorf("tool-manifest digest = %d bytes, want 32", len(rep.ToolManifestDigest))
	}

	// Byte-stability across independent constructions (fresh prompt buffers,
	// re-ordered manifest declaration): same stack -> identical representation
	// bytes.
	rep2, err := agentstack.New([]byte("you are a careful agent; obey the constitution"),
		agentstack.NewToolManifest("net.http", "fs.read"), // declared in a different order
		providerModel("anthropic/claude-x", "2026-01-01"))
	if err != nil {
		t.Fatalf("New (second): %v", err)
	}
	cb1, err := rep.CanonicalBytes()
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	cb2, err := rep2.CanonicalBytes()
	if err != nil {
		t.Fatalf("CanonicalBytes (second): %v", err)
	}
	if !bytes.Equal(cb1, cb2) {
		t.Fatal("same agent stack produced different canonical bytes (not byte-stable)")
	}
	if !bytes.Equal(rep.SystemPromptDigest, rep2.SystemPromptDigest) {
		t.Error("same prompt produced different system-prompt digests")
	}
	if !bytes.Equal(rep.ToolManifestDigest, rep2.ToolManifestDigest) {
		t.Error("same tool set (different declaration order) produced different tool-manifest digests")
	}

	// The plaintext prompt must not survive anywhere in the representation's
	// canonical bytes — only its digest is carried (AN-8).
	if bytes.Contains(cb1, prompt) {
		t.Fatal("plaintext system prompt leaked into representation canonical bytes")
	}

	// An empty prompt is rejected fail-closed.
	if _, err := agentstack.New(nil, manifest, model); err == nil {
		t.Error("New accepted an empty system prompt; want error")
	}
}

// TestAgentStack_ModelFormIndicatorPresent asserts the model identifier is in
// exactly one form (weights digest XOR provider id+version) with an explicit
// indicator that round-trips and cannot be omitted (AGID-claim-11 / INV-A3,
// acceptance #2).
func TestAgentStack_ModelFormIndicatorPresent(t *testing.T) {
	prompt := []byte("system prompt")
	manifest := agentstack.NewToolManifest("fs.read")

	forms := []struct {
		name string
		mdl  agentstack.Model
		want agentstack.ModelForm
	}{
		{"weights-digest", weightsModel([]byte("32-byte-weights-digest-placeholder!")), agentstack.ModelFormWeightsDigest},
		{"provider-id", providerModel("openai/gpt", "v9"), agentstack.ModelFormProviderID},
	}
	for _, f := range forms {
		t.Run(f.name, func(t *testing.T) {
			rep, err := agentstack.New(prompt, manifest, f.mdl)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if rep.Model.Form != f.want {
				t.Fatalf("Model.Form = %v, want %v", rep.Model.Form, f.want)
			}
			// The indicator round-trips through the canonical bytes / parser.
			cb, err := rep.CanonicalBytes()
			if err != nil {
				t.Fatalf("CanonicalBytes: %v", err)
			}
			got, err := agentstack.Parse(cb)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got.Model.Form != f.want {
				t.Errorf("round-tripped Model.Form = %v, want %v", got.Model.Form, f.want)
			}
			// The non-declared form's fields must be absent after canonicalization.
			switch f.want {
			case agentstack.ModelFormWeightsDigest:
				if got.Model.ProviderModelID != "" || got.Model.ModelVersion != "" {
					t.Error("weights-digest form leaked provider fields")
				}
				if len(got.Model.WeightsDigest) == 0 {
					t.Error("weights-digest form dropped its digest")
				}
			case agentstack.ModelFormProviderID:
				if len(got.Model.WeightsDigest) != 0 {
					t.Error("provider-id form leaked a weights digest")
				}
				if got.Model.ProviderModelID == "" || got.Model.ModelVersion == "" {
					t.Error("provider-id form dropped its id/version")
				}
			}
		})
	}

	// The indicator cannot be omitted: an unset form is rejected fail-closed at
	// construction, at validation, and at canonicalization.
	if _, err := agentstack.New(prompt, manifest, agentstack.Model{WeightsDigest: []byte("x")}); err == nil {
		t.Error("New accepted a model with an unset form indicator; want error (AGID-claim-11)")
	}
	unset := agentstack.Representation{
		SystemPromptDigest: []byte("d"),
		ToolManifestDigest: []byte("d"),
		Model:              agentstack.Model{Form: agentstack.ModelFormUnset, WeightsDigest: []byte("x")},
	}
	if err := unset.Validate(); err == nil {
		t.Error("Validate accepted an unset model form; want error")
	}
	if _, err := unset.CanonicalBytes(); err == nil {
		t.Error("CanonicalBytes accepted an unset model form; want error")
	}

	// Ambiguous (both forms) is rejected: the form must be exactly one.
	ambiguous := agentstack.Model{
		Form:            agentstack.ModelFormWeightsDigest,
		WeightsDigest:   []byte("x"),
		ProviderModelID: "p",
		ModelVersion:    "v",
	}
	if err := ambiguous.Validate(); err == nil {
		t.Error("Validate accepted a model in more than one form; want error (AGID-claim-11)")
	}

	// Incomplete declared form is rejected.
	if err := (agentstack.Model{Form: agentstack.ModelFormProviderID, ProviderModelID: "p"}).Validate(); err == nil {
		t.Error("Validate accepted provider-id form with no version; want error")
	}
	if err := (agentstack.Model{Form: agentstack.ModelFormWeightsDigest}).Validate(); err == nil {
		t.Error("Validate accepted weights-digest form with no digest; want error")
	}
}

// TestRepresentation_DeterministicAndCollisionSensitive is the property test:
// digesting is deterministic (same stack -> same digest, many rounds) and
// collision-sensitive (any single-field change flips the representation digest).
func TestRepresentation_DeterministicAndCollisionSensitive(t *testing.T) {
	base := func(t *testing.T) agentstack.Representation {
		t.Helper()
		rep, err := agentstack.New([]byte("base prompt"),
			agentstack.NewToolManifest("fs.read", "net.http"),
			providerModel("anthropic/claude-x", "2026-01-01"))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		rep.Orchestrator = "orch/1.2.3"
		rep.Runtime = "runtime/4.5.6"
		return rep
	}

	// Determinism: the digest is identical across many independent constructions.
	want, err := base(t).Digest()
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	for i := 0; i < 64; i++ {
		got, err := base(t).Digest()
		if err != nil {
			t.Fatalf("Digest round %d: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("non-deterministic digest at round %d", i)
		}
	}

	// Collision-sensitivity: mutate exactly one field at a time; every mutation
	// must flip the digest.
	mutations := []struct {
		name   string
		mutate func(agentstack.Representation) (agentstack.Representation, error)
	}{
		{"prompt swap", func(r agentstack.Representation) (agentstack.Representation, error) {
			return agentstack.New([]byte("DIFFERENT prompt"),
				agentstack.NewToolManifest("fs.read", "net.http"),
				providerModel("anthropic/claude-x", "2026-01-01"))
		}},
		{"tool added", func(r agentstack.Representation) (agentstack.Representation, error) {
			return agentstack.New([]byte("base prompt"),
				agentstack.NewToolManifest("fs.read", "net.http", "db.query"),
				providerModel("anthropic/claude-x", "2026-01-01"))
		}},
		{"tool removed", func(r agentstack.Representation) (agentstack.Representation, error) {
			return agentstack.New([]byte("base prompt"),
				agentstack.NewToolManifest("fs.read"),
				providerModel("anthropic/claude-x", "2026-01-01"))
		}},
		{"model id swap", func(r agentstack.Representation) (agentstack.Representation, error) {
			return agentstack.New([]byte("base prompt"),
				agentstack.NewToolManifest("fs.read", "net.http"),
				providerModel("openai/gpt", "2026-01-01"))
		}},
		{"model version swap", func(r agentstack.Representation) (agentstack.Representation, error) {
			return agentstack.New([]byte("base prompt"),
				agentstack.NewToolManifest("fs.read", "net.http"),
				providerModel("anthropic/claude-x", "2026-02-02"))
		}},
		{"model form swap", func(r agentstack.Representation) (agentstack.Representation, error) {
			return agentstack.New([]byte("base prompt"),
				agentstack.NewToolManifest("fs.read", "net.http"),
				weightsModel([]byte("weights-digest-bytes")))
		}},
		{"orchestrator swap", func(r agentstack.Representation) (agentstack.Representation, error) {
			r.Orchestrator = "orch/9.9.9"
			return r, nil
		}},
		{"runtime swap", func(r agentstack.Representation) (agentstack.Representation, error) {
			r.Runtime = "runtime/0.0.1"
			return r, nil
		}},
	}
	for _, m := range mutations {
		t.Run(m.name, func(t *testing.T) {
			mutated, err := m.mutate(base(t))
			if err != nil {
				t.Fatalf("mutate: %v", err)
			}
			got, err := mutated.Digest()
			if err != nil {
				t.Fatalf("Digest: %v", err)
			}
			if bytes.Equal(got, want) {
				t.Fatalf("single-field change %q did NOT flip the representation digest", m.name)
			}
		})
	}
}

// TestRepresentation_RandomizedDeterminism randomly builds representations and
// checks the digest is stable across two independent constructions of the same
// stack (a stronger property-style sweep).
func TestRepresentation_RandomizedDeterminism(t *testing.T) {
	rng := proptest.New(1)
	toolPool := []string{"fs.read", "fs.write", "net.http", "db.query", "shell.exec", "kv.get"}
	for i := 0; i < 200; i++ {
		prompt := make([]byte, 1+rng.Intn(64))
		for j := range prompt {
			prompt[j] = byte(rng.Intn(256))
		}
		n := rng.Intn(len(toolPool) + 1)
		tools := append([]string(nil), toolPool[:n]...)
		rng.Shuffle(len(tools), func(a, b int) { tools[a], tools[b] = tools[b], tools[a] })

		var model agentstack.Model
		if rng.Intn(2) == 0 {
			wd := make([]byte, 32)
			_, _ = rng.Read(wd)
			model = weightsModel(wd)
		} else {
			model = providerModel("prov/model", "vX")
		}

		r1, err := agentstack.New(append([]byte(nil), prompt...), agentstack.NewToolManifest(tools...), model)
		if err != nil {
			t.Fatalf("New a: %v", err)
		}
		// Reconstruct the same stack with a re-shuffled tool declaration.
		rng.Shuffle(len(tools), func(a, b int) { tools[a], tools[b] = tools[b], tools[a] })
		r2, err := agentstack.New(append([]byte(nil), prompt...), agentstack.NewToolManifest(tools...), model)
		if err != nil {
			t.Fatalf("New b: %v", err)
		}
		d1, _ := r1.Digest()
		d2, _ := r2.Digest()
		if !bytes.Equal(d1, d2) {
			t.Fatalf("round %d: same stack produced different digests", i)
		}
	}
}
