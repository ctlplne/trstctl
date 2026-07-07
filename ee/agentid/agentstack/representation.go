// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package agentstack defines the AGID agent-stack representation (§4.1): the
// bound description of what an autonomous agent actually is — a digest of its
// canonicalized system prompt, a digest of the sorted tool manifest it is
// configured with, a model identifier in exactly one of two mutually exclusive
// forms (a model-weights digest for locally hosted weights OR a provider model
// id + version when weights are not exposed) together with an explicit
// indicator of which form is present, and the orchestrator/runtime version
// identifiers (claims 11, 27-repr; establishing INV-A3, the representation +
// tool-manifest-excess half).
//
// The representation is CANONICAL and byte-stable: the same agent stack yields
// identical CanonicalBytes across runs, machines, and architectures (fixed
// big-endian widths, length-prefixed strings, sorted sets), mirroring AGID-01's
// authority-canonicalization discipline so a later verifier (AGID-04, the
// relying-party verifier AGID-09) can reproduce a digest deterministically. Any
// single-field change — a prompt swap, a model swap, or a tool-set change —
// flips the representation (§4.4).
//
// This package is representation + digesting + manifest-comparison predicate
// only. It performs NO private-key operation and never mints: INV-A1 is
// preserved here by construction (this package holds no issuance key and calls
// no signer). Binding the representation into a credential and minting the
// signed tool-manifest refusal record are AGID-04's job, inside the AN-4
// signer; the carriage encodings are AGID-08. All hashing routes through the
// core internal/crypto AN-3 boundary; no crypto/* is imported here. Any
// secret-class input (a raw system prompt before digesting) is held in an
// internal/crypto/secret locked, zeroizable buffer (AN-8) — never a string —
// and its plaintext is never logged; the representation itself stores only
// digests, which are safe to carry. This package is proprietary
// Enterprise/Provider material under the ee/ fence; core never imports it.
package agentstack

import (
	"bytes"
	"encoding/binary"
	"errors"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// RepresentationVersion identifies the exact semantics of the canonical
// encoding and digesting rules below, so a later verifier (AGID-04, AGID-09) can
// reproduce a digest deterministically. Bump this string whenever the encoding
// or any field's contribution changes; a recorded digest is only reproducible
// against a matching version.
const RepresentationVersion = "agid.agentstack/v1"

// canonicalPrefix domain-separates the canonical agent-stack encoding from every
// other hashed structure in the repo (it is part of the v1 semantics named
// above). It intentionally differs from delegation's authority prefix so an
// authority digest can never collide with an agent-stack digest.
const canonicalPrefix = "agid/agentstack/v1"

// promptDigestDomain and toolManifestDigestDomain domain-separate the two
// component digests so a system-prompt digest can never be confused with a
// tool-manifest digest, and neither collides with a bare SHA-256 of the same
// bytes.
const (
	promptDigestDomain       = "agid/agentstack/system-prompt/v1"
	toolManifestDigestDomain = "agid/agentstack/tool-manifest/v1"
)

// ModelForm is the explicit indicator (claim 11) of which of the two mutually
// exclusive model-identifier forms a Representation carries. Exactly one form is
// present; the indicator round-trips through CanonicalBytes and cannot be
// omitted (the unset zero value is rejected by Validate).
type ModelForm uint8

const (
	// ModelFormUnset is the zero value and is never a valid representation: a
	// representation with no declared model form is rejected fail-closed, so the
	// indicator cannot be silently omitted (claim 11).
	ModelFormUnset ModelForm = 0
	// ModelFormWeightsDigest indicates the model is identified by a digest of its
	// locally hosted weights (WeightsDigest is set; ProviderModelID/ModelVersion
	// are empty).
	ModelFormWeightsDigest ModelForm = 1
	// ModelFormProviderID indicates the model is identified by a provider model id
	// plus a version (ProviderModelID and ModelVersion are set; WeightsDigest is
	// empty) — the case where the weights are not exposed.
	ModelFormProviderID ModelForm = 2
)

// String renders the indicator for reports and errors (never a secret).
func (f ModelForm) String() string {
	switch f {
	case ModelFormWeightsDigest:
		return "weights-digest"
	case ModelFormProviderID:
		return "provider-id"
	default:
		return "unset"
	}
}

// Model is the model-identifier component of a Representation in EXACTLY ONE of
// two forms, tagged by an explicit Form indicator (claim 11). WeightsDigest is a
// raw digest (typically SHA-256 of the weights) computed by the caller outside
// this package. ProviderModelID/ModelVersion are non-secret opaque identifiers
// (for example "anthropic/claude-x" and "2026-01-01"). None of these fields is
// secret-class, so they are plain (byte/string) fields — only the raw system
// prompt is secret-class and it never lives on this struct.
type Model struct {
	Form            ModelForm `json:"form"`
	WeightsDigest   []byte    `json:"weights_digest,omitempty"`
	ProviderModelID string    `json:"provider_model_id,omitempty"`
	ModelVersion    string    `json:"model_version,omitempty"`
}

// Representation is the canonical agent-stack representation (§4.1). It stores
// ONLY digests and non-secret identifiers, so a Representation is safe to carry,
// serialize, and bind into a credential (AGID-04). Build one with New from a
// raw (secret-class) system prompt and a tool manifest; the raw prompt is
// digested through a locked buffer and never retained.
//
// SystemPromptDigest is the domain-separated digest of the canonicalized system
// prompt. ToolManifestDigest is the domain-separated digest of the sorted,
// de-duplicated tool manifest. Model carries the model identifier in exactly one
// form with its indicator. Orchestrator and Runtime are non-secret version
// identifiers of the orchestrator and agent runtime that produced this stack.
type Representation struct {
	SystemPromptDigest []byte `json:"system_prompt_digest"`
	ToolManifestDigest []byte `json:"tool_manifest_digest"`
	Model              Model  `json:"model"`
	Orchestrator       string `json:"orchestrator,omitempty"`
	Runtime            string `json:"runtime,omitempty"`
}

// Errors returned when a representation or its inputs are malformed. All are
// fail-closed: a representation that cannot be validated is never treated as
// acceptable.
var (
	// ErrNoSystemPrompt is returned by New when the raw system prompt is empty.
	// An agent stack must have a system prompt to digest.
	ErrNoSystemPrompt = errors.New("agentstack: system prompt is empty")
	// ErrMissingPromptDigest is returned by Validate when the representation lacks
	// a system-prompt digest.
	ErrMissingPromptDigest = errors.New("agentstack: representation missing system-prompt digest")
	// ErrMissingToolDigest is returned by Validate when the representation lacks a
	// tool-manifest digest.
	ErrMissingToolDigest = errors.New("agentstack: representation missing tool-manifest digest")
	// ErrModelFormUnset is returned when the model-form indicator is unset — the
	// indicator cannot be omitted (claim 11).
	ErrModelFormUnset = errors.New("agentstack: model form indicator is unset (claim 11)")
	// ErrModelFormAmbiguous is returned when the model carries fields for more than
	// one form (e.g. both a weights digest and a provider id), so the single-form
	// rule is violated.
	ErrModelFormAmbiguous = errors.New("agentstack: model identifier present in more than one form (claim 11)")
	// ErrModelFormIncomplete is returned when the declared form's required fields
	// are absent (e.g. ModelFormProviderID without a provider id or version).
	ErrModelFormIncomplete = errors.New("agentstack: model identifier incomplete for its declared form (claim 11)")
	// ErrUnknownModelForm is returned when the model-form indicator is not one of
	// the two defined forms.
	ErrUnknownModelForm = errors.New("agentstack: unknown model form indicator")
)

// New builds a canonical Representation from a raw, secret-class system prompt,
// a tool manifest, and a model identifier. The raw prompt is copied into an
// internal/crypto/secret locked, zeroizable buffer, canonicalized and digested
// through the AN-3 crypto boundary, and the buffer is destroyed before New
// returns — the plaintext prompt is never retained on the struct nor logged
// (AN-8). The tool manifest is sorted and de-duplicated before digesting so
// declaration order and duplicates do not change the digest. New validates the
// model form (claim 11) and returns an error rather than an invalid
// representation (fail-closed).
//
// New performs NO key operation: the digests route through crypto.SHA256Sum
// only. rawSystemPrompt is not modified; callers that want their own copy wiped
// should wipe it after New returns.
func New(rawSystemPrompt []byte, manifest ToolManifest, model Model) (Representation, error) {
	if len(rawSystemPrompt) == 0 {
		return Representation{}, ErrNoSystemPrompt
	}
	if err := model.Validate(); err != nil {
		return Representation{}, err
	}
	promptDigest, err := digestSystemPrompt(rawSystemPrompt)
	if err != nil {
		return Representation{}, err
	}
	rep := Representation{
		SystemPromptDigest: promptDigest,
		ToolManifestDigest: manifest.Digest(),
		Model:              model.canonical(),
	}
	return rep, nil
}

// digestSystemPrompt copies the raw prompt into a locked secret buffer, digests
// the domain-separated, length-prefixed canonical prompt bytes through the AN-3
// boundary, and destroys the buffer. The prompt bytes are treated as an opaque
// byte string (no normalization is applied to prompt CONTENT — a byte-exact
// prompt swap must flip the digest); "canonicalization" here is the stable,
// domain-separated framing, not content mangling.
func digestSystemPrompt(rawSystemPrompt []byte) ([]byte, error) {
	buf, err := secret.NewFrom(rawSystemPrompt)
	if err != nil {
		return nil, err
	}
	defer buf.Destroy()
	var b bytes.Buffer
	b.WriteString(promptDigestDomain)
	writeBytes(&b, buf.Bytes())
	sum := crypto.SHA256Sum(b.Bytes())
	// Wipe the transient framing buffer that briefly held the plaintext prompt
	// alongside the domain tag, so no unlocked copy of the prompt survives.
	secret.Wipe(b.Bytes())
	return sum, nil
}

// Validate reports whether m is a well-formed model identifier under the
// single-form rule (claim 11): exactly one form is declared and complete, the
// indicator is one of the two defined forms, and no fields for the other form
// are set. It is fail-closed — an unset or ambiguous form is an error.
func (m Model) Validate() error {
	hasWeights := len(m.WeightsDigest) > 0
	hasProvider := m.ProviderModelID != "" || m.ModelVersion != ""
	switch m.Form {
	case ModelFormUnset:
		return ErrModelFormUnset
	case ModelFormWeightsDigest:
		if hasProvider {
			return ErrModelFormAmbiguous
		}
		if !hasWeights {
			return ErrModelFormIncomplete
		}
		return nil
	case ModelFormProviderID:
		if hasWeights {
			return ErrModelFormAmbiguous
		}
		if m.ProviderModelID == "" || m.ModelVersion == "" {
			return ErrModelFormIncomplete
		}
		return nil
	default:
		return ErrUnknownModelForm
	}
}

// canonical returns a copy of m with the fields of the non-declared form cleared,
// so the canonical encoding contributes only the declared form. Validate must
// have passed.
func (m Model) canonical() Model {
	switch m.Form {
	case ModelFormWeightsDigest:
		return Model{Form: m.Form, WeightsDigest: append([]byte(nil), m.WeightsDigest...)}
	case ModelFormProviderID:
		return Model{Form: m.Form, ProviderModelID: m.ProviderModelID, ModelVersion: m.ModelVersion}
	default:
		return Model{Form: m.Form}
	}
}

// Validate reports whether a representation is well-formed: it carries both
// component digests and a valid single-form model identifier (claim 11 / §4.1).
// It is fail-closed and performs no key operation.
func (r Representation) Validate() error {
	if len(r.SystemPromptDigest) == 0 {
		return ErrMissingPromptDigest
	}
	if len(r.ToolManifestDigest) == 0 {
		return ErrMissingToolDigest
	}
	return r.Model.Validate()
}

// CanonicalBytes returns the stable, deterministic byte encoding of the
// representation. The same agent stack — regardless of the transient
// declaration order of its tool manifest or the machine that built it — produces
// identical bytes across runs, machines, and architectures (fixed big-endian
// widths, length-prefixed byte strings, an explicit model-form tag). A digest or
// signature (AGID-04) binds these bytes. The encoding is part of the versioned
// semantics named by RepresentationVersion. Any single-field change flips the
// bytes: a different prompt changes SystemPromptDigest, a different tool set
// changes ToolManifestDigest, a model swap changes the model block (including its
// form tag), and different orchestrator/runtime ids change their fields.
//
// CanonicalBytes fails closed on an invalid representation (missing digest or an
// unset/ambiguous model form) rather than emitting ambiguous bytes.
func (r Representation) CanonicalBytes() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	b.WriteString(canonicalPrefix)
	writeField(&b, "system_prompt_digest")
	writeBytes(&b, r.SystemPromptDigest)
	writeField(&b, "tool_manifest_digest")
	writeBytes(&b, r.ToolManifestDigest)
	// model block: an explicit one-byte form tag then the declared form's fields,
	// so the indicator itself is bound and a form swap flips the bytes (claim 11).
	writeField(&b, "model")
	b.WriteByte(byte(r.Model.Form))
	switch r.Model.Form {
	case ModelFormWeightsDigest:
		writeField(&b, "weights_digest")
		writeBytes(&b, r.Model.WeightsDigest)
	case ModelFormProviderID:
		writeField(&b, "provider_model_id")
		writeStr(&b, r.Model.ProviderModelID)
		writeField(&b, "model_version")
		writeStr(&b, r.Model.ModelVersion)
	}
	writeField(&b, "orchestrator")
	writeStr(&b, r.Orchestrator)
	writeField(&b, "runtime")
	writeStr(&b, r.Runtime)
	return b.Bytes(), nil
}

// Digest returns the SHA-256 of the representation's canonical bytes, routed
// through the internal/crypto AN-3 boundary. This is the agent-stack digest that
// AGID-04 binds into the issued credential (matching the store's
// AgentStackDigest column from AGID-02). It performs no key operation.
func (r Representation) Digest() ([]byte, error) {
	cb, err := r.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	return crypto.SHA256Sum(cb), nil
}

// --- canonical encoding primitives (mirroring delegation/authority.go) ---

func writeField(b *bytes.Buffer, name string) { writeStr(b, name) }

func writeStr(b *bytes.Buffer, s string) {
	writeU64(b, uint64(len(s)))
	b.WriteString(s)
}

func writeBytes(b *bytes.Buffer, p []byte) {
	writeU64(b, uint64(len(p)))
	b.Write(p)
}

func writeU64(b *bytes.Buffer, v uint64) {
	var x [8]byte
	binary.BigEndian.PutUint64(x[:], v)
	b.Write(x[:])
}
