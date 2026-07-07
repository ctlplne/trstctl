// SPDX-License-Identifier: LicenseRef-trstctl-EE

package delegation

import (
	"encoding/json"
	"errors"
	"fmt"
)

// subject.go performs a MINIMAL, self-contained structural check of the opaque agent-stack
// representation bytes the seam forwards (SubjectRepr), WITHOUT importing
// ee/agentid/agentstack. That package transitively imports internal/attest ->
// internal/graph -> database/sql, which must never link into the isolated signer (AN-4).
// The full AGID-03 representation semantics (canonical byte-stability, model-form rules)
// are the CALLER's responsibility and are re-checkable by a relying party (AGID-09) with
// the agentstack package; the signer only needs to (a) confirm the representation is
// well-formed enough to bind (it carries the required digests) and (b) bind its exact
// bytes plus their digest so a byte-exact prompt/tool swap flips the binding.
//
// The gate treats the bytes as untrusted: a malformed or digest-less body is refused
// fail-closed with a signed refusal (no key op). The bytes are bound verbatim; the gate
// does not re-serialize them, so what the relying party decodes is exactly what was
// bound.

// ErrDecodeSubjectRepr is returned when the opaque SubjectRepr body cannot be structurally
// validated as an agent-stack representation. Fail-closed: it becomes a signed refusal, no
// key op.
var ErrDecodeSubjectRepr = errors.New("delegation: cannot decode agent-stack representation body")

// ErrReprMissingDigests is returned when a representation body decodes but is missing the
// system-prompt or tool-manifest digest the binding requires.
var ErrReprMissingDigests = errors.New("delegation: agent-stack representation missing prompt/tool digest")

// reprShape is the minimal shape the gate checks: the two component digests must be
// present. It intentionally mirrors only the fields the binding depends on (the AGID-03
// agentstack.Representation JSON), so the gate need not link the agentstack package. A
// relying party decodes the full representation with agentstack.
type reprShape struct {
	SystemPromptDigest []byte `json:"system_prompt_digest"`
	ToolManifestDigest []byte `json:"tool_manifest_digest"`
}

// validateReprBytes structurally validates the opaque representation bytes fail-closed: it
// must be a JSON object carrying a non-empty system-prompt digest and a non-empty
// tool-manifest digest (so the bound representation genuinely carries prompt+tool
// digests). It does NOT enforce the full model-form rules (that is the caller's / relying
// party's job via agentstack); it enforces only what the binding depends on.
func validateReprBytes(b []byte) error {
	var rs reprShape
	if err := json.Unmarshal(b, &rs); err != nil {
		return fmt.Errorf("%w: %v", ErrDecodeSubjectRepr, err)
	}
	if len(rs.SystemPromptDigest) == 0 || len(rs.ToolManifestDigest) == 0 {
		return ErrReprMissingDigests
	}
	return nil
}
