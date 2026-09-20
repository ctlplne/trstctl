// SPDX-License-Identifier: BUSL-1.1

package verify

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
)

// agentstack_repr.go recovers the bound agent-stack DIGESTS from the OPAQUE
// representation bytes the carriage forms transport (BoundValues.AgentStackRepr).
// It accepts both internal/agentid/agentstack.Representation.CanonicalBytes() and the deployed
// JSON representation shape the signer gate minimally validates. The AGID-08 carriage
// package deliberately carries those bytes opaque so the relying-party verifier stays
// dependency-light -- in particular it need NOT import internal/agentid/agentstack, which pulls
// internal/attest (and, natively, database/sql) and would bloat the WASM build. This file
// therefore re-derives only what a relying party needs -- the system-prompt digest, the
// tool-manifest digest, and the model block -- with tiny, allocation-BOUNDED, panic-FREE
// decoders.
//
// It is an UNTRUSTED-INPUT surface (the repr bytes arrive inside a caller-supplied
// credential, before the signature is trusted), so every read is bounds-checked
// and a hostile length header can only produce ErrMalformedRepr, never a panic or
// a huge allocation -- matching agentstack/parse.go's discipline. AN-3: it names
// no crypto/* package; the only hash it computes (the tool-manifest digest, to
// enforce AGID-claim-29) routes through internal/crypto.

// These constants MIRROR internal/agentid/agentstack's canonical framing. They are
// duplicated here (rather than imported) precisely to keep this package from
// importing agentstack; a differential/conformance test asserts a repr this
// decoder accepts yields the same digests the agentstack package produced, so a
// drift in the framing is caught rather than silently tolerated.
const (
	reprCanonicalPrefix      = "agid/agentstack/v1"
	toolManifestDigestDomain = "agid/agentstack/tool-manifest/v1"
)

// model-form tags mirror agentstack.ModelForm (AGID-claim-11): 0 unset (rejected), 1
// weights-digest, 2 provider-id.
const (
	modelFormUnset         = 0
	modelFormWeightsDigest = 1
	modelFormProviderID    = 2
)

// reprMaxDecodeLen bounds any single length-prefixed element so a hostile length
// header cannot request a huge allocation. It mirrors agentstack/parse.go's
// maxDecodeLen (1 MiB): far larger than any legitimate field yet small enough to
// make resource exhaustion via the length prefix impossible.
const reprMaxDecodeLen = 1 << 20

// ErrMalformedRepr is returned when the opaque agent-stack representation bytes
// cannot be decoded to the bound digests: wrong prefix, an unexpected field, a
// length that overruns the buffer, an unset/unknown model form, or trailing
// bytes. Fail-closed: a credential whose bound representation cannot be decoded is
// never treated as matching any policy.
var ErrMalformedRepr = errors.New("verify: malformed agent-stack representation bytes")

// boundRepr is the subset of the bound agent-stack representation a relying party
// evaluates: the two component digests and the model block. It carries only
// digests and non-secret identifiers (never a raw prompt), so it is safe to hold
// and compare. The model block is recovered so a policy may pin the model too.
type boundRepr struct {
	SystemPromptDigest []byte
	ToolManifestDigest []byte
	ModelForm          uint8
	ModelWeightsDigest []byte
	ModelProviderID    string
	ModelVersion       string
	Orchestrator       string
	Runtime            string
}

// decodeBoundRepr decodes opaque representation bytes into the bound digests. It is
// fail-closed and never panics on hostile input; any structural error yields
// ErrMalformedRepr and a zero value. The canonical decoder requires exact framing and no
// trailing bytes; the JSON decoder requires the deployed representation fields and model
// form to be complete.
func decodeBoundRepr(repr []byte) (boundRepr, error) {
	d := &reprDecoder{buf: repr}
	if !d.expectPrefix(reprCanonicalPrefix) {
		return decodeJSONBoundRepr(repr)
	}
	var r boundRepr

	if !d.expectField("system_prompt_digest") {
		return boundRepr{}, ErrMalformedRepr
	}
	sp, ok := d.readBytes()
	if !ok {
		return boundRepr{}, ErrMalformedRepr
	}
	r.SystemPromptDigest = sp

	if !d.expectField("tool_manifest_digest") {
		return boundRepr{}, ErrMalformedRepr
	}
	tm, ok := d.readBytes()
	if !ok {
		return boundRepr{}, ErrMalformedRepr
	}
	r.ToolManifestDigest = tm

	if !d.expectField("model") {
		return boundRepr{}, ErrMalformedRepr
	}
	form, ok := d.readByte()
	if !ok {
		return boundRepr{}, ErrMalformedRepr
	}
	r.ModelForm = form
	switch form {
	case modelFormWeightsDigest:
		if !d.expectField("weights_digest") {
			return boundRepr{}, ErrMalformedRepr
		}
		wd, ok := d.readBytes()
		if !ok {
			return boundRepr{}, ErrMalformedRepr
		}
		r.ModelWeightsDigest = wd
	case modelFormProviderID:
		if !d.expectField("provider_model_id") {
			return boundRepr{}, ErrMalformedRepr
		}
		id, ok := d.readString()
		if !ok {
			return boundRepr{}, ErrMalformedRepr
		}
		r.ModelProviderID = id
		if !d.expectField("model_version") {
			return boundRepr{}, ErrMalformedRepr
		}
		ver, ok := d.readString()
		if !ok {
			return boundRepr{}, ErrMalformedRepr
		}
		r.ModelVersion = ver
	default:
		// Unset (0) or unknown form: fail closed (AGID-claim-11 -- the indicator cannot
		// be omitted or bogus).
		return boundRepr{}, ErrMalformedRepr
	}

	if !d.expectField("orchestrator") {
		return boundRepr{}, ErrMalformedRepr
	}
	orch, ok := d.readString()
	if !ok {
		return boundRepr{}, ErrMalformedRepr
	}
	r.Orchestrator = orch

	if !d.expectField("runtime") {
		return boundRepr{}, ErrMalformedRepr
	}
	rt, ok := d.readString()
	if !ok {
		return boundRepr{}, ErrMalformedRepr
	}
	r.Runtime = rt

	if !d.atEnd() {
		return boundRepr{}, ErrMalformedRepr
	}
	if len(r.SystemPromptDigest) == 0 || len(r.ToolManifestDigest) == 0 {
		// A representation missing a component digest is not well-formed (AGID-03
		// Validate would reject it); fail closed.
		return boundRepr{}, ErrMalformedRepr
	}
	return r, nil
}

func decodeJSONBoundRepr(repr []byte) (boundRepr, error) {
	var jr struct {
		SystemPromptDigest []byte `json:"system_prompt_digest"`
		ToolManifestDigest []byte `json:"tool_manifest_digest"`
		Model              struct {
			Form            uint8  `json:"form"`
			WeightsDigest   []byte `json:"weights_digest,omitempty"`
			ProviderModelID string `json:"provider_model_id,omitempty"`
			ModelVersion    string `json:"model_version,omitempty"`
		} `json:"model"`
		Orchestrator string `json:"orchestrator,omitempty"`
		Runtime      string `json:"runtime,omitempty"`
	}
	if err := json.Unmarshal(repr, &jr); err != nil {
		return boundRepr{}, ErrMalformedRepr
	}
	r := boundRepr{
		SystemPromptDigest: append([]byte(nil), jr.SystemPromptDigest...),
		ToolManifestDigest: append([]byte(nil), jr.ToolManifestDigest...),
		ModelForm:          jr.Model.Form,
		ModelWeightsDigest: append([]byte(nil), jr.Model.WeightsDigest...),
		ModelProviderID:    jr.Model.ProviderModelID,
		ModelVersion:       jr.Model.ModelVersion,
		Orchestrator:       jr.Orchestrator,
		Runtime:            jr.Runtime,
	}
	if len(r.SystemPromptDigest) == 0 || len(r.ToolManifestDigest) == 0 {
		return boundRepr{}, ErrMalformedRepr
	}
	switch r.ModelForm {
	case modelFormWeightsDigest:
		if len(r.ModelWeightsDigest) == 0 || r.ModelProviderID != "" || r.ModelVersion != "" {
			return boundRepr{}, ErrMalformedRepr
		}
	case modelFormProviderID:
		if len(r.ModelWeightsDigest) != 0 || r.ModelProviderID == "" || r.ModelVersion == "" {
			return boundRepr{}, ErrMalformedRepr
		}
	default:
		return boundRepr{}, ErrMalformedRepr
	}
	return r, nil
}

// toolManifestDigest recomputes the domain-separated digest of a tool list
// exactly as internal/agentid/agentstack.ToolManifest.Digest() does: normalize (trim +
// lowercase), de-duplicate, sort, then hash the domain tag over the count and the
// length-prefixed tools through internal/crypto (AN-3). A relying party supplies
// its APPROVED tool manifest (the tool list whose digest is bound in the
// representation); recomputing the digest here lets the verifier confirm the
// supplied manifest is the one bound, then confine an action to that manifest
// (AGID-claim-29). Recomputing (rather than importing agentstack) keeps the verifier
// dependency-light while guaranteeing the same digest for the same tool set.
func toolManifestDigest(tools []string) []byte {
	canon := canonicalTools(tools)
	// Mirror agentstack.ToolManifest.Digest's exact byte framing.
	buf := make([]byte, 0, len(toolManifestDigestDomain)+8+len(canon)*16)
	buf = append(buf, toolManifestDigestDomain...)
	var x [8]byte
	binary.BigEndian.PutUint64(x[:], uint64(len(canon)))
	buf = append(buf, x[:]...)
	for _, t := range canon {
		binary.BigEndian.PutUint64(x[:], uint64(len(t)))
		buf = append(buf, x[:]...)
		buf = append(buf, t...)
	}
	return crypto.SHA256Sum(buf)
}

// normTool mirrors agentstack.normTool: trim surrounding whitespace and
// lower-case, so tool identity compares the same on both sides.
func normTool(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// canonicalTools mirrors agentstack.canonicalTools: normalize, drop empties,
// de-duplicate, and sort, so the tool-manifest digest is order- and
// duplicate-independent.
func canonicalTools(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		n := normTool(s)
		if n == "" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// reprDecoder is a bounds-checked cursor over untrusted bytes, mirroring
// agentstack/parse.go's decoder: every read validates the requested length
// against the remaining buffer, so a hostile length prefix can only produce an
// error, never an out-of-range slice or a huge allocation.
type reprDecoder struct {
	buf []byte
	pos int
}

func (d *reprDecoder) remaining() int { return len(d.buf) - d.pos }

func (d *reprDecoder) atEnd() bool { return d.pos == len(d.buf) }

func (d *reprDecoder) expectPrefix(s string) bool {
	if d.remaining() < len(s) {
		return false
	}
	if string(d.buf[d.pos:d.pos+len(s)]) != s {
		return false
	}
	d.pos += len(s)
	return true
}

func (d *reprDecoder) expectField(name string) bool {
	got, ok := d.readString()
	return ok && got == name
}

func (d *reprDecoder) readByte() (byte, bool) {
	if d.remaining() < 1 {
		return 0, false
	}
	b := d.buf[d.pos]
	d.pos++
	return b, true
}

func (d *reprDecoder) readU64() (uint64, bool) {
	if d.remaining() < 8 {
		return 0, false
	}
	v := binary.BigEndian.Uint64(d.buf[d.pos : d.pos+8])
	d.pos += 8
	return v, true
}

func (d *reprDecoder) readBytes() ([]byte, bool) {
	n, ok := d.readU64()
	if !ok {
		return nil, false
	}
	// Bound the hostile length header against the allocation cap FIRST, so the
	// narrowing below is exact: n <= reprMaxDecodeLen (1 MiB) fits an int on every
	// platform this builds for. Only then compare it against what is actually left
	// in the buffer.
	if n > reprMaxDecodeLen {
		return nil, false
	}
	size := int(n)
	if size > d.remaining() {
		return nil, false
	}
	out := make([]byte, size)
	copy(out, d.buf[d.pos:d.pos+size])
	d.pos += size
	return out, true
}

func (d *reprDecoder) readString() (string, bool) {
	b, ok := d.readBytes()
	if !ok {
		return "", false
	}
	return string(b), true
}
