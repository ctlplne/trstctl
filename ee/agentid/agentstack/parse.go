// SPDX-License-Identifier: LicenseRef-trstctl-EE

package agentstack

import (
	"encoding/binary"
	"errors"
)

// parse.go decodes the canonical byte encoding produced by
// Representation.CanonicalBytes back into a Representation. It is the untrusted-
// input surface: a relying party (or a differential test) that received the
// canonical bytes parses them here, so this decoder must be robust against
// arbitrary, malicious, or truncated input — it never panics and always returns
// an error rather than a partially-populated representation (fail-closed). The
// package's fuzz test drives arbitrary bytes through Parse.
//
// Parse performs no key operation and no I/O.

// ErrMalformed is returned when the canonical bytes cannot be decoded: wrong
// prefix, a length that overruns the buffer, an unknown field, trailing bytes, or
// a decoded representation that fails validation.
var ErrMalformed = errors.New("agentstack: malformed canonical representation bytes")

// maxDecodeLen bounds any single length-prefixed element so a hostile length
// header cannot request a huge allocation. It is far larger than any legitimate
// field (a digest is 32 bytes; ids are short) yet small enough to make a
// resource-exhaustion attempt via the length prefix impossible.
const maxDecodeLen = 1 << 20 // 1 MiB

// Parse decodes canonical representation bytes (as produced by
// Representation.CanonicalBytes) into a Representation, validating the result. It
// is fail-closed: any structural error, any length that overruns the input, any
// unexpected field name or model-form tag, any trailing bytes, or a decoded
// representation that does not Validate yields ErrMalformed (wrapping the specific
// cause where useful) and a zero Representation. It never panics on hostile input.
func Parse(data []byte) (Representation, error) {
	d := &decoder{buf: data}

	if !d.expectPrefix(canonicalPrefix) {
		return Representation{}, ErrMalformed
	}

	var rep Representation

	if !d.expectField("system_prompt_digest") {
		return Representation{}, ErrMalformed
	}
	promptDigest, ok := d.readBytes()
	if !ok {
		return Representation{}, ErrMalformed
	}
	rep.SystemPromptDigest = promptDigest

	if !d.expectField("tool_manifest_digest") {
		return Representation{}, ErrMalformed
	}
	toolDigest, ok := d.readBytes()
	if !ok {
		return Representation{}, ErrMalformed
	}
	rep.ToolManifestDigest = toolDigest

	if !d.expectField("model") {
		return Representation{}, ErrMalformed
	}
	form, ok := d.readByte()
	if !ok {
		return Representation{}, ErrMalformed
	}
	rep.Model.Form = ModelForm(form)
	switch rep.Model.Form {
	case ModelFormWeightsDigest:
		if !d.expectField("weights_digest") {
			return Representation{}, ErrMalformed
		}
		wd, ok := d.readBytes()
		if !ok {
			return Representation{}, ErrMalformed
		}
		rep.Model.WeightsDigest = wd
	case ModelFormProviderID:
		if !d.expectField("provider_model_id") {
			return Representation{}, ErrMalformed
		}
		id, ok := d.readString()
		if !ok {
			return Representation{}, ErrMalformed
		}
		rep.Model.ProviderModelID = id
		if !d.expectField("model_version") {
			return Representation{}, ErrMalformed
		}
		ver, ok := d.readString()
		if !ok {
			return Representation{}, ErrMalformed
		}
		rep.Model.ModelVersion = ver
	default:
		// Unset or unknown form tag: fail closed rather than accept an
		// indicator-less or bogus model (AGID-claim-11).
		return Representation{}, ErrMalformed
	}

	if !d.expectField("orchestrator") {
		return Representation{}, ErrMalformed
	}
	orch, ok := d.readString()
	if !ok {
		return Representation{}, ErrMalformed
	}
	rep.Orchestrator = orch

	if !d.expectField("runtime") {
		return Representation{}, ErrMalformed
	}
	rt, ok := d.readString()
	if !ok {
		return Representation{}, ErrMalformed
	}
	rep.Runtime = rt

	if !d.atEnd() {
		// Trailing bytes after a complete representation: fail closed.
		return Representation{}, ErrMalformed
	}
	if err := rep.Validate(); err != nil {
		return Representation{}, errors.Join(ErrMalformed, err)
	}
	return rep, nil
}

// decoder is a bounds-checked cursor over untrusted bytes. Every read validates
// the requested length against the remaining buffer, so a hostile length prefix
// can only produce an error, never an out-of-range slice or a huge allocation.
type decoder struct {
	buf []byte
	pos int
}

func (d *decoder) remaining() int { return len(d.buf) - d.pos }

func (d *decoder) atEnd() bool { return d.pos == len(d.buf) }

// expectPrefix consumes and matches a fixed, unframed prefix string.
func (d *decoder) expectPrefix(s string) bool {
	if d.remaining() < len(s) {
		return false
	}
	if string(d.buf[d.pos:d.pos+len(s)]) != s {
		return false
	}
	d.pos += len(s)
	return true
}

// expectField reads a length-prefixed string and matches it against the expected
// field name.
func (d *decoder) expectField(name string) bool {
	got, ok := d.readString()
	return ok && got == name
}

func (d *decoder) readByte() (byte, bool) {
	if d.remaining() < 1 {
		return 0, false
	}
	b := d.buf[d.pos]
	d.pos++
	return b, true
}

// readU64 reads a big-endian uint64 length prefix.
func (d *decoder) readU64() (uint64, bool) {
	if d.remaining() < 8 {
		return 0, false
	}
	v := binary.BigEndian.Uint64(d.buf[d.pos : d.pos+8])
	d.pos += 8
	return v, true
}

// readBytes reads a length-prefixed byte string, bounded by maxDecodeLen and the
// remaining buffer. It returns a copy so the returned slice does not alias the
// input buffer.
func (d *decoder) readBytes() ([]byte, bool) {
	n, ok := d.readU64()
	if !ok {
		return nil, false
	}
	if n > maxDecodeLen || n > uint64(d.remaining()) {
		return nil, false
	}
	out := make([]byte, n)
	copy(out, d.buf[d.pos:d.pos+int(n)])
	d.pos += int(n)
	return out, true
}

// readString reads a length-prefixed UTF-8 (opaque) string with the same bounds
// as readBytes.
func (d *decoder) readString() (string, bool) {
	b, ok := d.readBytes()
	if !ok {
		return "", false
	}
	return string(b), true
}
