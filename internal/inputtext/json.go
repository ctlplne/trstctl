// SPDX-License-Identifier: BUSL-1.1

// Package inputtext checks untrusted text before it is written to an event or
// PostgreSQL projection. An escaped NUL is legal JSON but cannot fit a PostgreSQL
// text or jsonb value.
package inputtext

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"
)

var ErrNUL = errors.New("text contains NUL")
var ErrInvalidUTF8 = errors.New("text is not valid UTF-8")

// ValidateString checks one decoded field, including object keys and path values.
func ValidateString(s string) error {
	if strings.IndexByte(s, 0) >= 0 {
		return ErrNUL
	}
	if !utf8.ValidString(s) {
		return ErrInvalidUTF8
	}
	return nil
}

// ValidateJSONStrings checks every decoded string token in a JSON document. It
// leaves non-JSON opaque event data alone: existing events can carry binary
// bytes. The quick scan keeps the ordinary append path free of a second JSON
// tokenization.
func ValidateJSONStrings(raw []byte) error {
	if !utf8.Valid(raw) {
		if json.Valid(raw) {
			return ErrInvalidUTF8
		}
		return nil
	}
	if bytes.IndexByte(raw, 0) < 0 && !bytes.Contains(raw, []byte(`\u0000`)) {
		return nil
	}
	if !json.Valid(raw) {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	for {
		token, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if value, ok := token.(string); ok && strings.IndexByte(value, 0) >= 0 {
			return ErrNUL
		}
	}
}
