// SPDX-License-Identifier: BUSL-1.1

package accessrules

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"trstctl.com/trstctl/internal/crypto"
)

// UnmarshalJSON keeps the frozen policy vocabulary closed, including nested
// rule facts. A future policy cannot silently lose fields on an older gateway.
func (p *Policy) UnmarshalJSON(raw []byte) error {
	if len(raw) > 128<<10 {
		return errors.New("command rules: policy JSON exceeds its bound")
	}
	type wire Policy
	var value wire
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return errors.New("command rules: invalid policy JSON")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errors.New("command rules: trailing policy JSON")
	}
	*p = Policy(value)
	return nil
}

// PolicyDigest binds the exact public enforcement snapshot. Message hashing
// likewise uses internal/crypto; the matcher has no cryptographic backend.
func PolicyDigest(p *Policy) (string, error) {
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	return crypto.SHA256Hex(append([]byte("trstctl:pam-command-policy:v1\x00"), raw...)), nil
}
