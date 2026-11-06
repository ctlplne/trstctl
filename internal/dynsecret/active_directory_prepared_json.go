// SPDX-License-Identifier: BUSL-1.1
package dynsecret

import (
	"bytes"
	"encoding/json"
	"errors"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// Preparation is a flat, canonical field set. Scan raw slices before typed
// Unmarshal so duplicate/escaped/case-alias keys cannot change authority, and a
// Decoder does not retain a second unwipeable copy of the credential document.
func validateADPreparationFields(raw []byte) error {
	if len(raw) == 0 || len(raw) > 64<<10 || !json.Valid(raw) {
		return errors.New("dynsecret AD: invalid preparation JSON")
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) < 2 || raw[0] != '{' || raw[len(raw)-1] != '}' {
		return errors.New("dynsecret AD: preparation must be an object")
	}
	names := []string{"version", "role", "operation_id", "predecessor", "provider_binding", "bind_dn", "username", "native_guid", "native_sid", "password_set_at", "password"}
	seen := uint16(0)
	i := adJSONSpace(raw, 1)
	for i < len(raw)-1 {
		end := adJSONStringEnd(raw, i)
		if end < 0 || end-i > 64 {
			return errors.New("dynsecret AD: invalid preparation key")
		}
		index := -1
		for n, name := range names {
			if len(name) == end-i-2 && bytes.Equal(raw[i+1:end-1], []byte(name)) {
				index = n
				break
			}
		}
		if index < 0 || seen&(1<<index) != 0 {
			return errors.New("dynsecret AD: unknown, duplicate or alternate preparation key")
		}
		seen |= 1 << index
		i = adJSONSpace(raw, end)
		if i >= len(raw) || raw[i] != ':' {
			return errors.New("dynsecret AD: invalid preparation field")
		}
		i = adJSONSpace(raw, i+1)
		if i >= len(raw) {
			return errors.New("dynsecret AD: missing preparation value")
		}
		if raw[i] == '"' {
			i = adJSONStringEnd(raw, i)
			if i < 0 {
				return errors.New("dynsecret AD: invalid preparation string")
			}
		} else {
			if raw[i] != '-' && (raw[i] < '0' || raw[i] > '9') {
				return errors.New("dynsecret AD: preparation values must be scalar")
			}
			for i < len(raw) && raw[i] != ',' && raw[i] != '}' {
				i++
			}
		}
		i = adJSONSpace(raw, i)
		if i == len(raw)-1 && raw[i] == '}' {
			return nil
		}
		if i >= len(raw) || raw[i] != ',' {
			return errors.New("dynsecret AD: invalid preparation separator")
		}
		i = adJSONSpace(raw, i+1)
	}
	return nil
}
func adJSONSpace(raw []byte, i int) int {
	for i < len(raw) {
		switch raw[i] {
		case ' ', '\t', '\r', '\n':
			i++
		default:
			return i
		}
	}
	return i
}
func adJSONStringEnd(raw []byte, i int) int {
	if i >= len(raw) || raw[i] != '"' {
		return -1
	}
	for i = i + 1; i < len(raw); i++ {
		if raw[i] == '\\' {
			i++
			continue
		}
		if raw[i] == '"' {
			return i + 1
		}
	}
	return -1
}

// Only public metadata goes through encoding/json's pooled encoder. Secret
// quoting uses an owned byte slice, which is wiped after the final wire copy.
func marshalADStaticPreparation(p adStaticPreparation) ([]byte, error) {
	password := p.Password
	p.Password = nil
	metadata, err := json.Marshal(p) // #nosec G117 -- password is cleared/omitted before the public-only marshal; native password stamp is public metadata (CWE-200)
	if err != nil {
		return nil, err
	}
	return appendADCredentialPassword(metadata, password)
}
func appendADCredentialPassword(metadata, password []byte) ([]byte, error) {
	if len(metadata) < 2 || metadata[0] != '{' || metadata[len(metadata)-1] != '}' {
		return nil, errors.New("dynsecret AD: credential metadata is not an object")
	}
	quoted, err := secret.JSONBytes(password).MarshalJSON()
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(quoted)
	field := []byte(`,"password":`)
	out := make([]byte, len(metadata)-1+len(field)+len(quoted)+1)
	i := copy(out, metadata[:len(metadata)-1])
	i += copy(out[i:], field)
	i += copy(out[i:], quoted)
	out[i] = '}'
	return out, nil
}
