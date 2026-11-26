// SPDX-License-Identifier: BUSL-1.1

// Package approvalresource gives approval creation and review one exact name
// mapping. Approval intents are trimmed before storage, while secret names can
// contain edge whitespace; those names need an unambiguous encoded namespace.
package approvalresource

import (
	"encoding/base64"
	"strconv"
	"strings"
	"unicode/utf8"
)

const encodedSecretPrefix = "secret-name-b64:"
const legacySecretPrefix = "secret:"

// SecretID preserves legacy IDs for ordinary names and encodes names whose
// edge whitespace would be lost by approval intent canonicalization.
func SecretID(name string) string {
	if strings.TrimSpace(name) != name {
		return encodedSecretPrefix + base64.RawURLEncoding.EncodeToString([]byte(name))
	}
	return legacySecretPrefix + name
}

// SecretDisplayName keeps edge whitespace visible in review UI and logs.
func SecretDisplayName(name string) string {
	if strings.TrimSpace(name) != name {
		return strconv.Quote(name)
	}
	return name
}

// DecodeSecretID returns the exact storage name for an approval target.
func DecodeSecretID(id string) (string, bool) {
	if raw, ok := strings.CutPrefix(id, encodedSecretPrefix); ok {
		decoded, err := base64.RawURLEncoding.DecodeString(raw)
		if err != nil || len(decoded) == 0 {
			return "", false
		}
		name := string(decoded)
		if !utf8.ValidString(name) || SecretID(name) != id {
			return "", false
		}
		return name, true
	}
	name, ok := strings.CutPrefix(id, legacySecretPrefix)
	return name, ok && name != "" && SecretID(name) == id
}
