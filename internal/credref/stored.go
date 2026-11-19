// SPDX-License-Identifier: BUSL-1.1

// Package credref parses references to values in the tenant secret store.
package credref

import (
	"errors"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const storedPrefix = "secret://"

var ErrStoredFormat = errors.New("credential reference must use canonical secret://name or secret://name?version=N")

// Stored names one tenant secret and optionally pins a positive immutable version.
type Stored struct {
	Name    string
	Version *int

	literalName string
}

// LegacyLiteralName reports the different name an older literal reader would
// have used. It is only for detecting a conflict, never for credential lookup.
func (s Stored) LegacyLiteralName() string { return s.literalName }

// IsStored identifies candidates for parsing. Detection also identifies scheme
// aliases so that walking a nested document cannot miss a malformed reference.
func IsStored(raw string) bool {
	scheme, _, found := strings.Cut(strings.TrimSpace(raw), ":")
	return found && strings.EqualFold(scheme, "secret")
}

type invalidStoredAlias struct{ name string }

func (e *invalidStoredAlias) Error() string { return ErrStoredFormat.Error() }
func (e *invalidStoredAlias) Unwrap() error { return ErrStoredFormat }

// NameForDenial identifies a name from a recognizable invalid legacy spelling.
// It preserves an environment denial for that name. Parsing still failed and
// the name must never be used for grant or retrieval.
func NameForDenial(err error) string {
	var alias *invalidStoredAlias
	if errors.As(err, &alias) {
		return alias.name
	}
	return ""
}

var storedFirstSegmentEscapes = strings.NewReplacer(":", "%3A", "@", "%40")

// Parse accepts a lowercase scheme, a nonempty slash-delimited name in its
// canonical path spelling, and at most one positive decimal version. Optional
// surrounding whitespace is accepted at the input boundary.
func Parse(raw string) (Stored, error) {
	body, ok := strings.CutPrefix(strings.TrimSpace(raw), storedPrefix)
	if !ok || strings.Contains(body, "#") {
		return Stored{}, ErrStoredFormat
	}
	encodedName, query, hasVersion := strings.Cut(body, "?")
	name, err := url.PathUnescape(strings.Trim(encodedName, "/"))
	if err != nil || name == "" || !utf8.ValidString(name) || strings.Contains(name, "..") ||
		strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return Stored{}, ErrStoredFormat
	}
	parts := strings.Split(name, "/")
	for i, part := range parts {
		if part == "" || part == "." {
			return Stored{}, ErrStoredFormat
		}
		parts[i] = url.PathEscape(part)
	}
	parts[0] = storedFirstSegmentEscapes.Replace(parts[0])
	if strings.Join(parts, "/") != encodedName {
		return Stored{}, &invalidStoredAlias{name: name}
	}
	if changesLegacyURLName(encodedName, name) {
		return Stored{}, ErrStoredFormat
	}
	reference := Stored{Name: name}
	if body != name {
		reference.literalName = body
	}
	if !hasVersion {
		return reference, nil
	}
	number, ok := strings.CutPrefix(query, "version=")
	version, err := strconv.ParseInt(number, 10, 32)
	if !ok || err != nil || version < 1 || number != strconv.FormatInt(version, 10) {
		return Stored{}, &invalidStoredAlias{name: name}
	}
	pin := int(version)
	reference.Version = &pin
	return reference, nil
}

// Older connector and relay readers URL-decoded the first segment as a host,
// then unescaped the joined name again. Refuse any spelling that would switch
// its identity on upgrade. The old spelling is never used for lookup.
func changesLegacyURLName(encodedName, name string) bool {
	first, _, _ := strings.Cut(encodedName, "/")
	if !strings.Contains(first, "%") {
		return false
	}
	previous, err := url.Parse(storedPrefix + encodedName)
	if err != nil {
		return false
	}
	oldName, err := url.PathUnescape(strings.Trim(strings.TrimSpace(previous.Host+previous.EscapedPath()), "/"))
	return err == nil && oldName != "" && !strings.Contains(oldName, "..") && oldName != name
}
