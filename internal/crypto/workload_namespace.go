// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"encoding/hex"
	"errors"
	"net/url"
	"path"
	"strings"
)

// ReservedWorkloadSPIFFEPath belongs to the authenticated automatic workload
// issuers. Ordinary CSR profiles and manual registration cannot grant this
// namespace, regardless of which trust domain or SAN allow-list they use.
const ReservedWorkloadSPIFFEPath = "/_trstctl"

const encodedWorkloadSegmentPrefix = "trstctl-hex-"

// EncodeWorkloadSPIFFESegment preserves plain SPIFFE-safe text and maps other
// bytes to lowercase hex. Literal encoded-looking text is encoded too, so two
// different fields cannot claim the same wire name. Callers split subject
// hierarchy first; method and agent fields remain one segment even with slashes.
func EncodeWorkloadSPIFFESegment(segment string) (string, error) {
	if segment == "" || segment == "." || segment == ".." || len(segment) > MaxSPIFFEIDLength {
		return "", errors.New("workload identity fields must be nonempty, bounded and not relative path segments")
	}
	if ValidateSPIFFEPathSegment(segment) != nil || strings.HasPrefix(segment, encodedWorkloadSegmentPrefix) {
		return encodedWorkloadSegmentPrefix + hex.EncodeToString([]byte(segment)), nil
	}
	return segment, nil
}

// DecodeWorkloadSPIFFESegment accepts only the encoder's exact canonical output.
// It is used to verify an approved subject against a signed, versioned identity;
// it never grants authority and must not be applied to historical literal names.
func DecodeWorkloadSPIFFESegment(segment string) (string, error) {
	if len(segment) > MaxSPIFFEIDLength || ValidateSPIFFEPathSegment(segment) != nil {
		return "", errors.New("invalid encoded workload identity segment")
	}
	decoded := segment
	if strings.HasPrefix(segment, encodedWorkloadSegmentPrefix) {
		raw, err := hex.DecodeString(strings.TrimPrefix(segment, encodedWorkloadSegmentPrefix))
		if err != nil {
			return "", errors.New("invalid workload identity hex encoding")
		}
		decoded = string(raw)
	}
	canonical, err := EncodeWorkloadSPIFFESegment(decoded)
	if err != nil || canonical != segment {
		return "", errors.New("noncanonical workload identity segment")
	}
	return decoded, nil
}

// IsReservedWorkloadSPIFFEID recognizes the protected namespace and encoded or
// relative-path attempts to reach it. URL decoding/cleaning is used ONLY to
// reject aliases, never to authorize, rename or sign an alternative identity.
// Canonical automatic identities are separately checked by ParseSPIFFEID.
func IsReservedWorkloadSPIFFEID(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || !strings.EqualFold(u.Scheme, "spiffe") {
		return false
	}
	cleaned := path.Clean(u.Path)
	return cleaned == ReservedWorkloadSPIFFEPath || strings.HasPrefix(cleaned, ReservedWorkloadSPIFFEPath+"/")
}
