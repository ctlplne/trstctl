// SPDX-License-Identifier: BUSL-1.1

package discovery

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
)

// These limits keep one observation bounded and its indexed natural key below
// PostgreSQL's btree entry limit, including the fixed UUID columns.
const (
	MaxFindingKindBytes        = 128
	MaxFindingRefBytes         = 1024
	MaxFindingProvenanceBytes  = 1024
	MaxFindingFingerprintBytes = 256
	MaxFindingMetadataBytes    = 16 << 10
)

var ErrFindingShape = errors.New("discovery: finding is empty, oversized, or malformed")

// ValidateFindingShape is shared by event admission and historical replay.
func ValidateFindingShape(kind, ref, provenance, fingerprint string, metadata []byte) error {
	if strings.TrimSpace(kind) == "" || len(kind) > MaxFindingKindBytes ||
		strings.TrimSpace(ref) == "" || len(ref) > MaxFindingRefBytes ||
		len(provenance) > MaxFindingProvenanceBytes ||
		len(fingerprint) > MaxFindingFingerprintBytes ||
		len(metadata) > MaxFindingMetadataBytes ||
		(len(metadata) > 0 && (!json.Valid(metadata) || bytes.TrimSpace(metadata)[0] != '{')) {
		return ErrFindingShape
	}
	return nil
}
