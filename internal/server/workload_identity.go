// SPDX-License-Identifier: MPL-2.0

package server

import (
	"encoding/hex"
	"errors"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
)

const encodedSubjectSegmentPrefix = "trstctl-hex-"

// workloadSPIFFEID preserves valid subject hierarchy, not URL escaping. A
// segment outside SPIFFE's alphabet becomes trstctl-hex-<lowercase byte hex>.
// Literal segments starting with that reserved prefix are encoded too: otherwise
// the subject "a:b" and the literal subject "trstctl-hex-613a62" would collide.
// Empty and relative segments are rejected, never trimmed or cleaned. The
// top-level agent namespace belongs only to brokered issuance, so attested
// subjects beginning with agent encode that segment as well. The verified
// original subject remains unchanged in audit and issuance history.
func workloadSPIFFEID(trustDomain, namespace, subject string) (string, error) {
	domainID, err := crypto.ParseSPIFFEID("spiffe://" + strings.TrimSpace(trustDomain))
	if err != nil || domainID.Path != "" {
		return "", errors.New("a canonical SPIFFE trust domain without a path is required")
	}
	if subject == "" || len(subject) > crypto.MaxSPIFFEIDLength {
		return "", errors.New("attestation subject is empty or exceeds the identity size limit")
	}
	id := domainID.String()
	if namespace != "" {
		id += "/" + namespace
	}
	for index, segment := range strings.Split(subject, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return "", errors.New("attestation subject must not contain empty or relative path segments")
		}
		segmentErr := crypto.ValidateSPIFFEPathSegment(segment)
		reservedNamespace := namespace == "" && index == 0 && segment == "agent"
		if segmentErr != nil || strings.HasPrefix(segment, encodedSubjectSegmentPrefix) || reservedNamespace {
			segment = encodedSubjectSegmentPrefix + hex.EncodeToString([]byte(segment))
		}
		if len(id)+1+len(segment) > crypto.MaxSPIFFEIDLength {
			return "", errors.New("mapped attestation subject exceeds the SPIFFE identity size limit")
		}
		id += "/" + segment
	}
	if _, err := crypto.ParseSPIFFEID(id); err != nil {
		return "", err
	}
	return id, nil
}
