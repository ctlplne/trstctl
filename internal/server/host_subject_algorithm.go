// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"errors"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"trstctl.com/trstctl/internal/crypto"
)

// Subject choice is identity intent, distinct from a profile's allowed set.
// Enqueue freezes it into the job. Subsequent renewals retain that choice rather
// than silently moving a PQC endpoint back to the old ECDSA generator.
func hostRenewalSubjectAlgorithm(attributes json.RawMessage) (string, error) {
	if len(attributes) == 0 {
		return "", nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(attributes, &fields); err != nil {
		return "", err
	}
	raw, present := fields["subject_key_algorithm"]
	if !present {
		return "", nil
	}
	var algorithm string
	if err := json.Unmarshal(raw, &algorithm); err != nil {
		return "", errors.New("server: subject_key_algorithm must name a supported algorithm")
	}
	algorithm = strings.TrimSpace(algorithm)
	switch algorithm {
	case string(crypto.ECDSAP256), "ML-DSA-44", "ML-DSA-65", "ML-DSA-87":
		return algorithm, nil
	default:
		return "", errors.New("server: subject_key_algorithm is unsupported; no other algorithm was selected")
	}
}

func (d *issuanceDispatcher) authorizeAgentSubjectAlgorithm(csr []byte, selected string) error {
	selected = strings.TrimSpace(selected)
	if selected == "" {
		return nil
	} // Historical jobs still use their profile gate.
	info, err := d.inspectSubjectCSR(csr)
	if err != nil {
		return status.Error(codes.InvalidArgument, "host CSR proof is invalid")
	}
	if selected == string(crypto.ECDSAP256) && info.KeyAlgorithm == "ECDSA" && info.KeyBits == 256 {
		return nil
	}
	if selected == info.KeyAlgorithm {
		return nil
	}
	return status.Error(codes.PermissionDenied, "host CSR algorithm differs from the reviewed job; no algorithm substitution is authorized")
}
