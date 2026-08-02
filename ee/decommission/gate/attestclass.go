// SPDX-License-Identifier: LicenseRef-trstctl-EE

package gate

import (
	"errors"
	"fmt"
	"strings"
)

var ErrBelowMinAttestationClass = errors.New("custody destroy: attestation class below policy minimum")

// AttestationClass is ordered weakest to strongest. The identifier is carried
// forward so the destruction record minter can bind the exact evidence class.
//
// The class floor practices VDEC-claim-7: policy associates a key class with a
// minimum attestation class, the signer refuses to mint on lower-class evidence,
// and the commitment binds the attestation-class identifier.
type AttestationClass int

const (
	ClassNone AttestationClass = iota
	ClassSoftwareZeroize
	ClassModule
	ClassCertifiedHardware
)

func (c AttestationClass) ID() string {
	switch c {
	case ClassSoftwareZeroize:
		return "software-zeroize"
	case ClassModule:
		return "module"
	case ClassCertifiedHardware:
		return "certified-hardware"
	default:
		return "none"
	}
}

func (c AttestationClass) String() string { return c.ID() }

func (c AttestationClass) Meets(min AttestationClass) bool { return c >= min }

// AttestationClassPolicy maps a key class to the minimum destruction-evidence
// class it accepts before a destruction record may be minted.
type AttestationClassPolicy map[string]AttestationClass

func (p AttestationClassPolicy) Minimum(keyClass string) AttestationClass {
	if p == nil {
		return ClassNone
	}
	return p[strings.TrimSpace(keyClass)]
}

type AttestationClassBinding struct {
	KeyClass          string
	EvidenceClass     AttestationClass
	EvidenceClassID   string
	MinimumClass      AttestationClass
	MinimumClassID    string
	EvidenceDigestHex string
}

// EnforceBeforeMint is the VDEC-06 pre-mint gate. It refuses evidence below the
// configured minimum and returns the class id VDEC-07 must bind on success.
func (p AttestationClassPolicy) EnforceBeforeMint(keyClass string, evidence DestructionEvidence) (AttestationClassBinding, error) {
	trimmed := strings.TrimSpace(keyClass)
	if trimmed == "" {
		return AttestationClassBinding{}, fmt.Errorf("%w: key class is required", ErrInvalidEvidence)
	}
	if len(evidence.Digest) == 0 {
		return AttestationClassBinding{}, fmt.Errorf("%w: destruction evidence digest is required", ErrInvalidEvidence)
	}
	class := evidence.AttestationClass
	classID := class.ID()
	if reported := strings.TrimSpace(evidence.AttestationClassID); reported != "" && reported != classID {
		return AttestationClassBinding{}, fmt.Errorf("%w: evidence class id mismatch", ErrInvalidDestroyEvidence)
	}
	minimum := p.Minimum(trimmed)
	binding := AttestationClassBinding{
		KeyClass:          trimmed,
		EvidenceClass:     class,
		EvidenceClassID:   classID,
		MinimumClass:      minimum,
		MinimumClassID:    minimum.ID(),
		EvidenceDigestHex: hexDigest(evidence.Digest),
	}
	if !class.Meets(minimum) {
		return binding, fmt.Errorf("%w: evidence class %s < minimum %s", ErrBelowMinAttestationClass, class.ID(), minimum.ID())
	}
	return binding, nil
}
