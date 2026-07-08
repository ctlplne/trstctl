// SPDX-License-Identifier: LicenseRef-trstctl-EE

package witness

import (
	"encoding/json"

	"trstctl.com/trstctl/internal/crypto"
)

type Evidence struct {
	Body              Body               `json:"body"`
	Signatures        []WitnessSignature `json:"signatures"`
	CounterSignatures []WitnessSignature `json:"counter_signatures,omitempty"`
	Disputes          []DisputeRecord    `json:"disputes,omitempty"`
}

func EvidenceFromSignedWitness(signed SignedWitness) (Evidence, error) {
	if err := signed.Verify(map[string]crypto.PublicKey{
		signed.KeyID: {Algorithm: signed.Algorithm, DER: append([]byte(nil), signed.PublicKeyDER...)},
	}); err != nil {
		return Evidence{}, err
	}
	return Evidence{
		Body:       signed.Body,
		Signatures: []WitnessSignature{signed.SignatureRecord()},
	}, nil
}

func (e Evidence) ContentHash() []byte {
	payload, err := e.Body.CanonicalBytes()
	if err != nil {
		return nil
	}
	return crypto.SHA256Sum(payload)
}

func (e Evidence) CanonicalBytes() ([]byte, error) {
	if err := e.validateShape(); err != nil {
		return nil, err
	}
	return json.Marshal(e)
}

func (e Evidence) validateShape() error {
	if !e.Body.VerifyWitnessID() || len(e.Signatures) == 0 {
		return ErrInvalidWitness
	}
	if len(e.Body.DigestRefs) < 2 || len(e.Body.Entries) == 0 {
		return ErrInvalidWitness
	}
	for _, entry := range e.Body.Entries {
		if entry.Class == "" {
			return ErrInvalidWitness
		}
	}
	return nil
}
