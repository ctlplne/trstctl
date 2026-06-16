// Package tpmquote is the TPM 2.0 quote attester (S11.3, F30). A node proves
// possession of a hardware TPM by signing a quote (binding a challenge nonce)
// with its attestation key (AK), whose certificate chains to a trusted
// manufacturer/EK root. This attester verifies the AK endorsement, the quote
// signature, and the nonce binding; a forged quote, an untrusted AK, or a replay
// (wrong nonce) is rejected (fail-closed).
package tpmquote

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/crypto"
)

// Quote is the TPM 2.0 quote envelope this attester verifies. (A production
// integration parses the TPMS_ATTEST structure with go-tpm; this envelope carries
// the same verified facts — AK certificate, signed quote, and nonce — so the
// verification logic is exercised end-to-end.)
type Quote struct {
	AKCertDER []byte `json:"ak_cert"`   // attestation-key certificate (chains to a manufacturer/EK root)
	Message   []byte `json:"message"`   // the signed quote bytes; must embed the challenge nonce
	Signature []byte `json:"signature"` // AK signature over Message
	Nonce     []byte `json:"nonce"`     // the challenge nonce echoed by the quote
}

// Attestor verifies TPM 2.0 quotes.
type Attestor struct {
	// ManufacturerRoots are the trusted EK/AK manufacturer CA certificates (DER).
	ManufacturerRoots [][]byte
	// ExpectedNonce, if set, must match the quote's nonce and be embedded in the
	// signed message (anti-replay).
	ExpectedNonce []byte
}

// Method implements attest.Attestor.
func (a *Attestor) Method() string { return "tpm" }

// Attest verifies the AK endorsement, the quote signature, and the nonce binding.
func (a *Attestor) Attest(_ context.Context, payload []byte) (attest.Attestation, error) {
	var q Quote
	if err := json.Unmarshal(payload, &q); err != nil {
		return attest.Attestation{}, fmt.Errorf("tpm: parse quote: %w", err)
	}
	if len(q.AKCertDER) == 0 || len(q.Message) == 0 || len(q.Signature) == 0 {
		return attest.Attestation{}, fmt.Errorf("tpm: quote missing ak_cert/message/signature")
	}
	endorsed := false
	for _, root := range a.ManufacturerRoots {
		if crypto.VerifyLeafSignedByCA(q.AKCertDER, root) == nil {
			endorsed = true
			break
		}
	}
	if !endorsed {
		return attest.Attestation{}, fmt.Errorf("tpm: AK is not endorsed by a trusted manufacturer root")
	}
	akPub, err := crypto.PublicKeyDERFromCert(q.AKCertDER)
	if err != nil {
		return attest.Attestation{}, fmt.Errorf("tpm: %w", err)
	}
	if err := crypto.VerifyMessage(akPub, q.Message, q.Signature); err != nil {
		return attest.Attestation{}, fmt.Errorf("tpm: quote signature: %w", err)
	}
	if len(a.ExpectedNonce) > 0 {
		if !bytes.Equal(q.Nonce, a.ExpectedNonce) || !bytes.Contains(q.Message, a.ExpectedNonce) {
			return attest.Attestation{}, fmt.Errorf("tpm: nonce mismatch (possible replay)")
		}
	}
	fp := crypto.SHA256Hex(q.AKCertDER)
	return attest.Attestation{
		Subject:   fp,
		Selectors: []string{"tpm:ak-fingerprint:" + fp},
		Claims:    map[string]string{"ak_fingerprint": fp},
	}, nil
}
