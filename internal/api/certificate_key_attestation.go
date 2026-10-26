// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"encoding/pem"
	"errors"
	"net/http"
	"time"

	"trstctl.com/trstctl/internal/store"
)

// CertificateKeyAttestation is a certificate's device-bound custody evidence
// (A131), complete for offline re-verification: the device's TPM attestation
// and the binding whose SHA-256 it signed, exactly as verified at issuance,
// and the certificate itself. The verifier supplies its own TPM roots.
type CertificateKeyAttestation struct {
	CertificateID                string    `json:"certificate_id"`
	Fingerprint                  string    `json:"fingerprint"`
	Source                       string    `json:"source"`
	Format                       string    `json:"format"`
	Credential                   []byte    `json:"credential"`
	Binding                      []byte    `json:"binding"`
	PublicKeySHA256              []byte    `json:"public_key_sha256"`
	AttestationCertificateSHA256 []byte    `json:"attestation_certificate_sha256"`
	TrustedRootsSHA256           []byte    `json:"trusted_roots_sha256"`
	VerifiedAt                   time.Time `json:"verified_at"`
	CertificatePEM               string    `json:"certificate_pem"`
	Verify                       string    `json:"verify"`
}

func (a *API) getCertificateKeyAttestation(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	certificate, err := a.store.GetCertificate(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	evidence, err := a.store.GetCertificateKeyAttestation(r.Context(), tenantID, certificate.ID)
	if errors.Is(err, store.ErrCertificateKeyAttestationNotFound) {
		a.writeError(w, errStatus(http.StatusNotFound, "this certificate carries no device-bound custody claim"))
		return
	}
	if err != nil {
		a.writeError(w, err)
		return
	}
	certificatePEM := string(certificate.CertificatePEM)
	if certificatePEM == "" && len(certificate.CertificateDER) > 0 {
		certificatePEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.CertificateDER}))
	}
	a.writeJSON(w, http.StatusOK, CertificateKeyAttestation{
		CertificateID: certificate.ID, Fingerprint: certificate.Fingerprint,
		Source: evidence.Source, Format: evidence.Format,
		Credential: evidence.Credential, Binding: evidence.Binding,
		PublicKeySHA256:              evidence.PublicKeySHA256,
		AttestationCertificateSHA256: evidence.AttestationCertificateSHA256,
		TrustedRootsSHA256:           evidence.TrustedRootsSHA256,
		VerifiedAt:                   evidence.VerifiedAt, CertificatePEM: certificatePEM,
		Verify: "trstctl-cli certificates verify-key-attestation --evidence <this file> --roots <your TPM roots PEM>",
	})
}
