// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"errors"
	"strings"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// Generating a subject key on the host that will serve it (epic B2).
//
// The whole point of B2 is that a private key for a workload is born on the
// machine that will use it and never travels. That inverts the previous flow,
// where the control plane generated the key, sealed it into an outbox row and
// an append-only event, and handed it to an agent — so the key existed in at
// least three places it did not need to.
//
// This is the boundary primitive that makes the inversion possible. It lives
// here because generating a key and building a PKCS#10 are both crypto/x509
// work (AN-3), and it returns the private material as a LOCKED, zeroizable
// buffer rather than a []byte or a string (AN-8): the host executor needs the
// PEM to write to a connector's target path, and the window between "generated"
// and "written" is the only time it should exist at all.

// HostSubjectKey is a freshly generated subject key and the CSR that requests a
// certificate for it.
//
// The caller owns Destroy and must call it. The PEM accessor deliberately
// returns a copy the caller must wipe, rather than a long-lived field: a struct
// that held the PEM would keep it alive for the lifetime of the value, and the
// lifetime that matters here is measured in the milliseconds it takes to write
// one file.
type HostSubjectKey struct {
	signer *LockedSigner
	// CSRDER is the PKCS#10 to send up. Public by construction — it carries the
	// public key and the requested names, and nothing else.
	CSRDER []byte
	// PublicKeyDER is the SubjectPublicKeyInfo, so a caller can record which
	// key was generated without touching the private half.
	PublicKeyDER []byte
}

// ErrNoSubjectNames is returned when a request names nothing to certify.
var ErrNoSubjectNames = errors.New("crypto: a host subject key needs a common name or at least one DNS name")

// GenerateHostSubjectKey generates a key on this host and builds its CSR.
//
// Algorithm is fixed to ECDSA P-256 rather than taken as a parameter. A host
// agent renewing a service certificate is not the place to be choosing key
// algorithms — that is a profile decision the control plane already enforces
// when it signs — and an agent that could pick would be a way to request a
// weaker key than policy allows.
func GenerateHostSubjectKey(commonName string, dnsNames []string) (*HostSubjectKey, error) {
	commonName = strings.TrimSpace(commonName)
	cleaned := make([]string, 0, len(dnsNames))
	for _, n := range dnsNames {
		if n = strings.TrimSpace(n); n != "" {
			cleaned = append(cleaned, n)
		}
	}
	if commonName == "" && len(cleaned) == 0 {
		return nil, ErrNoSubjectNames
	}
	if commonName == "" {
		commonName = cleaned[0]
	}

	signer, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		return nil, err
	}
	csrDER, err := CreateCertificateRequest(CertificateRequestTemplate{
		CommonName: commonName,
		DNSNames:   cleaned,
	}, signer)
	if err != nil {
		signer.Destroy()
		return nil, err
	}
	return &HostSubjectKey{
		signer:       signer,
		CSRDER:       csrDER,
		PublicKeyDER: append([]byte(nil), signer.Public().DER...),
	}, nil
}

// PrivateKeyPEM returns a COPY of the private key in PEM form.
//
// The caller must wipe it. Returning a copy rather than exposing the buffer
// means a caller that forgets cannot corrupt the locked original, and the copy
// is the thing with the short life: it exists to be written to one file and
// then destroyed.
func (h *HostSubjectKey) PrivateKeyPEM() ([]byte, error) {
	if h == nil || h.signer == nil {
		return nil, errors.New("crypto: host subject key has been destroyed")
	}
	return h.signer.PrivateKeyPEM()
}

// Destroy zeroizes the private material.
//
// Idempotent, because the call sites that matter are deferred and a deferred
// Destroy that panicked on a second call would turn a cleanup path into an
// outage.
func (h *HostSubjectKey) Destroy() {
	if h == nil || h.signer == nil {
		return
	}
	h.signer.Destroy()
	h.signer = nil
	secret.Wipe(h.CSRDER)
	h.CSRDER = nil
}
