// SPDX-License-Identifier: BUSL-1.1

package pqcruntime

import (
	"context"
	"errors"
	"time"

	boundarycrypto "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/pqc"
	"trstctl.com/trstctl/internal/protocols/spiffe"
)

const SPIFFEHybridMLDSAHint = "trstctl-hybrid-ml-dsa-65"

type spiffeHybridIssuer struct {
	caCertDER []byte
	caSigner  boundarycrypto.DigestSigner
}

// NewSPIFFEHybridSVIDIssuer is the tagged-attach factory for the second half of
// a hybrid Workload API response. Core sees only the feature-neutral
// AdditionalX509SVIDIssuer interface.
func NewSPIFFEHybridSVIDIssuer(caCertDER []byte, caSigner boundarycrypto.DigestSigner) (spiffe.AdditionalX509SVIDIssuer, error) {
	if len(caCertDER) == 0 || caSigner == nil {
		return nil, errors.New("pqcruntime: SPIFFE hybrid issuer requires signer-backed CA")
	}
	return &spiffeHybridIssuer{caCertDER: append([]byte(nil), caCertDER...), caSigner: caSigner}, nil
}

func (s *spiffeHybridIssuer) IssueAdditionalX509SVID(_ context.Context, spiffeID string, expiresAt time.Time) (spiffe.AdditionalX509SVID, error) {
	if _, err := boundarycrypto.ParseSPIFFEID(spiffeID); err != nil {
		return spiffe.AdditionalX509SVID{}, err
	}
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		return spiffe.AdditionalX509SVID{}, errors.New("pqcruntime: SPIFFE hybrid SVID expiry is not in the future")
	}
	key, pkcs8, err := pqc.GenerateInteroperableMLDSAKey(pqc.MLDSA65)
	if err != nil {
		return spiffe.AdditionalX509SVID{}, err
	}
	defer key.Destroy()
	keepPKCS8 := false
	defer func() {
		if !keepPKCS8 {
			secret.Wipe(pkcs8)
		}
	}()
	spki, err := boundarycrypto.MarshalOpaqueSubjectPublicKeyInfo(pqc.MLDSA65OID, key.Public().DER)
	if err != nil {
		return spiffe.AdditionalX509SVID{}, err
	}
	certDER, err := boundarycrypto.SignOpaqueLeafFromVerifiedRequestWithProfile(s.caCertDER, s.caSigner, boundarycrypto.OpaqueLeafRequest{
		Info: boundarycrypto.CSRInfo{
			KeyAlgorithm: string(pqc.MLDSA65), KeyBits: len(key.Public().DER) * 8,
			URIs: []string{spiffeID},
		},
		SubjectPublicKeyInfoDER: spki,
		SignatureOnly:           true,
	}, ttl, boundarycrypto.LeafProfile{AllowedExtKeyUsage: []string{"serverAuth", "clientAuth"}})
	if err != nil {
		return spiffe.AdditionalX509SVID{}, err
	}
	keepPKCS8 = true
	return spiffe.AdditionalX509SVID{
		CertificateDER:  certDER,
		PrivateKeyPKCS8: pkcs8,
		Hint:            SPIFFEHybridMLDSAHint,
	}, nil
}

var _ spiffe.AdditionalX509SVIDIssuer = (*spiffeHybridIssuer)(nil)
