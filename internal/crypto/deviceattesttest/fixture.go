// SPDX-License-Identifier: BUSL-1.1

// Package deviceattesttest builds real TPM WebAuthn attestation fixtures for
// tests. It lives below internal/crypto so fixture key generation and X.509
// construction cannot teach production packages to bypass the crypto boundary.
package deviceattesttest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/google/go-tpm/tpm2"

	trstcrypto "trstctl.com/trstctl/internal/crypto"
)

var (
	oidSubjectAlternativeName = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidTPMManufacturer        = asn1.ObjectIdentifier{2, 23, 133, 2, 1}
	oidTPMModel               = asn1.ObjectIdentifier{2, 23, 133, 2, 2}
	oidTPMVersion             = asn1.ObjectIdentifier{2, 23, 133, 2, 3}
	oidTPMAIKCertificate      = asn1.ObjectIdentifier{2, 23, 133, 8, 3}
)

// TPMIdentity is one isolated TPM-like credential, AIK, trust root, and CSR.
type TPMIdentity struct {
	credentialKey *ecdsa.PrivateKey
	aikKey        *ecdsa.PrivateKey
	csrDER        []byte
	rootDER       []byte
	rootPEM       []byte
	aikDER        []byte
}

// EdgeCAKeyProvider returns a TPM-like opaque-handle provider over the same
// credential key CredentialJSON attests. It exists only in this test-fixture
// package so served journeys can drive the exact handle/CSR/sign APIs used by
// trstctl-agent without exporting fixture private bytes into the normal path.
func (i *TPMIdentity) EdgeCAKeyProvider() trstcrypto.EdgeCAKeyProvider {
	return &edgeCAProvider{identity: i}
}

type edgeCAProvider struct{ identity *TPMIdentity }

func (*edgeCAProvider) Name() string { return "tpm2" }

func (p *edgeCAProvider) GenerateManagedKey(ctx context.Context, algorithm trstcrypto.Algorithm) (trstcrypto.Signer, trstcrypto.KeyRef, error) {
	return p.GenerateManagedKeyForOperation(ctx, "fixture-unscoped", algorithm)
}

func (p *edgeCAProvider) GenerateManagedKeyForOperation(ctx context.Context, _ string, algorithm trstcrypto.Algorithm) (trstcrypto.Signer, trstcrypto.KeyRef, error) {
	if err := ctx.Err(); err != nil {
		return nil, trstcrypto.KeyRef{}, err
	}
	if algorithm != trstcrypto.ECDSAP256 {
		return nil, trstcrypto.KeyRef{}, fmt.Errorf("TPM fixture supports only ECDSA-P256")
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&p.identity.credentialKey.PublicKey)
	if err != nil {
		return nil, trstcrypto.KeyRef{}, err
	}
	signer := edgeCASigner{identity: p.identity, publicDER: publicDER}
	return signer, trstcrypto.KeyRef{ID: "fixture-persistent-handle", Algorithm: algorithm}, nil
}

func (p *edgeCAProvider) RotateKey(ctx context.Context, ref trstcrypto.KeyRef) (trstcrypto.Signer, trstcrypto.KeyRef, error) {
	return p.GenerateManagedKey(ctx, ref.Algorithm)
}

func (p *edgeCAProvider) RotateKeyForOperation(ctx context.Context, operationID string, ref trstcrypto.KeyRef) (trstcrypto.Signer, trstcrypto.KeyRef, error) {
	return p.GenerateManagedKeyForOperation(ctx, operationID, ref.Algorithm)
}

func (*edgeCAProvider) RevokeKey(context.Context, trstcrypto.KeyRef) error  { return nil }
func (*edgeCAProvider) ZeroizeKey(context.Context, trstcrypto.KeyRef) error { return nil }
func (*edgeCAProvider) RevokeKeyForOperation(context.Context, string, trstcrypto.KeyRef) error {
	return nil
}
func (*edgeCAProvider) ZeroizeKeyForOperation(context.Context, string, trstcrypto.KeyRef) error {
	return nil
}

func (p *edgeCAProvider) SignManagedDigest(ctx context.Context, ref trstcrypto.KeyRef, digest []byte, _ trstcrypto.SignOptions) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if ref.ID != "fixture-persistent-handle" || ref.Algorithm != trstcrypto.ECDSAP256 {
		return nil, fmt.Errorf("TPM fixture: unknown edge CA handle")
	}
	return ecdsa.SignASN1(rand.Reader, p.identity.credentialKey, digest)
}

type edgeCASigner struct {
	identity  *TPMIdentity
	publicDER []byte
}

func (s edgeCASigner) Public() trstcrypto.PublicKey {
	return trstcrypto.PublicKey{Algorithm: trstcrypto.ECDSAP256, DER: append([]byte(nil), s.publicDER...)}
}
func (edgeCASigner) Algorithm() trstcrypto.Algorithm { return trstcrypto.ECDSAP256 }
func (s edgeCASigner) Sign(message []byte, opts trstcrypto.SignOptions) ([]byte, error) {
	hash := opts.Hash
	if hash == "" {
		hash = trstcrypto.SHA256
	}
	digest, err := trstcrypto.Digest(hash, message)
	if err != nil {
		return nil, err
	}
	return ecdsa.SignASN1(rand.Reader, s.identity.credentialKey, digest)
}

// NewTPMIdentity creates a fresh fixture whose AIK chains to a fresh root.
func NewTPMIdentity(now time.Time) (*TPMIdentity, error) {
	credentialKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate credential key: %w", err)
	}
	aikKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate AIK: %w", err)
	}
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate root: %w", err)
	}

	rootSerial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          rootSerial,
		Subject:               pkix.Name{CommonName: "trstctl TPM fixture root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("create root certificate: %w", err)
	}

	sanDER, err := tpmSubjectAlternativeName()
	if err != nil {
		return nil, err
	}
	aikSerial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	aikTemplate := &x509.Certificate{
		SerialNumber:          aikSerial,
		Subject:               pkix.Name{},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{oidTPMAIKCertificate},
		BasicConstraintsValid: true,
		IsCA:                  false,
		ExtraExtensions: []pkix.Extension{{
			Id:    oidSubjectAlternativeName,
			Value: sanDER,
		}},
	}
	aikDER, err := x509.CreateCertificate(rand.Reader, aikTemplate, rootTemplate, &aikKey.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("create AIK certificate: %w", err)
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "host-01.example.test"},
		DNSNames: []string{"host-01.example.test"},
	}, credentialKey)
	if err != nil {
		return nil, fmt.Errorf("create credential CSR: %w", err)
	}

	return &TPMIdentity{
		credentialKey: credentialKey,
		aikKey:        aikKey,
		csrDER:        csrDER,
		rootDER:       rootDER,
		rootPEM:       pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}),
		aikDER:        aikDER,
	}, nil
}

// CSRDER returns a copy of the fixture credential's PKCS#10 request.
func (i *TPMIdentity) CSRDER() []byte {
	return append([]byte(nil), i.csrDER...)
}

// CredentialKeyPEM exports the fixture key only for adversarial tests that
// deliberately bypass the shipping opaque-handle path (for example, forging
// an out-of-constraint leaf so reconciliation can prove it records a
// violation). Normal edge-host journeys use EdgeCAKeyProvider and never call
// this method.
func (i *TPMIdentity) CredentialKeyPEM() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(i.credentialKey)
	if err != nil {
		return nil, fmt.Errorf("marshal credential key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// RootPEM returns a copy of the operator trust anchor.
func (i *TPMIdentity) RootPEM() []byte {
	return append([]byte(nil), i.rootPEM...)
}

// CredentialJSON returns a WebAuthn credential creation response carrying a
// valid TPM 2.0 attestation over challenge.
func (i *TPMIdentity) CredentialJSON(challenge []byte) ([]byte, error) {
	clientDataJSON, err := json.Marshal(map[string]any{
		"type":        "webauthn.create",
		"challenge":   base64.RawURLEncoding.EncodeToString(challenge),
		"origin":      "https://trstctl.invalid",
		"crossOrigin": false,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal client data: %w", err)
	}

	coordinateSize := (i.credentialKey.Curve.Params().BitSize + 7) / 8
	coseKey, err := webauthncbor.Marshal(webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   int64(webauthncose.EllipticKey),
			Algorithm: int64(webauthncose.AlgES256),
		},
		Curve:  int64(webauthncose.P256),
		XCoord: i.credentialKey.X.FillBytes(make([]byte, coordinateSize)),
		YCoord: i.credentialKey.Y.FillBytes(make([]byte, coordinateSize)),
	})
	if err != nil {
		return nil, fmt.Errorf("marshal COSE credential key: %w", err)
	}
	credentialID := sha256.Sum256(coseKey)
	authData := make([]byte, 0, 32+1+4+16+2+len(credentialID)+len(coseKey))
	rpIDHash := sha256.Sum256([]byte("trstctl.invalid"))
	authData = append(authData, rpIDHash[:]...)
	authData = append(authData, byte(0x41)) // user present + attested credential data
	authData = binary.BigEndian.AppendUint32(authData, 0)
	authData = append(authData, make([]byte, 16)...)
	authData = binary.BigEndian.AppendUint16(authData, uint16(len(credentialID)))
	authData = append(authData, credentialID[:]...)
	authData = append(authData, coseKey...)

	pubArea := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt:         true,
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
		},
		Parameters: tpm2.NewTPMUPublicParms[*tpm2.TPMSECCParms](tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Symmetric: tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgNull},
			Scheme: tpm2.TPMTECCScheme{
				Scheme: tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUAsymScheme[*tpm2.TPMSSigSchemeECDSA](tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{
					HashAlg: tpm2.TPMAlgSHA256,
				}),
			},
			CurveID: tpm2.TPMECCNistP256,
			KDF:     tpm2.TPMTKDFScheme{Scheme: tpm2.TPMAlgNull},
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: i.credentialKey.X.FillBytes(make([]byte, coordinateSize))},
			Y: tpm2.TPM2BECCParameter{Buffer: i.credentialKey.Y.FillBytes(make([]byte, coordinateSize))},
		}),
	}
	pubAreaBytes := tpm2.Marshal(pubArea)
	objectName, err := tpm2.ObjectName(&pubArea)
	if err != nil {
		return nil, fmt.Errorf("derive TPM object name: %w", err)
	}

	clientHash := sha256.Sum256(clientDataJSON)
	attToBeSigned := append(append([]byte(nil), authData...), clientHash[:]...)
	extraData := sha256.Sum256(attToBeSigned)
	certInfo := tpm2.TPMSAttest{
		Magic: tpm2.TPMGeneratedValue,
		Type:  tpm2.TPMSTAttestCertify,
		Attested: tpm2.NewTPMUAttest[*tpm2.TPMSCertifyInfo](tpm2.TPMSTAttestCertify, &tpm2.TPMSCertifyInfo{
			Name:          *objectName,
			QualifiedName: tpm2.TPM2BName{},
		}),
		ExtraData: tpm2.TPM2BData{Buffer: extraData[:]},
	}
	certInfoBytes := tpm2.Marshal(certInfo)
	certInfoHash := sha256.Sum256(certInfoBytes)
	signature, err := ecdsa.SignASN1(rand.Reader, i.aikKey, certInfoHash[:])
	if err != nil {
		return nil, fmt.Errorf("sign TPM certInfo: %w", err)
	}

	attestationObject, err := webauthncbor.Marshal(map[string]any{
		"fmt":      "tpm",
		"authData": authData,
		"attStmt": map[string]any{
			"ver":      "2.0",
			"alg":      int64(webauthncose.AlgES256),
			"x5c":      []any{i.aikDER, i.rootDER},
			"sig":      signature,
			"certInfo": certInfoBytes,
			"pubArea":  pubAreaBytes,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal TPM attestation object: %w", err)
	}

	return json.Marshal(map[string]any{
		"id":    base64.RawURLEncoding.EncodeToString(credentialID[:]),
		"rawId": base64.RawURLEncoding.EncodeToString(credentialID[:]),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientDataJSON),
			"attestationObject": base64.RawURLEncoding.EncodeToString(attestationObject),
		},
	})
}

func randomSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return nil, fmt.Errorf("generate certificate serial: %w", err)
	}
	if serial.Sign() == 0 {
		return big.NewInt(1), nil
	}
	return serial, nil
}

func tpmSubjectAlternativeName() ([]byte, error) {
	nameDER, err := asn1.Marshal(pkix.RDNSequence{{
		{Type: oidTPMManufacturer, Value: "id:4D534654"},
		{Type: oidTPMModel, Value: "trstctl-test"},
		{Type: oidTPMVersion, Value: "id:00010000"},
	}})
	if err != nil {
		return nil, fmt.Errorf("marshal TPM directory name: %w", err)
	}
	return asn1.Marshal([]asn1.RawValue{{
		Class:      asn1.ClassContextSpecific,
		Tag:        4,
		IsCompound: true,
		Bytes:      nameDER,
	}})
}
