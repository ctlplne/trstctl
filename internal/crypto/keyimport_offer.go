// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hpke"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"time"
)

const (
	AuthenticatedKeyImportSuite = KeyImportSuite + "-auth-v2"
	KeyImportOfferVersion       = 2
	KeyImportCAPurpose          = 1 // SignerService KeyPurpose_KEY_PURPOSE_CA_SIGN.
	keyImportOfferLifetime      = time.Hour
	keyImportOfferClockSkew     = 2 * time.Minute
	caHierarchyHandlePrefix     = "ca-hierarchy-"
)

// KeyImportPolicy identifies the key and the permissions the recipient will
// persist. The CA import path shares this public representation with its
// offline wrapper and the isolated signer.
type KeyImportPolicy struct {
	TenantID             string  `json:"tenant_id"`
	OperationID          string  `json:"operation_id"`
	Handle               string  `json:"signer_handle"`
	ExpectedPublicKey    []byte  `json:"expected_public_key"`
	AllowedPurposes      []int32 `json:"allowed_purposes"`
	AllowedHashes        []int32 `json:"allowed_hashes"`
	RequireAuthorization bool    `json:"require_authorization"`
}

// CAHierarchySignerHandle is the existing deterministic handle for a ceremony.
func CAHierarchySignerHandle(operationID string) string {
	return caHierarchyHandlePrefix + operationID
}

// IsCanonicalCAHierarchyHandle identifies names reserved for the durable CA
// ceremony slot. A caller checking an alias must also check its filesystem stem.
func IsCanonicalCAHierarchyHandle(handle string) bool {
	operation, ok := strings.CutPrefix(handle, caHierarchyHandlePrefix)
	return ok && canonicalImportUUID(operation)
}

func canonicalImportUUID(value string) bool {
	if len(value) != 36 || value == "00000000-0000-0000-0000-000000000000" {
		return false
	}
	for i := range len(value) {
		c := value[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				return false
			}
		}
	}
	return true
}

func CAKeyImportPolicy(tenantID, operationID string, expectedSPKI []byte) KeyImportPolicy {
	return KeyImportPolicy{
		TenantID: tenantID, OperationID: operationID, Handle: CAHierarchySignerHandle(operationID),
		ExpectedPublicKey: bytes.Clone(expectedSPKI), AllowedPurposes: []int32{KeyImportCAPurpose},
		AllowedHashes: []int32{}, RequireAuthorization: true,
	}
}

// Equal compares the semantic policy, treating empty constraint sets equally
// before and after encoding on transports.
func (p KeyImportPolicy) Equal(other KeyImportPolicy) bool {
	return p.TenantID == other.TenantID && p.OperationID == other.OperationID && p.Handle == other.Handle &&
		bytes.Equal(p.ExpectedPublicKey, other.ExpectedPublicKey) &&
		slices.Equal(p.AllowedPurposes, other.AllowedPurposes) && slices.Equal(p.AllowedHashes, other.AllowedHashes) &&
		p.RequireAuthorization == other.RequireAuthorization
}

// Validate rejects policy aliases and any policy that would create a key
// outside the reviewed CA signing and dual-control contract.
func (p KeyImportPolicy) Validate() error {
	if !canonicalImportUUID(p.TenantID) || !canonicalImportUUID(p.OperationID) ||
		p.Handle != CAHierarchySignerHandle(p.OperationID) {
		return errors.New("crypto: CA import requires canonical tenant, ceremony and signer handle")
	}
	if ValidateKeyImportSPKI(p.ExpectedPublicKey) != nil {
		return errors.New("crypto: CA import requires a supported expected public key")
	}
	if len(p.AllowedPurposes) != 1 || p.AllowedPurposes[0] != KeyImportCAPurpose ||
		len(p.AllowedHashes) != 0 || !p.RequireAuthorization {
		return errors.New("crypto: CA import requires the CA signing policy and dual control")
	}
	return nil
}

// ValidateKeyImportSPKI bounds and checks the canonical PKIX public key that
// identifies an imported CA in both the offer and installed envelope.
func ValidateKeyImportSPKI(der []byte) error {
	if len(der) == 0 || len(der) > 2048 {
		return errors.New("crypto: CA import public key is out of bounds")
	}
	public, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return errors.New("crypto: invalid CA import public key")
	}
	switch public.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
	default:
		return errors.New("crypto: unsupported CA import public key")
	}
	canonical, err := x509.MarshalPKIXPublicKey(public)
	if err != nil || !bytes.Equal(canonical, der) {
		return errors.New("crypto: noncanonical CA import public key")
	}
	return nil
}

// Receipt identifies an exact sealed command, independently of the lifetime
// of the preparation used to install it. It contains no key material.
func (p KeyImportPolicy) Receipt(sealed []byte) [sha256.Size]byte {
	info := p.appendCanonical([]byte("trstctl.ca-key-import.receipt.v2\x00"))
	digest := sha256.Sum256(sealed)
	return sha256.Sum256(append(info, digest[:]...))
}

func (p KeyImportPolicy) appendCanonical(out []byte) []byte {
	out = appendKeyImportField(out, []byte(p.TenantID))
	out = appendKeyImportField(out, []byte(p.OperationID))
	out = appendKeyImportField(out, []byte(p.Handle))
	expected := sha256.Sum256(p.ExpectedPublicKey)
	out = append(out, expected[:]...)
	out = binary.BigEndian.AppendUint64(out, uint64(len(p.AllowedPurposes)))
	for _, purpose := range p.AllowedPurposes {
		out = binary.AppendVarint(out, int64(purpose))
	}
	out = binary.BigEndian.AppendUint64(out, uint64(len(p.AllowedHashes)))
	for _, hash := range p.AllowedHashes {
		out = binary.AppendVarint(out, int64(hash))
	}
	var authorization byte
	if p.RequireAuthorization {
		authorization = 1
	}
	return append(out, authorization)
}

// AuthenticatedKeyImportOffer is prepared and signed inside the isolated
// signer. The public identity travels beside the signature and gains trust
// only through an independently provisioned fingerprint.
type AuthenticatedKeyImportOffer struct {
	KeyImportPolicy
	Version         uint32 `json:"version"`
	Suite           string `json:"suite"`
	PublicKey       []byte `json:"public_key"`
	IssuedAt        int64  `json:"issued_at_unix"`
	ExpiresAt       int64  `json:"expires_at_unix"`
	SignerPublicKey []byte `json:"signer_public_key"`
	Signature       []byte `json:"signature"`
}

func SignKeyImportOffer(policy KeyImportPolicy, recipient []byte, now time.Time, signer DigestSigner) (AuthenticatedKeyImportOffer, error) {
	if signer == nil || signer.Algorithm() != ECDSAP256 {
		return AuthenticatedKeyImportOffer{}, errors.New("crypto: key import offer identity must use ECDSA P-256")
	}
	offer := AuthenticatedKeyImportOffer{
		KeyImportPolicy: policy, Version: KeyImportOfferVersion, Suite: AuthenticatedKeyImportSuite,
		PublicKey: bytes.Clone(recipient), IssuedAt: now.Unix(), ExpiresAt: now.Add(keyImportOfferLifetime).Unix(),
		SignerPublicKey: signer.Public().DER,
	}
	info, err := offer.transcript("trstctl.ca-key-import.offer.v2\x00")
	if err != nil {
		return AuthenticatedKeyImportOffer{}, err
	}
	digest := sha256.Sum256(info)
	offer.Signature, err = signer.SignDigest(digest[:], SignOptions{Hash: SHA256})
	return offer, err
}

// Verify checks the independently supplied pin, signature and current lifetime
// before returning the public HPKE context. It never reads the private input.
func (o AuthenticatedKeyImportOffer) Verify(pin string, now time.Time) ([]byte, error) {
	if len(pin) != 64 || !ConstantTimeEqual([]byte(pin), []byte(SHA256Hex(o.SignerPublicKey))) {
		return nil, errors.New("crypto: the key import signer fingerprint does not match the trusted pin")
	}
	if now.Unix() >= o.ExpiresAt || now.Add(keyImportOfferClockSkew).Unix() < o.IssuedAt {
		return nil, errors.New("crypto: the key import offer is outside its validity window")
	}
	message, err := o.transcript("trstctl.ca-key-import.offer.v2\x00")
	if err != nil {
		return nil, err
	}
	if len(o.Signature) == 0 || len(o.Signature) > 80 || VerifyMessage(o.SignerPublicKey, message, o.Signature) != nil {
		return nil, errors.New("crypto: invalid key import offer signature")
	}
	return o.HPKEInfo()
}

// HPKEInfo reconstructs the authenticated policy for the isolated recipient.
// A caller obtains the offer from sealed storage or verifies it first.
func (o AuthenticatedKeyImportOffer) HPKEInfo() ([]byte, error) {
	return o.transcript("trstctl.ca-key-import.hpke.v2\x00")
}

func (o AuthenticatedKeyImportOffer) transcript(domain string) ([]byte, error) {
	const maxTime = int64(253402300799) // End of year 9999, UTC.
	if o.Version != KeyImportOfferVersion || o.Suite != AuthenticatedKeyImportSuite {
		return nil, errors.New("crypto: authenticated CA import offer v2 is required")
	}
	if err := o.Validate(); err != nil {
		return nil, err
	}
	if o.IssuedAt <= 0 || o.ExpiresAt <= o.IssuedAt || o.ExpiresAt > maxTime ||
		o.ExpiresAt-o.IssuedAt != int64(keyImportOfferLifetime/time.Second) {
		return nil, errors.New("crypto: invalid key import offer lifetime")
	}
	if len(o.PublicKey) == 0 || len(o.PublicKey) > 2048 {
		return nil, errors.New("crypto: invalid key import recipient")
	}
	if _, err := hpke.MLKEM768P256().NewPublicKey(o.PublicKey); err != nil {
		return nil, errors.New("crypto: invalid key import recipient")
	}
	if err := validateKeyImportIdentity(o.SignerPublicKey); err != nil {
		return nil, err
	}
	out := binary.BigEndian.AppendUint32([]byte(domain), o.Version)
	out = appendKeyImportField(out, []byte(o.Suite))
	out = appendKeyImportField(out, o.PublicKey)
	out = o.appendCanonical(out)
	out = binary.AppendVarint(out, o.IssuedAt)
	out = binary.AppendVarint(out, o.ExpiresAt)
	return appendKeyImportField(out, o.SignerPublicKey), nil
}

func validateKeyImportIdentity(der []byte) error {
	if len(der) == 0 || len(der) > 256 {
		return errors.New("crypto: invalid P-256 key import offer identity")
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	key, ok := parsed.(*ecdsa.PublicKey)
	if err != nil || !ok || key.Curve != elliptic.P256() {
		return errors.New("crypto: invalid P-256 key import offer identity")
	}
	canonical, err := x509.MarshalPKIXPublicKey(key)
	if err != nil || !bytes.Equal(canonical, der) {
		return errors.New("crypto: invalid P-256 key import offer identity")
	}
	return nil
}

func appendKeyImportField(out, value []byte) []byte {
	out = binary.BigEndian.AppendUint64(out, uint64(len(value)))
	return append(out, value...)
}
