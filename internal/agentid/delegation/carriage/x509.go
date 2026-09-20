// SPDX-License-Identifier: BUSL-1.1

package carriage

import (
	"encoding/asn1"
	"encoding/json"
	"errors"

	"trstctl.com/trstctl/internal/crypto"
)

// x509.go is the X.509 carriage form (AGID-claim-27, first alternative): the bound values ride
// in a dedicated NON-CRITICAL certificate extension. Non-critical is mandatory: a legacy
// relying party that does not understand AGID still parses and uses the certificate,
// while an AGID-aware relying party (AGID-09) reads the extension and re-verifies the
// binding offline. The extension VALUE is DER (an ASN.1 OCTET STRING wrapping the
// JSON-encoded bound values), framed identically to the minimal AGID-04 binding extension
// so the two are interchangeable on the wire.
//
// AN-3: this file performs NO crypto primitive. encoding/asn1 and encoding/json are
// structural carriage framing. The extension is stamped onto (and read back from) a
// certificate through the internal/crypto boundary's backend-agnostic CertificateExtension
// and LeafExtensionValue -- callers never import crypto/x509.

// AGIDCarriageOIDString is the dotted OID of the AGID carriage extension. It is the SAME
// private-arc OID the AGID-04 minimal binding extension uses (1.3.6.1.4.1.58888.4.1): the
// X.509 carriage form is that same extension carrying the same bound values, so a relying
// party reads one OID whether the credential was stamped by the signer's minimal binding
// or by this carriage encoder.
const AGIDCarriageOIDString = "1.3.6.1.4.1.58888.4.1"

// ErrExtensionCritical is returned by DecodeExtension when the AGID extension is marked
// CRITICAL. The carriage contract requires non-critical (so legacy relying parties still
// parse the certificate); a critical AGID extension is a malformed/hostile carriage and is
// rejected fail-closed.
var ErrExtensionCritical = errors.New("carriage: AGID x509 extension is critical (must be non-critical)")

// Extension encodes bv into a backend-agnostic, NON-CRITICAL X.509 extension carrying the
// bound values. It is what a caller places into a leaf profile's ExtraExtensions (or hands
// to the signer's MintCredential) so the issued certificate transports the binding. The
// value is the DER of an OCTET STRING wrapping the JSON of bv.
func Extension(bv BoundValues) (crypto.CertificateExtension, error) {
	payload, err := json.Marshal(bv)
	if err != nil {
		return crypto.CertificateExtension{}, err
	}
	der, err := asn1.Marshal(payload) // OCTET STRING wrapper (matches the AGID-04 binding extension)
	if err != nil {
		return crypto.CertificateExtension{}, err
	}
	return crypto.CertificateExtension{
		OID:      AGIDCarriageOIDString,
		Critical: false,
		Value:    der,
	}, nil
}

// DecodeExtensionValue recovers the bound values from an AGID extension's raw DER VALUE
// (the OCTET STRING wrapper). It is the shared inner decode both DecodeExtension (from a
// crypto.CertificateExtension) and DecodeCertificate (from a whole certificate) use. It
// fails closed on malformed DER or JSON and never panics on untrusted input.
func DecodeExtensionValue(der []byte) (BoundValues, error) {
	var payload []byte
	rest, err := asn1.Unmarshal(der, &payload)
	if err != nil {
		return BoundValues{}, ErrMalformedCarriage
	}
	if len(rest) != 0 {
		// Trailing bytes after the OCTET STRING are not a well-formed extension value.
		return BoundValues{}, ErrMalformedCarriage
	}
	var bv BoundValues
	if err := json.Unmarshal(payload, &bv); err != nil {
		return BoundValues{}, ErrMalformedCarriage
	}
	return bv, nil
}

// DecodeExtension recovers the bound values from a backend-agnostic extension, enforcing
// the OID and the non-critical requirement. A caller that already holds the parsed
// extension (rather than the whole certificate) uses this.
func DecodeExtension(ext crypto.CertificateExtension) (BoundValues, error) {
	if ext.OID != AGIDCarriageOIDString {
		return BoundValues{}, ErrNoAGIDCarriage
	}
	if ext.Critical {
		return BoundValues{}, ErrExtensionCritical
	}
	return DecodeExtensionValue(ext.Value)
}

// DecodeCertificate recovers the bound values from a whole DER-encoded certificate by
// reading the AGID carriage extension through the internal/crypto boundary (AN-3;
// LeafExtensionValue does the crypto/x509 parse inside the boundary). It enforces the
// non-critical requirement and fails closed: a certificate that does not parse, or that
// carries no AGID extension, or whose extension is critical/malformed, returns an error.
// This is the entry point the AGID-09 relying-party X.509 path uses.
func DecodeCertificate(certDER []byte) (BoundValues, error) {
	value, critical, found, err := crypto.LeafExtensionValue(certDER, AGIDCarriageOIDString)
	if err != nil {
		// A certificate that does not parse is not a usable AGID carriage.
		return BoundValues{}, ErrMalformedCarriage
	}
	if !found {
		return BoundValues{}, ErrNoAGIDCarriage
	}
	if critical {
		return BoundValues{}, ErrExtensionCritical
	}
	return DecodeExtensionValue(value)
}

// X509Decoder adapts the X.509 carriage form to the common Decoder surface: its Decode
// takes a whole DER-encoded certificate. It lets a relying party read all three forms
// through one interface.
type X509Decoder struct{}

// Decode implements Decoder for a DER-encoded certificate.
func (X509Decoder) Decode(certDER []byte) (BoundValues, error) { return DecodeCertificate(certDER) }

// Kind implements Decoder.
func (X509Decoder) Kind() string { return "x509" }
