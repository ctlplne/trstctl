// SPDX-License-Identifier: BUSL-1.1

package deviceattest

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 -- a card-verifiable certificate may name ECDSA/RSA with SHA-1; verified only, never produced (CWE-327)
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Card-verifiable certificates (A175-L3). Some tokens attest a key they
// generated not with X.509 certificate objects but in their own format: a
// SmartCard-HSM (and the Nitrokey HSM 2 built on it) answers key generation
// with an authenticated card-verifiable certificate request — the new key's
// public key, signed by the key itself and then by the device's own
// authentication key — and holds the device's CV certificate and its device
// issuer CA's (DICA) in the file C_DevAut, chaining to the vendor's root CA
// (SRCA). The format is BSI TR-03110 part 3: BER-TLV with application tags,
// signatures over the encoded body, ECDSA signatures in plain r||s form
// (TR-03111). A segment pins the vendor's root as a "CV CERTIFICATE" PEM
// block beside its X.509 roots.

// PEMTypeCVCertificate is the PEM block type a pinned CV certificate root
// is carried in.
const PEMTypeCVCertificate = "CV CERTIFICATE"

// maxCVCBytes bounds one card-verifiable object.
const maxCVCBytes = 4096

// CV certificate and request tags (BSI TR-03110 part 3, D.2).
const (
	cvcTagCertificate   = 0x7F21
	cvcTagBody          = 0x7F4E
	cvcTagProfile       = 0x5F29
	cvcTagCAR           = 0x42
	cvcTagPublicKey     = 0x7F49
	cvcTagCHR           = 0x5F20
	cvcTagCHAT          = 0x7F4C
	cvcTagEffective     = 0x5F25
	cvcTagExpiration    = 0x5F24
	cvcTagExtensions    = 0x65
	cvcTagSignature     = 0x5F37
	cvcTagAuthenticated = 0x67
	cvcTagOID           = 0x06
)

// Signature algorithms of a CV public key (BSI TR-03110 part 3, A.2.1.1):
// id-TA-RSA and id-TA-ECDSA.
var (
	oidTARSA   = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 2, 1}
	oidTAECDSA = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 2, 2}
)

// cvcTLV is one decoded element: its tag, its value and its whole encoding.
type cvcTLV struct {
	tag   int
	value []byte
	raw   []byte
}

// readCVCTLV decodes the first element of b (BER: tags up to two bytes,
// lengths up to three) and returns it and what follows it.
func readCVCTLV(b []byte) (cvcTLV, []byte, error) {
	if len(b) < 2 {
		return cvcTLV{}, nil, errors.New("truncated element")
	}
	i, tag := 1, int(b[0])
	if b[0]&0x1F == 0x1F {
		if len(b) < 3 || b[1]&0x80 != 0 {
			return cvcTLV{}, nil, errors.New("unsupported tag")
		}
		tag, i = tag<<8|int(b[1]), 2
	}
	n := int(b[i])
	i++
	if n&0x80 != 0 {
		width := n & 0x7F
		if width == 0 || width > 3 || len(b) < i+width {
			return cvcTLV{}, nil, errors.New("invalid length")
		}
		n = 0
		for _, c := range b[i : i+width] {
			n = n<<8 | int(c)
		}
		i += width
	}
	if n > maxCVCBytes || len(b)-i < n {
		return cvcTLV{}, nil, errors.New("truncated element")
	}
	return cvcTLV{tag: tag, value: b[i : i+n], raw: b[:i+n]}, b[i+n:], nil
}

// readCVCElements decodes every element of b in order.
func readCVCElements(b []byte) ([]cvcTLV, error) {
	var out []cvcTLV
	for len(b) > 0 {
		e, rest, err := readCVCTLV(b)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
		b = rest
		if len(out) > 32 {
			return nil, errors.New("too many elements")
		}
	}
	return out, nil
}

// cvcPublicKey is a CV certificate's public key: its algorithm and either an
// RSA modulus and exponent or an EC point with the domain parameters the
// certificate carries (a CA's), which certificates below it inherit.
type cvcPublicKey struct {
	oid      asn1.ObjectIdentifier
	modulus  []byte
	exponent []byte
	prime    []byte
	a, b     []byte
	base     []byte
	order    []byte
	point    []byte
}

func (k cvcPublicKey) isEC() bool { return len(k.point) > 0 }

// cvCertificate is one CV certificate or certificate request.
type cvCertificate struct {
	raw       []byte // the whole 7F21 element
	body      []byte // the 7F4E element as encoded: what the signature covers
	car       string
	chr       string
	key       cvcPublicKey
	effective []byte
	expires   []byte
	signature []byte
}

// parseCVCertificate decodes a 7F21 CV certificate (or request).
func parseCVCertificate(b []byte) (cvCertificate, error) {
	if len(b) == 0 || len(b) > maxCVCBytes {
		return cvCertificate{}, errors.New("CV certificate has an invalid size")
	}
	outer, rest, err := readCVCTLV(b)
	if err != nil || outer.tag != cvcTagCertificate || len(rest) != 0 {
		return cvCertificate{}, errors.New("not a CV certificate")
	}
	parts, err := readCVCElements(outer.value)
	if err != nil || len(parts) != 2 || parts[0].tag != cvcTagBody || parts[1].tag != cvcTagSignature || len(parts[1].value) == 0 {
		return cvCertificate{}, errors.New("a CV certificate is a body and a signature")
	}
	c := cvCertificate{raw: outer.raw, body: parts[0].raw, signature: parts[1].value}
	fields, err := readCVCElements(parts[0].value)
	if err != nil {
		return cvCertificate{}, fmt.Errorf("CV certificate body: %w", err)
	}
	var sawKey, sawCHR bool
	for _, f := range fields {
		switch f.tag {
		case cvcTagProfile:
			if len(f.value) != 1 || f.value[0] != 0 {
				return cvCertificate{}, errors.New("unsupported CV certificate profile")
			}
		case cvcTagCAR:
			c.car = string(f.value)
		case cvcTagCHR:
			c.chr, sawCHR = string(f.value), true
		case cvcTagPublicKey:
			if c.key, err = parseCVCPublicKey(f.value); err != nil {
				return cvCertificate{}, err
			}
			sawKey = true
		case cvcTagEffective:
			c.effective = f.value
		case cvcTagExpiration:
			c.expires = f.value
		case cvcTagCHAT, cvcTagExtensions:
		default:
			return cvCertificate{}, fmt.Errorf("unexpected CV certificate field %X", f.tag)
		}
	}
	if !sawKey || !sawCHR {
		return cvCertificate{}, errors.New("a CV certificate names its holder and public key")
	}
	return c, nil
}

func parseCVCPublicKey(b []byte) (cvcPublicKey, error) {
	fields, err := readCVCElements(b)
	if err != nil || len(fields) == 0 || fields[0].tag != cvcTagOID {
		return cvcPublicKey{}, errors.New("a CV public key starts with its algorithm")
	}
	var k cvcPublicKey
	oidLen := len(fields[0].value)
	if oidLen == 0 || oidLen > 127 {
		return cvcPublicKey{}, errors.New("unreadable CV public key algorithm")
	}
	der := append([]byte{0x06, byte(oidLen)}, fields[0].value...) // #nosec G115 -- oidLen is checked to be 1..127 above (CWE-190)
	if _, err := asn1.Unmarshal(der, &k.oid); err != nil {
		return cvcPublicKey{}, errors.New("unreadable CV public key algorithm")
	}
	rsaKey := len(k.oid) == len(oidTARSA)+1 && k.oid[:len(oidTARSA)].Equal(oidTARSA)
	ecKey := len(k.oid) == len(oidTAECDSA)+1 && k.oid[:len(oidTAECDSA)].Equal(oidTAECDSA)
	if !rsaKey && !ecKey {
		return cvcPublicKey{}, fmt.Errorf("unsupported CV public key algorithm %s", k.oid)
	}
	for _, f := range fields[1:] {
		switch f.tag {
		case 0x81:
			if rsaKey {
				k.modulus = f.value
			} else {
				k.prime = f.value
			}
		case 0x82:
			if rsaKey {
				k.exponent = f.value
			} else {
				k.a = f.value
			}
		case 0x83:
			k.b = f.value
		case 0x84:
			k.base = f.value
		case 0x85:
			k.order = f.value
		case 0x86:
			k.point = f.value
		case 0x87, 0x02:
		default:
			return cvcPublicKey{}, fmt.Errorf("unexpected CV public key field %X", f.tag)
		}
	}
	if rsaKey && (len(k.modulus) == 0 || len(k.exponent) == 0) {
		return cvcPublicKey{}, errors.New("a CV RSA key carries its modulus and exponent")
	}
	if ecKey && len(k.point) == 0 {
		return cvcPublicKey{}, errors.New("a CV EC key carries its public point")
	}
	return k, nil
}

// cvcCurve names the curve whose explicit domain parameters a key carries.
// Only the curves Go's standard library implements are recognized: a key on
// another curve (a brainpool curve) cannot be verified here.
func cvcCurve(k cvcPublicKey) (elliptic.Curve, error) {
	if len(k.prime) == 0 {
		return nil, errors.New("the EC key's domain parameters are not known")
	}
	for _, c := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		p := c.Params()
		a := new(big.Int).Sub(p.P, big.NewInt(3))
		size := (p.BitSize + 7) / 8
		g := make([]byte, 1+2*size)
		g[0] = 4
		p.Gx.FillBytes(g[1 : 1+size])
		p.Gy.FillBytes(g[1+size:])
		if new(big.Int).SetBytes(k.prime).Cmp(p.P) == 0 && new(big.Int).SetBytes(k.a).Cmp(a) == 0 &&
			new(big.Int).SetBytes(k.b).Cmp(p.B) == 0 && new(big.Int).SetBytes(k.order).Cmp(p.N) == 0 && bytes.Equal(k.base, g) {
			return c, nil
		}
	}
	return nil, errors.New("the EC key's curve is not one this build verifies (P-256, P-384, P-521)")
}

// inherit gives a key without domain parameters its issuer's.
func (k cvcPublicKey) inherit(issuer cvcPublicKey) cvcPublicKey {
	if k.isEC() && len(k.prime) == 0 {
		k.prime, k.a, k.b, k.base, k.order = issuer.prime, issuer.a, issuer.b, issuer.base, issuer.order
	}
	return k
}

// publicKey is the key as a Go public key.
func (k cvcPublicKey) publicKey() (crypto.PublicKey, error) {
	if !k.isEC() {
		n, e := new(big.Int).SetBytes(k.modulus), new(big.Int).SetBytes(k.exponent)
		if n.BitLen() < 2048 || !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1 {
			return nil, errors.New("unsupported CV RSA key")
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
	}
	curve, err := cvcCurve(k)
	if err != nil {
		return nil, err
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(curve, k.point)
	if err != nil {
		return nil, errors.New("the CV EC point is not an uncompressed point on its curve")
	}
	return pub, nil
}

// verifyCVCSignature verifies sig over data with key, per key's algorithm.
func verifyCVCSignature(key cvcPublicKey, data, sig []byte) error {
	pub, err := key.publicKey()
	if err != nil {
		return err
	}
	variant := key.oid[len(key.oid)-1]
	if key.isEC() {
		var h crypto.Hash
		switch variant {
		case 1:
			h = crypto.SHA1
		case 2:
			h = crypto.SHA224
		case 3:
			h = crypto.SHA256
		case 4:
			h = crypto.SHA384
		case 5:
			h = crypto.SHA512
		default:
			return fmt.Errorf("unsupported ECDSA variant %d", variant)
		}
		ec := pub.(*ecdsa.PublicKey)
		size := (ec.Params().N.BitLen() + 7) / 8
		if len(sig) != 2*size {
			return errors.New("the ECDSA signature is not r||s of the curve's size")
		}
		r, s := new(big.Int).SetBytes(sig[:size]), new(big.Int).SetBytes(sig[size:])
		if !ecdsa.Verify(ec, cvcDigest(h, data), r, s) {
			return errors.New("the signature does not verify")
		}
		return nil
	}
	rsaKey := pub.(*rsa.PublicKey)
	var h crypto.Hash
	pss := false
	switch variant {
	case 1:
		h = crypto.SHA1
	case 2:
		h = crypto.SHA256
	case 3:
		h, pss = crypto.SHA1, true
	case 4:
		h, pss = crypto.SHA256, true
	case 5:
		h = crypto.SHA512
	case 6:
		h, pss = crypto.SHA512, true
	default:
		return fmt.Errorf("unsupported RSA variant %d", variant)
	}
	digest := cvcDigest(h, data)
	if pss {
		return rsa.VerifyPSS(rsaKey, h, digest, sig, nil)
	}
	return rsa.VerifyPKCS1v15(rsaKey, h, digest, sig)
}

func cvcDigest(h crypto.Hash, data []byte) []byte {
	switch h {
	case crypto.SHA1:
		d := sha1.Sum(data) // #nosec G401 -- verifying a CV signature that names SHA-1 (CWE-327)
		return d[:]
	case crypto.SHA224:
		d := sha256.Sum224(data)
		return d[:]
	case crypto.SHA256:
		d := sha256.Sum256(data)
		return d[:]
	case crypto.SHA384:
		d := sha512.Sum384(data)
		return d[:]
	default:
		d := sha512.Sum512(data)
		return d[:]
	}
}

// cvcDateValid reports whether now falls in a certificate's validity, given
// its effective and expiration dates (YYMMDD, one digit a byte); a
// certificate without dates is not limited.
func cvcDateValid(effective, expires []byte, now time.Time) bool {
	parse := func(d []byte) (time.Time, bool) {
		if len(d) != 6 {
			return time.Time{}, false
		}
		for _, c := range d {
			if c > 9 {
				return time.Time{}, false
			}
		}
		y, m, day := 2000+int(d[0])*10+int(d[1]), time.Month(int(d[2])*10+int(d[3])), int(d[4])*10+int(d[5])
		return time.Date(y, m, day, 0, 0, 0, 0, time.UTC), true
	}
	if len(effective) > 0 {
		from, ok := parse(effective)
		if !ok || now.Before(from) {
			return false
		}
	}
	if len(expires) > 0 {
		until, ok := parse(expires)
		if !ok || !now.Before(until.AddDate(0, 0, 1)) {
			return false
		}
	}
	return true
}

// SmartCardHSMAttestation is the evidence a SmartCard-HSM gives for a key it
// generated: the authenticated CV request (tag 67) it answered key
// generation with, and the device's and the device issuer CA's CV
// certificates from C_DevAut.
type SmartCardHSMAttestation struct {
	AuthenticatedRequest []byte
	DeviceCVC            []byte
	DICACVC              []byte
}

// VerifySmartCardHSMKeyAttestation verifies a SmartCard-HSM key attestation
// (A175-L3) against the CV certificate roots the segment pinned: the device
// issuer CA is certified by a pinned root, the device by the DICA, the
// authenticated request's outer signature is the device's over the request
// and the outer reference, the request's own signature is its key's (proof
// of possession), and the request's key is the CSR's.
func VerifySmartCardHSMKeyAttestation(ev SmartCardHSMAttestation, rootsPEM [][]byte, csrDER []byte, now time.Time) (TokenAttestation, error) {
	refuse := func(format string, args ...any) (TokenAttestation, error) {
		return TokenAttestation{}, &EdgeAttestationError{kind: ErrTokenAttestationRefused, msg: "SmartCard-HSM attestation: " + fmt.Sprintf(format, args...)}
	}
	roots := map[string]cvCertificate{}
	for _, raw := range rootsPEM {
		for rest := raw; ; {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != PEMTypeCVCertificate {
				continue
			}
			root, err := parseCVCertificate(block.Bytes)
			if err != nil {
				return refuse("pinned root: %v", err)
			}
			roots[root.chr] = root
		}
	}
	if len(roots) == 0 {
		return refuse("the segment pins no CV certificate root")
	}
	dica, err := parseCVCertificate(ev.DICACVC)
	if err != nil {
		return refuse("device issuer CA certificate: %v", err)
	}
	root, ok := roots[dica.car]
	if !ok {
		return refuse("the device issuer CA %q is not certified by a pinned root", dica.chr)
	}
	if err := verifyCVCSignature(root.key, dica.body, dica.signature); err != nil {
		return refuse("the device issuer CA certificate: %v", err)
	}
	dica.key = dica.key.inherit(root.key)
	device, err := parseCVCertificate(ev.DeviceCVC)
	if err != nil {
		return refuse("device certificate: %v", err)
	}
	if device.car != dica.chr {
		return refuse("the device certificate is not issued by the device issuer CA")
	}
	if err := verifyCVCSignature(dica.key, device.body, device.signature); err != nil {
		return refuse("the device certificate: %v", err)
	}
	device.key = device.key.inherit(dica.key)
	for name, c := range map[string]cvCertificate{"root": root, "device issuer CA": dica, "device": device} {
		if !cvcDateValid(c.effective, c.expires, now) {
			return refuse("the %s certificate is not valid now", name)
		}
	}

	if len(ev.AuthenticatedRequest) == 0 || len(ev.AuthenticatedRequest) > maxCVCBytes {
		return refuse("the authenticated request has an invalid size")
	}
	outer, rest, err := readCVCTLV(ev.AuthenticatedRequest)
	if err != nil || outer.tag != cvcTagAuthenticated || len(rest) != 0 {
		return refuse("not an authenticated CV request")
	}
	parts, err := readCVCElements(outer.value)
	if err != nil || len(parts) != 3 || parts[0].tag != cvcTagCertificate || parts[1].tag != cvcTagCAR || parts[2].tag != cvcTagSignature {
		return refuse("an authenticated request is a request, the outer reference and the outer signature")
	}
	if string(parts[1].value) != device.chr {
		return refuse("the request is authenticated by %q, not the device", string(parts[1].value))
	}
	signed := append(append([]byte(nil), parts[0].raw...), parts[1].raw...)
	if err := verifyCVCSignature(device.key, signed, parts[2].value); err != nil {
		return refuse("the device's signature on the request: %v", err)
	}
	request, err := parseCVCertificate(parts[0].raw)
	if err != nil {
		return refuse("the request: %v", err)
	}
	if err := verifyCVCSignature(request.key.inherit(device.key), request.body, request.signature); err != nil {
		return refuse("the request's own signature: %v", err)
	}
	attested, err := request.key.inherit(device.key).publicKey()
	if err != nil {
		return refuse("the request's key: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil || csr.CheckSignature() != nil {
		return refuse("the CSR cannot be read")
	}
	if !samePublicKey(attested, csr.PublicKey) {
		return refuse("the device attests a different key than the CSR's")
	}
	digest := sha256.Sum256(root.raw)
	return TokenAttestation{RootSHA256: hex.EncodeToString(digest[:]), Serial: smartCardHSMSerial(device.chr)}, nil
}

// smartCardHSMSerial is the device serial in a SmartCard-HSM device CHR: the
// holder reference without its five-character sequence number.
func smartCardHSMSerial(chr string) string {
	if len(chr) <= 5 {
		return ""
	}
	return strings.TrimSpace(chr[:len(chr)-5])
}

func samePublicKey(a, b crypto.PublicKey) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	e, ok := a.(equaler)
	return ok && e.Equal(b)
}

// ParsePinnedCVCertificateRoots checks the CV certificate roots among a
// segment's pinned PEM roots (A175-L3): each "CV CERTIFICATE" block must be a
// CV certificate carrying its key's domain parameters (a root's). It returns
// how many there are.
func ParsePinnedCVCertificateRoots(rootsPEM [][]byte) (int, error) {
	n := 0
	for _, raw := range rootsPEM {
		for rest := raw; ; {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != PEMTypeCVCertificate {
				continue
			}
			root, err := parseCVCertificate(block.Bytes)
			if err != nil {
				return 0, err
			}
			if _, err := root.key.publicKey(); err != nil {
				return 0, fmt.Errorf("CV root %q: %w", root.chr, err)
			}
			if err := verifyCVCSignature(root.key, root.body, root.signature); err != nil {
				return 0, fmt.Errorf("CV root %q is not self-signed: %w", root.chr, err)
			}
			n++
		}
	}
	return n, nil
}
