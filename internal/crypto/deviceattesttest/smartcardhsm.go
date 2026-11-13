// SPDX-License-Identifier: BUSL-1.1

package deviceattesttest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"time"
)

// SmartCardHSM stands in for a SmartCard-HSM's key attestation (A175-L3),
// built to BSI TR-03110 part 3 as the card's is: a vendor root CA (SRCA), a
// device issuer CA (DICA) it certified, a device key the DICA certified, and
// for each key the card generates an authenticated CV request — the key's
// public key signed by the key itself, then by the device key over the
// request and the device's reference. Every key is ECDSA P-256 with SHA-256.
type SmartCardHSM struct {
	rootKey, dicaKey, deviceKey *ecdsa.PrivateKey
	RootCVC, DICACVC, DeviceCVC []byte
	rootCHR, dicaCHR, deviceCHR string
}

// id-TA-ECDSA-SHA-256 (0.4.0.127.0.7.2.2.2.2.3), as an OID's content bytes.
var cvcECDSASHA256 = []byte{0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x02, 0x03}

// NewSmartCardHSM makes a card whose device serial is serial (the device
// holder reference adds a five-digit sequence number) under a vendor root of
// its own. The root and DICA are valid from yesterday for twenty years.
func NewSmartCardHSM(serial string) (*SmartCardHSM, error) {
	// Each stand-in has its own vendor root and DICA (their holder
	// references differ, as distinct vendors' do).
	s := &SmartCardHSM{rootCHR: "DESRCA" + serial, dicaCHR: "DEDICA" + serial, deviceCHR: serial + "00001"}
	var err error
	for _, k := range []**ecdsa.PrivateKey{&s.rootKey, &s.dicaKey, &s.deviceKey} {
		if *k, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			return nil, err
		}
	}
	from, until := time.Now().UTC().AddDate(0, 0, -1), time.Now().UTC().AddDate(20, 0, 0)
	if s.RootCVC, err = cvCertificate(s.rootKey, s.rootCHR, s.rootCHR, &s.rootKey.PublicKey, true, from, until); err != nil {
		return nil, err
	}
	if s.DICACVC, err = cvCertificate(s.rootKey, s.rootCHR, s.dicaCHR, &s.dicaKey.PublicKey, false, from, until); err != nil {
		return nil, err
	}
	if s.DeviceCVC, err = cvCertificate(s.dicaKey, s.dicaCHR, s.deviceCHR, &s.deviceKey.PublicKey, false, from, until); err != nil {
		return nil, err
	}
	return s, nil
}

// RootPEM is the vendor root as a segment pins it.
func (s *SmartCardHSM) RootPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CV CERTIFICATE", Bytes: s.RootCVC})
}

// Attest answers key generation for key: the authenticated CV request the
// card returns, its public key self-signed and then signed by the device.
func (s *SmartCardHSM) Attest(key *ecdsa.PrivateKey) ([]byte, error) {
	if key == nil || key.Curve != elliptic.P256() {
		return nil, errors.New("deviceattesttest: the stand-in card generates P-256 keys")
	}
	body := cvcTLV(0x7F4E, cvcConcat(cvcTLV(0x5F29, []byte{0}), cvcTLV(0x42, []byte(s.rootCHR)),
		cvcPublicKey(&key.PublicKey, true), cvcTLV(0x5F20, []byte("DECARDKEY00001"))))
	inner, err := cvcSign(key, body)
	if err != nil {
		return nil, err
	}
	request := cvcTLV(0x7F21, cvcConcat(body, cvcTLV(0x5F37, inner)))
	outerCAR := cvcTLV(0x42, []byte(s.deviceCHR))
	outer, err := cvcSign(s.deviceKey, cvcConcat(request, outerCAR))
	if err != nil {
		return nil, err
	}
	return cvcTLV(0x67, cvcConcat(request, outerCAR, cvcTLV(0x5F37, outer))), nil
}

// GenerateKey generates a key on the card, as the token's key generation
// does: a CSR over it for commonName (as the host's PKCS#11 module makes
// one) and the authenticated request the card answered with. The key never
// leaves the stand-in.
func (s *SmartCardHSM) GenerateKey(commonName string) (csrDER, authenticatedRequest []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	if csrDER, err = x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}, key); err != nil {
		return nil, nil, err
	}
	if authenticatedRequest, err = s.Attest(key); err != nil {
		return nil, nil, err
	}
	return csrDER, authenticatedRequest, nil
}

// AttestWithAnotherDevice is Attest signed by a device key the DICA never
// certified: a forged attestation.
func (s *SmartCardHSM) AttestWithAnotherDevice(key *ecdsa.PrivateKey) ([]byte, error) {
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	forged := *s
	forged.deviceKey = other
	return forged.Attest(key)
}

func cvCertificate(issuer *ecdsa.PrivateKey, car, chr string, pub *ecdsa.PublicKey, withParams bool, from, until time.Time) ([]byte, error) {
	body := cvcTLV(0x7F4E, cvcConcat(cvcTLV(0x5F29, []byte{0}), cvcTLV(0x42, []byte(car)), cvcPublicKey(pub, withParams),
		cvcTLV(0x5F20, []byte(chr)), cvcTLV(0x5F25, cvcDate(from)), cvcTLV(0x5F24, cvcDate(until))))
	sig, err := cvcSign(issuer, body)
	if err != nil {
		return nil, err
	}
	return cvcTLV(0x7F21, cvcConcat(body, cvcTLV(0x5F37, sig))), nil
}

// cvcPublicKey is a 7F49 public key; a CA's carries the P-256 domain
// parameters, a certificate below it inherits them.
func cvcPublicKey(pub *ecdsa.PublicKey, withParams bool) []byte {
	p := pub.Params()
	point := cvcPoint(p.Gx.Bytes(), p.Gy.Bytes(), p.BitSize)
	fields := [][]byte{cvcTLV(0x06, cvcECDSASHA256)}
	if withParams {
		a := make([]byte, (p.BitSize+7)/8)
		new(big.Int).Sub(p.P, big.NewInt(3)).FillBytes(a)
		fields = append(fields, cvcTLV(0x81, p.P.Bytes()), cvcTLV(0x82, a), cvcTLV(0x83, p.B.Bytes()), cvcTLV(0x84, point),
			cvcTLV(0x85, p.N.Bytes()), cvcTLV(0x87, []byte{1}))
	}
	key, _ := pub.Bytes() // #nosec G104 -- a P-256 key the stand-in generated always encodes
	fields = append(fields, cvcTLV(0x86, key))
	return cvcTLV(0x7F49, cvcConcat(fields...))
}

func cvcPoint(x, y []byte, bits int) []byte {
	size := (bits + 7) / 8
	out := make([]byte, 1+2*size)
	out[0] = 4
	copy(out[1+size-len(x):1+size], x)
	copy(out[1+2*size-len(y):], y)
	return out
}

// cvcSign signs data's SHA-256 with key, in plain r||s form (TR-03111).
func cvcSign(key *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	digest := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return nil, err
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out, nil
}

// cvcDate is YYMMDD, one digit a byte.
func cvcDate(t time.Time) []byte {
	y, m, d := t.Year()%100, int(t.Month()), t.Day()
	return []byte{byte(y / 10), byte(y % 10), byte(m / 10), byte(m % 10), byte(d / 10), byte(d % 10)} // #nosec G115 -- each value is one decimal digit (CWE-190)
}

func cvcTLV(tag int, value []byte) []byte {
	var out []byte
	if tag > 0xFF {
		out = append(out, byte(tag>>8), byte(tag)) // #nosec G115 -- a CV tag is at most two bytes (CWE-190)
	} else {
		out = append(out, byte(tag)) // #nosec G115 -- a one-byte tag (CWE-190)
	}
	switch n := len(value); {
	case n < 0x80:
		out = append(out, byte(n))
	case n <= 0xFF:
		out = append(out, 0x81, byte(n))
	default:
		out = append(out, 0x82, byte(n>>8), byte(n)) // #nosec G115 -- a stand-in element is under 64 KiB (CWE-190)
	}
	return append(out, value...)
}

func cvcConcat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
