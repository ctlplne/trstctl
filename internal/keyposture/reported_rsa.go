// SPDX-License-Identifier: BUSL-1.1

package keyposture

import (
	"bytes"
	"encoding/base64"
	"encoding/pem"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/weakkey"
)

// MetaRSASPKI carries a reported RSA public key: the standard base64 of its
// DER SubjectPublicKeyInfo. It is public key material, never a secret. It lets
// the control plane apply the operator's blocklists, which a reporter never
// holds, and find primes shared across the inventory by batch GCD (eMudhra,
// Part 4).
const MetaRSASPKI = "rsa_spki"

// maxRSASPKIBase64 bounds the reported value; a 16384-bit key's
// SubjectPublicKeyInfo is under 2.1 KB.
const maxRSASPKIBase64 = 3000

// RSASPKIMetadata returns the metadata value for an RSA certificate's key, or
// "" for another key or unparseable bytes. The certificate may be DER or PEM;
// a PEM bundle gives its first certificate's key.
func RSASPKIMetadata(cert []byte) string {
	der := cert
	if bytes.Contains(cert, []byte("-----BEGIN")) {
		der = nil
		for rest := cert; ; {
			block, remaining := pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type == "CERTIFICATE" {
				der = block.Bytes
				break
			}
			rest = remaining
		}
	}
	spki, ok := weakkey.RSASubjectPublicKeyInfo(der)
	if !ok {
		return ""
	}
	return base64.StdEncoding.EncodeToString(spki)
}

// ReportedRSAKey returns the RSA SubjectPublicKeyInfo a reporter attached when
// it decodes, parses as an RSA key within bounds, and hashes to the reported
// spki_sha256 when one is reported, so a report cannot pin another key on a
// certificate. Anything else is not used.
func ReportedRSAKey(value, spkiSHA256 string) ([]byte, bool) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxRSASPKIBase64 {
		return nil, false
	}
	der, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, false
	}
	if _, ok := weakkey.RSASubjectPublicKeyInfo(der); !ok {
		return nil, false
	}
	if want := strings.ToLower(strings.TrimSpace(spkiSHA256)); want != "" && crypto.SHA256Hex(der) != want {
		return nil, false
	}
	return der, true
}

// RateReportedRSAKey checks a reported RSA key with the control plane's own
// weak-key checks, which include the operator's blocklists.
func RateReportedRSAKey(spki []byte) Verdict {
	findings, err := weakkey.Default().CheckSPKI(spki)
	if err != nil {
		return Verdict{}
	}
	var v Verdict
	for _, f := range findings {
		v.WeakReasons = append(v.WeakReasons, f.Reason)
	}
	return v
}
