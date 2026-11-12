// SPDX-License-Identifier: BUSL-1.1

package certinfo

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// MaxChainCertificates bounds the certificates CertificateChainDER returns,
// the same bound ParsePublicPEMChain keeps.
const MaxChainCertificates = 8

// CertificateChainDER returns each certificate's canonical DER from a single
// DER certificate or an exact, public-only PEM bundle of CERTIFICATE blocks,
// in order (B13-L1: a cloud provider returns a certificate with its chain).
// The bundle is held to ParsePublicPEMChain's envelope: anything that is not
// a parseable certificate, text around or between the blocks, headers, or
// more than MaxChainCertificates certificates or MaxPublicChainBytes is
// refused.
func CertificateChainDER(raw []byte) ([][]byte, error) {
	if len(raw) == 0 || len(raw) > MaxPublicChainBytes {
		return nil, errors.New("certinfo: a bounded certificate or chain is required")
	}
	if !bytes.HasPrefix(bytes.TrimSpace(raw), []byte("-----BEGIN")) {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return nil, errors.New("certinfo: not a certificate")
		}
		return [][]byte{bytes.Clone(cert.Raw)}, nil
	}
	first, _ := pem.Decode(bytes.TrimSpace(raw))
	if first == nil {
		return nil, errors.New("certinfo: not a certificate chain")
	}
	public, err := ParsePublicPEMChain(raw, first.Bytes)
	if err != nil {
		return nil, err
	}
	var out [][]byte
	for rest := public; ; {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		out = append(out, block.Bytes)
		rest = remaining
	}
	if len(out) == 0 || len(out) > MaxChainCertificates {
		return nil, errors.New("certinfo: not a certificate chain")
	}
	return out, nil
}
