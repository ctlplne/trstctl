// SPDX-License-Identifier: MPL-2.0

package terraformprovider

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net/http"
)

// httpTransport returns a transport that trusts the CA certificate(s) in caPEM
// and nothing else. The provider is its own module outside the control plane's
// AN-3 crypto boundary, so it carries this small helper itself.
func httpTransport(caPEM []byte) (*http.Transport, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("terraform-provider: no CA certificates found in PEM")
	}
	return &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}, nil
}

// sha256Hex is the lowercase hex SHA-256 of b.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
