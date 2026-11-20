// SPDX-License-Identifier: BUSL-1.1

package dbtls

import (
	"crypto/tls"
	"errors"

	"trstctl.com/trstctl/internal/crypto/mtls"
)

// Mongo supplies verified TLS settings and caps the leaf's status endpoints
// before the driver allocates a goroutine for each one.
func Mongo(name string, ca []byte) (*tls.Config, error) {
	config, err := mtls.VerifiedClientTLSConfig(name, ca)
	if err != nil {
		return nil, err
	}
	config.VerifyConnection = func(peer tls.ConnectionState) error {
		if len(peer.PeerCertificates) == 0 || len(peer.PeerCertificates[0].OCSPServer) > 4 {
			return errors.New("MongoDB certificate status endpoints exceed the permitted bound")
		}
		return nil
	}
	return config, nil
}
