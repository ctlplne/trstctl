// SPDX-License-Identifier: BUSL-1.1

package dbdsn

import (
	"errors"

	"trstctl.com/trstctl/internal/crypto/certinfo"
)

const MaxTrustBytes = certinfo.MaxPublicChainBytes

var ErrTrust = errors.New("database trust must contain bounded public certificate PEM and a valid certificate name")

// NormalizeTrust validates public trust independently of any DSN. It admits
// an empty bundle for system roots and returns a canonical certificate envelope
// for stable job binding.
func NormalizeTrust(pem []byte, serverName string) ([]byte, string, error) {
	if len(pem) > MaxTrustBytes {
		return nil, "", ErrTrust
	}
	if serverName != "" {
		name, err := HostName(serverName)
		if err != nil {
			return nil, "", ErrTrust
		}
		serverName = name
	}
	if len(pem) == 0 {
		return nil, serverName, nil
	}
	normalized, err := certinfo.NormalizePublicCertificatePEM(pem)
	if err != nil || len(normalized) > MaxTrustBytes {
		return nil, "", ErrTrust
	}
	return normalized, serverName, nil
}
