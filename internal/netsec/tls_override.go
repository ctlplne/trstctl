// SPDX-License-Identifier: BUSL-1.1

package netsec

import (
	"errors"
	"net/http"

	"trstctl.com/trstctl/internal/crypto/trust"
)

// AdoptTLSConfig copies a reviewed crypto-boundary client TLS configuration
// onto an HTTP transport that already owns a scoped dialer or egress policy.
// The copy is hardened again at this boundary, so replacing TLSClientConfig
// cannot silently remove the active operator distrust check. Call before the
// destination transport starts serving requests.
func AdoptTLSConfig(destination, source *http.Transport) error {
	if destination == nil || source == nil || source.TLSClientConfig == nil {
		return errors.New("netsec: TLS override needs both transports and a client TLS configuration")
	}
	if source.TLSClientConfig.InsecureSkipVerify {
		return errors.New("netsec: TLS override cannot disable peer verification")
	}
	destination.TLSClientConfig = trust.HardenTLSConfig(source.TLSClientConfig.Clone())
	return nil
}
