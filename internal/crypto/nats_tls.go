// SPDX-License-Identifier: BUSL-1.1

package crypto

import "crypto/tls"

// NATSTLSClientConfig pins verified TLS for the external event datastore.
// NATS's no-argument Secure option skips certificate verification, so the
// caller must pass this explicit configuration even with system roots.
func NATSTLSClientConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12}
}
