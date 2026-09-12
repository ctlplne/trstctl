// SPDX-License-Identifier: MPL-2.0

package relay

import "trstctl.com/trstctl/internal/crypto/tlsprobe"

// connectorTLSNegotiation follows the explicit connector, never a guessed
// port. PostgreSQL needs SSLRequest even on a nondefault port. Other existing
// connectors retain their direct-TLS behavior.
func connectorTLSNegotiation(name string) tlsprobe.PreHandshake {
	if name == "postgresql" {
		return tlsprobe.PostgresSSLRequest
	}
	return nil
}
