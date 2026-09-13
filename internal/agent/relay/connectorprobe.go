// SPDX-License-Identifier: MPL-2.0

package relay

import "trstctl.com/trstctl/internal/crypto/tlsprobe"

// connectorTLSNegotiation follows the explicit connector, never a guessed
// port. PostgreSQL and MySQL need their own SSLRequest even on nondefault ports.
// Other existing connectors retain their direct-TLS behavior.
func connectorTLSNegotiation(name string) tlsprobe.PreHandshake {
	switch name {
	case "postgresql":
		return tlsprobe.PostgresSSLRequest
	case "mysql":
		return tlsprobe.MySQLSSLRequest
	}
	return nil
}
