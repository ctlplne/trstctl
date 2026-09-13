// SPDX-License-Identifier: MPL-2.0

package mtls

import "crypto/tls"

// SMTPClientTLSConfig preserves verified STARTTLS for an external SMTP relay.
// System roots and the exact relay hostname remain mandatory. TLS 1.2 is the
// compatibility floor for this external integration, as for directory clients.
func SMTPClientTLSConfig(serverName string) *tls.Config {
	return &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12}
}
