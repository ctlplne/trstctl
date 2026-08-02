// SPDX-License-Identifier: MPL-2.0

package tlsprobe

// The discovery prober is the one sanctioned production user: it inventories
// whatever certificate the endpoint serves and never trusts the connection.
import "crypto/tls"

func probeConfig() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true}
}

var _ = probeConfig
