// SPDX-License-Identifier: LicenseRef-trstctl-EE

package enterpriseauth

import "trstctl.com/trstctl/internal/crypto"

// servedFixtureKey gives equal requests one bounded key with no reserved syntax.
func servedFixtureKey(method, path, body string) string {
	return crypto.SHA256Hex([]byte(method + "\x00" + path + "\x00" + body))
}
