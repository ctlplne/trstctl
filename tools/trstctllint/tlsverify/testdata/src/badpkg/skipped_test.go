// SPDX-License-Identifier: MPL-2.0

package badpkg

// A _test.go file speaks to its own local listener; skipping verification
// there is not a served path and is not flagged.
import "crypto/tls"

func testOnlyConfig() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true}
}

var _ = testOnlyConfig
