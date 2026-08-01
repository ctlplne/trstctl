// SPDX-License-Identifier: MPL-2.0

package cleanpkg

// Leaving verification on is never flagged, including explicit false and an
// unrelated struct that happens to have a field of the same name.
import "crypto/tls"

type notTLS struct{ InsecureSkipVerify bool }

func fine() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: false}
}

func unrelated() notTLS {
	return notTLS{InsecureSkipVerify: true}
}

var _ = fine
var _ = unrelated
