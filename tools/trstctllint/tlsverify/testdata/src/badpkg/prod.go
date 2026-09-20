// SPDX-License-Identifier: BUSL-1.1

package badpkg

// A production file outside the prober may not disable verification, in
// either the composite-literal or the assignment form.
import "crypto/tls"

func literal() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true} // want "InsecureSkipVerify: true disables TLS certificate verification"
}

func assign(cfg *tls.Config) {
	cfg.InsecureSkipVerify = true // want "InsecureSkipVerify: true disables TLS certificate verification"
}

var _ = literal
var _ = assign
