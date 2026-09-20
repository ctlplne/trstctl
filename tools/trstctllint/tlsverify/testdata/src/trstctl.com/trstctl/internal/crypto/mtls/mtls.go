// SPDX-License-Identifier: BUSL-1.1

package mtls

// The loopback liveness probe is the one sanctioned function outside the
// prober package; any other function in this package is still flagged.
import (
	"crypto/tls"
	"net/http"
)

func LoopbackProbeClient() *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
}

func somewhereElse() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true} // want "InsecureSkipVerify: true disables TLS certificate verification"
}

var _ = LoopbackProbeClient
var _ = somewhereElse
