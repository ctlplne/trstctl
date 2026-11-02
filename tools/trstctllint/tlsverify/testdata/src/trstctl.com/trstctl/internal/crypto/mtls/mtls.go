// SPDX-License-Identifier: BUSL-1.1

package mtls

// No function in this package may skip verification, the loopback liveness
// probe included: it pins the certificate the listener serves.
import (
	"crypto/tls"
	"net/http"
)

func LoopbackProbeClient() *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} // want "InsecureSkipVerify: true disables TLS certificate verification"
}

func somewhereElse() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true} // want "InsecureSkipVerify: true disables TLS certificate verification"
}

var _ = LoopbackProbeClient
var _ = somewhereElse
