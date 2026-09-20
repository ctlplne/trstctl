// SPDX-License-Identifier: BUSL-1.1

// Package netsec is the analyzer fixture stand-in for the real
// internal/netsec: the package that IMPLEMENTS the sanctioned outbound path.
// It must be able to construct an *http.Client, so it is expected to produce no
// diagnostics even though it holds a bare composite literal.
package netsec

import (
	"net/http"
	"time"
)

// SafeClient mirrors the real constructor's signature.
func SafeClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &http.Client{Timeout: timeout}
}
