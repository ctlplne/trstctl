// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"strings"
	"testing"
)

// M4-L6: protocols.spiffe.exchange_requests_per_minute is 0 (the default)
// or up to 60000 requests a client address a minute.
func TestExchangeRequestsPerMinuteIsValidatedM4L6(t *testing.T) {
	for _, n := range []int{0, 1, DefaultExchangeRequestsPerMinute, 60000} {
		p := Protocols{SPIFFE: SPIFFEProtocol{ExchangeRequestsPerMinute: n}}
		for _, err := range p.ValidateTenantBindings("") {
			if strings.Contains(err.Error(), "exchange_requests_per_minute") {
				t.Fatalf("limit %d rejected: %v", n, err)
			}
		}
	}
	for _, n := range []int{-1, 60001} {
		p := Protocols{SPIFFE: SPIFFEProtocol{ExchangeRequestsPerMinute: n}}
		found := false
		for _, err := range p.ValidateTenantBindings("") {
			found = found || strings.Contains(err.Error(), "protocols.spiffe.exchange_requests_per_minute")
		}
		if !found {
			t.Fatalf("limit %d was accepted", n)
		}
	}
}
