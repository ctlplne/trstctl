// SPDX-License-Identifier: BUSL-1.1

package netsec

import (
	"testing"
	"time"
)

func TestOutboundClientForEndpointFollowsTheLoopbackRule(t *testing.T) {
	if c, err := OutboundClientForEndpoint("https://idp.example.test/artifact", time.Second); err != nil || c == nil {
		t.Fatalf("https endpoint = %v %v, want the safe client", c, err)
	}
	if c, err := OutboundClientForEndpoint("http://127.0.0.1:9/artifact", time.Second); err != nil || c == nil {
		t.Fatalf("loopback http endpoint = %v %v, want the loopback client", c, err)
	}
	for _, bad := range []string{"http://idp.example.test/artifact", "ftp://127.0.0.1/x", "/relative", ""} {
		if _, err := OutboundClientForEndpoint(bad, time.Second); err == nil {
			t.Fatalf("endpoint %q was admitted", bad)
		}
	}
}
