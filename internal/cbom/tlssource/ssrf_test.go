// SPDX-License-Identifier: BUSL-1.1

package tlssource

import (
	"context"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/netsec"
)

func TestCR056CBOMDefaultTLSProbesBlockInternalAddresses(t *testing.T) {
	for _, target := range []string{"127.0.0.1:9", "localhost:9", "10.1.2.3:443", "169.254.169.254:443", "[::1]:443"} {
		t.Run(target, func(t *testing.T) {
			for _, probe := range []struct {
				name string
				run  Prober
			}{{"ordinary", defaultProber}, {"compatibility", compatibilityProber}} {
				t.Run(probe.name, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
					defer cancel()
					_, err := probe.run(ctx, target)
					if !errors.Is(err, netsec.ErrSSRFBlocked) {
						t.Fatalf("CBOM TLS probe attempted private target %q: %v", target, err)
					}
				})
			}
		})
	}
}
