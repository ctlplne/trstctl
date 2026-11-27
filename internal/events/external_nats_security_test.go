// SPDX-License-Identifier: BUSL-1.1

package events_test

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

func TestC0012ExternalEventLogRefusesInsecureConnectionBeforeDial(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  config.NATS
		want string
	}{
		{"plaintext", config.NATS{Mode: config.NATSExternal, URL: "nats://127.0.0.1:1", NKeySeedFile: "/unused"}, "tls://"},
		{"anonymous", config.NATS{Mode: config.NATSExternal, URL: "tls://127.0.0.1:1"}, "client identity"},
		{"URL secret", config.NATS{Mode: config.NATSExternal, URL: "tls://user:secret@127.0.0.1:1", NKeySeedFile: "/unused"}, "URL credentials"}, // #nosec G101 -- fabricated credential tests URL-secret rejection (CWE-798)
	} {
		t.Run(tc.name, func(t *testing.T) {
			log, err := events.Open(t.Context(), tc.cfg)
			if log != nil {
				_ = log.Close()
				t.Fatal("insecure external connection unexpectedly opened")
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("security refusal = %v, want %q", err, tc.want)
			}
		})
	}
}
