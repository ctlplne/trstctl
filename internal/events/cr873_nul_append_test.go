// SPDX-License-Identifier: BUSL-1.1

package events

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

func TestCR873NULInEventStringsIsRejectedBeforeAppend(t *testing.T) {
	log, err := openFixture(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	for _, tc := range []struct {
		name  string
		event Event
	}{
		{"nested value", Event{Type: "test.nul", TenantID: "tenant-a", Data: []byte(`{"reason":{"inner":"bad\u0000value"}}`)}},
		{"object key", Event{Type: "test.nul", TenantID: "tenant-a", Data: []byte(`{"bad\u0000key":true}`)}},
		{"actor subject", Event{Type: "test.nul", TenantID: "tenant-a", Data: []byte(`{}`), Actor: &Actor{Subject: "bad\x00actor"}}},
		{"actor role", Event{Type: "test.nul", TenantID: "tenant-a", Data: []byte(`{}`), Actor: &Actor{Subject: "operator", Roles: []string{"bad\x00role"}}}},
		{"event type", Event{Type: "bad\x00type", TenantID: "tenant-a", Data: []byte(`{}`)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before, err := log.LastSequence(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			_, err = log.Append(t.Context(), tc.event)
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), "nul") {
				t.Errorf("unsafe event append error = %v, want NUL refusal", err)
			}
			after, err := log.LastSequence(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if after != before {
				t.Errorf("unsafe event changed immutable log sequence from %d to %d", before, after)
			}
		})
	}
}
