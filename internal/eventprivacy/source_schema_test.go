// SPDX-License-Identifier: BUSL-1.1

package eventprivacy_test

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/events"
)

func TestSourceLifetimeRefusesUnknownLifecycleSchema(t *testing.T) {
	for _, kind := range []string{"tenant.registered", "tenant.offboarded"} {
		t.Run(kind, func(t *testing.T) {
			log, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(t.TempDir(), "events")})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = log.Close() })
			if kind == "tenant.offboarded" {
				appendSource(t, log, "known-registration", "tenant.registered", time.Now().UTC().Add(-time.Second), struct {
					Name string `json:"name"`
				}{"fixture"})
			}
			data := []byte(`{"name":"fixture"}`)
			if kind == "tenant.offboarded" {
				data = []byte(`{"rows_deleted":0}`)
			}
			if _, err := log.Append(t.Context(), events.Event{ID: "unknown-lifecycle-schema", Type: kind, TenantID: sourceTenant, SchemaVersion: 999, Data: data}); err != nil {
				t.Fatal(err)
			}
			if _, err := (eventprivacy.SourcePolicy{Log: log}).LatestLifetime(t.Context(), sourceTenant); !errors.Is(err, eventprivacy.ErrSource) {
				t.Fatalf("unsupported lifecycle schema granted authority: %v", err)
			}
		})
	}
}
