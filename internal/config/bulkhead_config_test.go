// SPDX-License-Identifier: MPL-2.0

package config

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/bulkhead"
)

func TestBulkheadEnvOverridesAndConfigs(t *testing.T) {
	env := map[string]string{
		"TRSTCTL_BULKHEAD_API_WORKERS":               "11",
		"TRSTCTL_BULKHEAD_API_QUEUE":                 "333",
		"TRSTCTL_BULKHEAD_OUTBOX_WORKERS":            "5",
		"TRSTCTL_BULKHEAD_OUTBOX_QUEUE":              "99",
		"TRSTCTL_BULKHEAD_OUTBOX_CONNECTORS_WORKERS": "2",
		"TRSTCTL_BULKHEAD_PROTOCOLS_WORKERS":         "13",
		"TRSTCTL_BULKHEAD_PROTOCOLS_QUEUE":           "377",
	}
	cfg, err := Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("Load with bulkhead env: %v", err)
	}
	got := map[string]bulkhead.Config{}
	for _, cfg := range cfg.Bulkheads.Configs() {
		got[cfg.Name] = cfg
	}
	for name, want := range map[string]bulkhead.Config{
		bulkhead.SubsystemAPI:                 {Name: bulkhead.SubsystemAPI, Workers: 11, Queue: 333},
		bulkhead.SubsystemOutbox:              {Name: bulkhead.SubsystemOutbox, Workers: 5, Queue: 99},
		bulkhead.SubsystemOutboxExternalCA:    {Name: bulkhead.SubsystemOutboxExternalCA, Workers: 5, Queue: 99},
		bulkhead.SubsystemOutboxConnectors:    {Name: bulkhead.SubsystemOutboxConnectors, Workers: 2, Queue: 99},
		bulkhead.SubsystemOutboxSecrets:       {Name: bulkhead.SubsystemOutboxSecrets, Workers: 5, Queue: 99},
		bulkhead.SubsystemOutboxSecretSync:    {Name: bulkhead.SubsystemOutboxSecretSync, Workers: 5, Queue: 99},
		bulkhead.SubsystemOutboxManagedKeys:   {Name: bulkhead.SubsystemOutboxManagedKeys, Workers: 5, Queue: 99},
		bulkhead.SubsystemOutboxTransparency:  {Name: bulkhead.SubsystemOutboxTransparency, Workers: 5, Queue: 99},
		bulkhead.SubsystemOutboxCodeSigning:   {Name: bulkhead.SubsystemOutboxCodeSigning, Workers: 5, Queue: 99},
		bulkhead.SubsystemOutboxNotifications: {Name: bulkhead.SubsystemOutboxNotifications, Workers: 5, Queue: 99},
		bulkhead.SubsystemOutboxTenantSeal:    {Name: bulkhead.SubsystemOutboxTenantSeal, Workers: 5, Queue: 99},
		bulkhead.SubsystemOutboxFleet:         {Name: bulkhead.SubsystemOutboxFleet, Workers: 5, Queue: 99},
		bulkhead.SubsystemProtocols:           {Name: bulkhead.SubsystemProtocols, Workers: 13, Queue: 377},
	} {
		if got[name] != want {
			t.Fatalf("%s config = %+v, want %+v", name, got[name], want)
		}
	}
}

func TestBulkheadValidationRejectsInvalidValues(t *testing.T) {
	cases := map[string]struct {
		mutate func(*Config)
		want   string
	}{
		"zero workers": {
			mutate: func(c *Config) { c.Bulkheads.API.Workers = 0 },
			want:   "bulkheads.api.workers",
		},
		"negative workers": {
			mutate: func(c *Config) { c.Bulkheads.Query.Workers = -1 },
			want:   "bulkheads.query.workers",
		},
		"zero queue": {
			mutate: func(c *Config) { c.Bulkheads.Agent.Queue = 0 },
			want:   "bulkheads.agent.queue",
		},
		"negative queue": {
			mutate: func(c *Config) { c.Bulkheads.Signing.Queue = -1 },
			want:   "bulkheads.signing.queue",
		},
		"invalid outbox family override": {
			mutate: func(c *Config) {
				c.Bulkheads.OutboxSecrets = &BulkheadLimit{Workers: 0, Queue: 1}
			},
			want: "bulkheads.outbox.secrets.workers",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := Default()
			tc.mutate(cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatal("Validate accepted an invalid bulkhead limit")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validation error %q does not name %q", err, tc.want)
			}
		})
	}
}
