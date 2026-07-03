package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
)

func TestSpineBurstProfileOverridesAndValidation(t *testing.T) {
	cfg := defaultProfile("cap-small")
	applyOverrides(&cfg, 3, 15, 90, 30, 2, 4, 0)
	if cfg.Samples != 3 || cfg.Step != 15*time.Second || cfg.EventWorkload != 90 || cfg.OutboxWorkload != 30 || cfg.Tenants != 2 || cfg.Agents != 4 {
		t.Fatalf("applyOverrides did not update profile: %+v", cfg)
	}
	if cfg.SlowUpstream != 0 {
		t.Fatalf("slow upstream = %s, want disabled", cfg.SlowUpstream)
	}
	if err := validateProfile(cfg); err != nil {
		t.Fatalf("validateProfile: %v", err)
	}
	for _, bad := range []profileConfig{
		{Name: "few-samples", Samples: 1, Step: time.Second, Tenants: 1, Agents: 1, EventWorkload: 1, OutboxWorkload: 1},
		{Name: "zero-step", Samples: 2, Tenants: 1, Agents: 1, EventWorkload: 1, OutboxWorkload: 1},
		{Name: "zero-work", Samples: 2, Step: time.Second, Tenants: 0, Agents: 1, EventWorkload: 1, OutboxWorkload: 1},
	} {
		if err := validateProfile(bad); err == nil {
			t.Fatalf("validateProfile(%+v) succeeded, want error", bad)
		}
	}
}

func TestSpineBurstCapacityProfilesPinExternalDatastores(t *testing.T) {
	cases := []struct {
		name      string
		tier      string
		tenants   int
		agents    int
		artifact  string
		pgMode    string
		natsMode  string
		replicas  int
		sourceHas string
	}{
		{
			name:      "cap-small",
			tier:      "CAP-SMALL",
			tenants:   5,
			agents:    50,
			artifact:  "scripts/perf/artifacts/spine-burst-cap-small.json",
			pgMode:    config.PostgresBundled,
			natsMode:  config.NATSEmbedded,
			replicas:  1,
			sourceHas: "embedded-postgres+embedded-jetstream",
		},
		{
			name:      "cap-medium",
			tier:      "CAP-MEDIUM",
			tenants:   50,
			agents:    500,
			artifact:  "scripts/perf/artifacts/spine-burst-cap-medium.json",
			pgMode:    config.PostgresExternal,
			natsMode:  config.NATSExternal,
			replicas:  config.DefaultExternalReplicas,
			sourceHas: "external-postgresql+external-jetstream",
		},
		{
			name:      "cap-large",
			tier:      "CAP-LARGE",
			tenants:   250,
			agents:    2000,
			artifact:  "scripts/perf/artifacts/spine-burst-cap-large.json",
			pgMode:    config.PostgresExternal,
			natsMode:  config.NATSExternal,
			replicas:  config.DefaultExternalReplicas,
			sourceHas: "external-postgresql+external-jetstream",
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			cfg := defaultProfile(tt.name)
			if cfg.CapacityTier != tt.tier || cfg.Tenants != tt.tenants || cfg.Agents != tt.agents {
				t.Fatalf("profile = %+v, want tier %s tenants %d agents %d", cfg, tt.tier, tt.tenants, tt.agents)
			}
			if cfg.PostgresMode != tt.pgMode || cfg.NATSMode != tt.natsMode || cfg.NATSReplicas != tt.replicas {
				t.Fatalf("datastore profile = pg %q nats %q replicas %d, want pg %q nats %q replicas %d", cfg.PostgresMode, cfg.NATSMode, cfg.NATSReplicas, tt.pgMode, tt.natsMode, tt.replicas)
			}
			if cfg.MeasurementArtifact != tt.artifact {
				t.Fatalf("measurement artifact = %q, want %q", cfg.MeasurementArtifact, tt.artifact)
			}
			if !strings.Contains(cfg.Source, tt.sourceHas) {
				t.Fatalf("source = %q, want it to contain %q", cfg.Source, tt.sourceHas)
			}
		})
	}
}

func TestSpineBurstExternalNATSConfigReadsRunopsEnv(t *testing.T) {
	t.Setenv("TRSTCTL_NATS_URL", "nats://perf-nats.example:4222")
	t.Setenv("TRSTCTL_NATS_REPLICAS", "5")
	t.Setenv("TRSTCTL_NATS_ALLOW_SINGLE_REPLICA", "true")

	got, err := externalNATSConfig(defaultProfile("cap-medium"))
	if err != nil {
		t.Fatalf("externalNATSConfig: %v", err)
	}
	if got.Mode != config.NATSExternal || got.URL != "nats://perf-nats.example:4222" || got.Replicas != 5 || !got.AllowSingleReplica {
		t.Fatalf("external nats config = %+v", got)
	}
}

func TestSpineBurstExternalNATSConfigRequiresURL(t *testing.T) {
	t.Setenv("TRSTCTL_NATS_URL", "")

	_, err := externalNATSConfig(defaultProfile("cap-large"))
	if err == nil || !strings.Contains(err.Error(), "TRSTCTL_NATS_URL") {
		t.Fatalf("externalNATSConfig error = %v, want missing URL guidance", err)
	}
}

func TestSpineBurstMathAndMarshalHelpers(t *testing.T) {
	if got := uuidFromInt(42); got != "00000000-0000-4000-8000-00000000002a" {
		t.Fatalf("uuidFromInt = %q", got)
	}
	if ceilDiv(0, 9) != 0 || ceilDiv(10, 3) != 4 {
		t.Fatalf("ceilDiv unexpected")
	}
	if minInt(4, 9) != 4 || maxInt(4, 9) != 9 {
		t.Fatalf("min/max unexpected")
	}
	if percentile(nil, 0.95) != 0 {
		t.Fatalf("percentile(nil) should be 0")
	}
	if got := percentile([]float64{10, 1, 5, 20}, 0.95); got != 20 {
		t.Fatalf("p95 = %.1f, want 20", got)
	}
	data, err := marshal(map[string]any{"ok": true}, false)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.HasSuffix(string(data), "\n") {
		t.Fatalf("marshal output missing trailing newline: %q", data)
	}
	var decoded map[string]bool
	if err := json.Unmarshal(data, &decoded); err != nil || !decoded["ok"] {
		t.Fatalf("marshal output did not decode: %v %#v", err, decoded)
	}
}
