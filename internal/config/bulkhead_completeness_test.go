// SPDX-License-Identifier: MPL-2.0

package config

import (
	"testing"

	"trstctl.com/trstctl/internal/bulkhead"
)

// TestBulkheadConfigCoversEveryRegisteredSubsystem is the completeness guard
// for AUD-201 follow-up A2/V11. bulkhead.DefaultConfigs() registered a kmip
// lane and the runtime code was written to use it — but config.Bulkheads never
// learned the subsystem, so the production set built from
// cfg.Bulkheads.Configs() had no kmip pool and the runtime silently fell back
// to the shared protocols pool. The mechanism that failed was the missing
// registration, not one lane: this test makes the whole class impossible by
// asserting every subsystem the bulkhead package registers is representable in
// deployment config, with a positive default.
func TestBulkheadConfigCoversEveryRegisteredSubsystem(t *testing.T) {
	items := map[string]BulkheadLimit{}
	for _, item := range defaultBulkheads().items() {
		items[item.name] = item.limit
	}
	for _, registered := range bulkhead.DefaultConfigs() {
		limit, ok := items[registered.Name]
		if !ok {
			t.Errorf("subsystem %q is registered in bulkhead.DefaultConfigs() but absent from config.Bulkheads.items(); "+
				"the production config-derived set will have no %q pool and the runtime will fall back or fail", registered.Name, registered.Name)
			continue
		}
		if limit.Workers <= 0 || limit.Queue <= 0 {
			t.Errorf("subsystem %q has default workers=%d queue=%d; defaultBulkheads() must carry the registered default "+
				"(%d/%d) or every deployment fails validation", registered.Name, limit.Workers, limit.Queue, registered.Workers, registered.Queue)
		}
	}
}

// TestBulkheadKMIPEnvOverrides pins the operator surface for the kmip lane.
func TestBulkheadKMIPEnvOverrides(t *testing.T) {
	env := map[string]string{
		"TRSTCTL_BULKHEAD_KMIP_WORKERS": "5",
		"TRSTCTL_BULKHEAD_KMIP_QUEUE":   "23",
	}
	cfg, err := Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Bulkheads.KMIP.Workers != 5 || cfg.Bulkheads.KMIP.Queue != 23 {
		t.Fatalf("bulkheads.kmip env override not applied: %+v", cfg.Bulkheads.KMIP)
	}
	var found *bulkhead.Config
	for _, c := range cfg.Bulkheads.Configs() {
		if c.Name == bulkhead.SubsystemKMIP {
			c := c
			found = &c
		}
	}
	if found == nil {
		t.Fatal("Configs() emitted no kmip lane")
	}
	if found.Workers != 5 || found.Queue != 23 {
		t.Fatalf("Configs() kmip lane = %+v, want workers 5 queue 23", found)
	}
}
