// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"testing"
	"trstctl.com/trstctl/internal/bulkhead"
)

func TestEventKeyDeliveryBulkheadsHaveIndependentOverrides(t *testing.T) {
	env := map[string]string{
		"TRSTCTL_BULKHEAD_OUTBOX_WORKERS": "5", "TRSTCTL_BULKHEAD_OUTBOX_QUEUE": "99",
		"TRSTCTL_BULKHEAD_OUTBOX_EVENT_KEY_PREPARATION_WORKERS": "1", "TRSTCTL_BULKHEAD_OUTBOX_EVENT_KEY_PREPARATION_QUEUE": "2",
		"TRSTCTL_BULKHEAD_OUTBOX_EVENT_KEY_DESTRUCTION_WORKERS": "2", "TRSTCTL_BULKHEAD_OUTBOX_EVENT_KEY_DESTRUCTION_QUEUE": "3",
	}
	cfg, err := Load(func(key string) string { return env[key] })
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bulkhead.Config{}
	for _, pool := range cfg.Bulkheads.Configs() {
		got[pool.Name] = pool
	}
	for name, want := range map[string]bulkhead.Config{
		bulkhead.SubsystemOutbox:                    {Name: bulkhead.SubsystemOutbox, Workers: 5, Queue: 99},
		bulkhead.SubsystemOutboxEventKeyPreparation: {Name: bulkhead.SubsystemOutboxEventKeyPreparation, Workers: 1, Queue: 2},
		bulkhead.SubsystemOutboxEventKeyDestruction: {Name: bulkhead.SubsystemOutboxEventKeyDestruction, Workers: 2, Queue: 3},
	} {
		if got[name] != want {
			t.Fatalf("pool %s got%+v want%+v", name, got[name], want)
		}
	}
}
