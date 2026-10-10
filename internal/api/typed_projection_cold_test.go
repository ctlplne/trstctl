// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"testing"

	configpkg "trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

func TestTypedRequestProjectionsRecoverAfterColdEventLogRestart(t *testing.T) {
	cfg := configpkg.NATS{Mode: configpkg.NATSEmbedded, StoreDir: t.TempDir()}
	log, err := events.Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct{ tenant, eventType, data string }{
		{"tenant-a", vaultMountEnabledEventType, `{"path":"secret/","type":"kv"}`},
		{"tenant-b", vaultMountEnabledEventType, `{"path":"other/","type":"kv"}`},
		{"tenant-a", "mdm.intune_scep_challenge", `{"decision":"allow","transaction_id":"tx-a"}`},
		{"tenant-a", policyVersionAuthoredEventType, `{"id":"policy-a","kind":"lifecycle","module":"package lifecycle","module_sha256":"digest-a","package":"lifecycle","query":"allow"}`},
		{"tenant-b", policyVersionAuthoredEventType, `{"id":"policy-b","kind":"lifecycle","module":"package lifecycle","module_sha256":"digest-b","package":"lifecycle","query":"allow"}`},
	} {
		if _, err := log.Append(t.Context(), events.Event{Type: item.eventType, TenantID: item.tenant, Data: []byte(item.data)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	log, err = events.Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	vault, err := newVaultCompatState(log).snapshot(t.Context(), "tenant-a")
	if err != nil || len(vault.mounts) != 1 || vault.mounts["secret/"].Type != "kv" {
		t.Fatalf("cold Vault projection = %+v, err=%v", vault, err)
	}
	a := &API{log: log}
	mdm, err := a.mdmSCEPTelemetry(t.Context(), "tenant-a")
	if err != nil || mdm.Allowed != 1 {
		t.Fatalf("cold MDM projection = %+v, err=%v", mdm, err)
	}
	policies, err := a.policyVersions(t.Context(), "tenant-a")
	if err != nil || len(policies.items) != 1 || policies.items["policy-a"] == nil {
		t.Fatalf("cold policy projection = %+v, err=%v", policies, err)
	}
}
