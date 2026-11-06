// SPDX-License-Identifier: BUSL-1.1
package windependents

import (
	"context"
	"strings"
	"testing"
)

type ownedPoolDriver struct {
	current, readback Pool
	proof             PoolRestartProof
	running           []PoolWorker
	writes, restarts  int
}

func (d *ownedPoolDriver) discover(context.Context, string) ([]Pool, error) {
	return []Pool{d.current}, nil
}
func (d *ownedPoolDriver) inspect(context.Context, string) (Pool, error) { return d.current, nil }
func (d *ownedPoolDriver) update(context.Context, Pool, []byte) (Pool, error) {
	d.writes++
	return d.readback, nil
}
func (d *ownedPoolDriver) restart(context.Context, Pool) (PoolRestartProof, error) {
	d.restarts++
	return d.proof, nil
}
func (d *ownedPoolDriver) workers(context.Context, string) ([]PoolWorker, error) {
	return d.running, nil
}
func ownedPool() Pool {
	return Pool{Name: "owned-pool", AccountSID: "S-1-5-21-100-200-300-1001", ConfigSHA256: strings.Repeat("a", 64), EncryptionProvider: "owned-native-provider", PasswordProtected: true, WasStarted: true}
}
func ownedPoolRestart() PoolRestartProof {
	p := ownedPool()
	return PoolRestartProof{Name: p.Name, AccountSID: p.AccountSID, ConfigSHA256: p.ConfigSHA256, WasStarted: true, StoppedObserved: true, StartedObserved: true, PreviousPIDs: []uint32{40}}
}
func TestPoolNativeAuthorityAndProtectionA267(t *testing.T) {
	target := ownedPool()
	driver := &ownedPoolDriver{current: target, readback: target, proof: ownedPoolRestart()}
	adapter := Pools{driver: driver}
	for _, change := range []func(*Pool){func(p *Pool) { p.AccountSID = "S-1-5-21-100-200-300-1002" }, func(p *Pool) { p.ConfigSHA256 = strings.Repeat("b", 64) }, func(p *Pool) { p.EncryptionProvider = "different-provider" }, func(p *Pool) { p.Name = "different-pool" }} {
		driver.current = target
		change(&driver.current)
		if err := adapter.UpdatePassword(t.Context(), target, []byte("Tr5!owned-pool-password")); err == nil || driver.writes != 0 {
			t.Fatal("changed native pool authority reached credential mutation")
		}
		if _, err := adapter.Restart(t.Context(), target); err == nil || driver.restarts != 0 {
			t.Fatal("changed native pool authority reached restart")
		}
	}
	driver.current = target
	if err := adapter.UpdatePassword(t.Context(), target, []byte("Tr5!owned-pool-password")); err != nil || driver.writes != 1 {
		t.Fatal("bound native pool password update failed")
	}
	driver.readback.PasswordProtected = false
	if err := adapter.UpdatePassword(t.Context(), target, []byte("Tr5!owned-pool-password")); err == nil {
		t.Fatal("unprotected native password readback claimed complete")
	}
	driver.readback = target
	driver.readback.EncryptionProvider = "different-provider"
	if err := adapter.UpdatePassword(t.Context(), target, []byte("Tr5!owned-pool-password")); err == nil {
		t.Fatal("native encryption provider was silently substituted")
	}
}
func TestPoolNativeFreshWorkersA267(t *testing.T) {
	target := ownedPool()
	driver := &ownedPoolDriver{current: target, readback: target, proof: ownedPoolRestart(), running: []PoolWorker{{ProcessID: 41, AccountSID: target.AccountSID}}}
	adapter := Pools{driver: driver}
	proof, err := adapter.Restart(t.Context(), target)
	if err != nil {
		t.Fatal(err)
	}
	if workers, err := adapter.VerifyWorkers(t.Context(), target, proof); err != nil || len(workers) != 1 {
		t.Fatal("fresh native pool worker rejected")
	}
	for _, workers := range [][]PoolWorker{nil, {{ProcessID: 40, AccountSID: target.AccountSID}}, {{ProcessID: 41, AccountSID: "S-1-5-21-100-200-300-1002"}}, {{ProcessID: 41, AccountSID: target.AccountSID}, {ProcessID: 41, AccountSID: target.AccountSID}}} {
		driver.running = workers
		if _, err := adapter.VerifyWorkers(t.Context(), target, proof); err == nil {
			t.Fatal("missing/stale/foreign/duplicate worker was called verified")
		}
	}
	driver.proof.StoppedObserved = false
	if _, err := adapter.Restart(t.Context(), target); err == nil {
		t.Fatal("unproven native stop called a fresh restart")
	}
}
