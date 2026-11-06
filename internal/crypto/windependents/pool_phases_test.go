// SPDX-License-Identifier: BUSL-1.1
package windependents

import (
	"context"
	"testing"
)

type phasedPoolDriverA267 struct {
	*ownedPoolDriver
	stops, starts int
}

func (d *phasedPoolDriverA267) stop(_ context.Context, p Pool) (PoolRestartProof, error) {
	d.stops++
	d.current.WasStarted = false
	return PoolRestartProof{Name: p.Name, AccountSID: p.AccountSID, ConfigSHA256: p.ConfigSHA256, WasStarted: p.WasStarted, StoppedObserved: true, PreviousPIDs: []uint32{40}}, nil
}
func (d *phasedPoolDriverA267) start(_ context.Context, p Pool, proof PoolRestartProof) (PoolRestartProof, error) {
	d.starts++
	d.current.WasStarted = true
	proof.StartedObserved = true
	return proof, nil
}
func TestPoolRotationSeparatesStopPasswordAndStartA267(t *testing.T) {
	target := ownedPool()
	driver := &phasedPoolDriverA267{ownedPoolDriver: &ownedPoolDriver{current: target, readback: target}}
	pools := Pools{driver: driver}
	stopped, e := pools.StopForRotation(t.Context(), target)
	if e != nil || driver.stops != 1 || driver.starts != 0 {
		t.Fatal("stop phase changed start state", e)
	}
	if e := pools.UpdatePassword(t.Context(), target, []byte("Tr5!owned-phased-password")); e != nil || driver.starts != 0 {
		t.Fatal("password update started pool before reviewed order", e)
	}
	started, e := pools.StartAfterRotation(t.Context(), target, stopped)
	if e != nil || driver.starts != 1 || !started.StartedObserved {
		t.Fatal("start did not restore native state", e)
	}
	foreign := stopped
	foreign.AccountSID = "S-1-5-21-100-200-300-1002"
	if _, e := pools.StartAfterRotation(t.Context(), target, foreign); e == nil || driver.starts != 1 {
		t.Fatal("foreign stop receipt reached native start")
	}
	inactive := target
	inactive.WasStarted = false
	stable := &phasedPoolDriverA267{ownedPoolDriver: &ownedPoolDriver{current: inactive, readback: inactive}}
	disabled := Pools{driver: stable}
	proof, e := disabled.StopForRotation(t.Context(), inactive)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := disabled.StartAfterRotation(t.Context(), inactive, proof); e != nil || stable.stops != 0 || stable.starts != 0 {
		t.Fatal("originally stopped pool was mutated", e)
	}
}
