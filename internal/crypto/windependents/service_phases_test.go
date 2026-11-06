// SPDX-License-Identifier: BUSL-1.1
package windependents

import (
	"context"
	"testing"
)

type phasedServiceDriverA267 struct {
	*ownedServiceDriver
	stops, starts int
}

func (d *phasedServiceDriverA267) stop(context.Context, Service) (Runtime, error) {
	d.stops++
	d.current.WasRunning = false
	return Runtime{}, nil
}
func (d *phasedServiceDriverA267) start(_ context.Context, s Service) (Runtime, error) {
	d.starts++
	d.current.WasRunning = true
	return Runtime{Running: true, ProcessID: 42, AccountSID: s.AccountSID}, nil
}
func TestServiceRotationSeparatesStopAndStartA267(t *testing.T) {
	target := ownedService()
	driver := &phasedServiceDriverA267{ownedServiceDriver: &ownedServiceDriver{current: target}}
	service := Services{driver: driver}
	if _, err := service.StopForRotation(t.Context(), target); err != nil || driver.stops != 1 || driver.starts != 0 {
		t.Fatal("stop phase started a process or failed", err)
	}
	if _, err := service.StartAfterRotation(t.Context(), target); err != nil || driver.starts != 1 {
		t.Fatal("start phase failed", err)
	}
	stopped := target
	stopped.WasRunning = false
	stable := &phasedServiceDriverA267{ownedServiceDriver: &ownedServiceDriver{current: stopped}}
	adapter := Services{driver: stable}
	if _, err := adapter.StopForRotation(t.Context(), stopped); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.StartAfterRotation(t.Context(), stopped); err != nil || stable.starts != 0 || stable.stops != 0 {
		t.Fatal("formerly stopped service was mutated", err)
	}
	changed := target
	changed.AccountSID = "S-1-5-21-100-200-300-1002"
	wrong := &phasedServiceDriverA267{ownedServiceDriver: &ownedServiceDriver{current: changed}}
	if _, err := (&Services{driver: wrong}).StopForRotation(t.Context(), target); err == nil || wrong.stops != 0 {
		t.Fatal("changed native authority reached stop")
	}
}

func (d *phasedServiceDriverA267) observe(_ context.Context, s Service) (Runtime, error) {
	if !d.current.WasRunning {
		return Runtime{}, nil
	}
	return Runtime{Running: true, ProcessID: 37, AccountSID: d.current.AccountSID}, nil
}
func TestServiceRotationObservationCannotStartAStoppedProcessA267(t *testing.T) {
	target := ownedService()
	target.WasRunning = false
	driver := &phasedServiceDriverA267{ownedServiceDriver: &ownedServiceDriver{current: target}}
	svc := Services{driver: driver}
	got, e := svc.ObserveForRotation(t.Context(), target)
	if e != nil || got.Running || driver.starts != 0 || driver.stops != 0 {
		t.Fatal("read-only verification mutated native state", e)
	}
	driver.current.WasRunning = true
	if _, e := svc.ObserveForRotation(t.Context(), target); e == nil || driver.starts != 0 {
		t.Fatal("changed stopped state was accepted")
	}
}
