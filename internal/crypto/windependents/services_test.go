// SPDX-License-Identifier: BUSL-1.1
package windependents

import (
	"context"
	"strings"
	"testing"
	"trstctl.com/trstctl/internal/crypto"
)

type ownedServiceDriver struct {
	current                 Service
	writes, restarts, reads int
	observed                string
	runtime                 Runtime
}

func (d *ownedServiceDriver) discover(context.Context, string) ([]Service, error) {
	return []Service{d.current}, nil
}
func (d *ownedServiceDriver) inspect(context.Context, string) (Service, error) {
	d.reads++
	return d.current, nil
}
func (d *ownedServiceDriver) update(_ context.Context, _ Service, password []byte) error {
	d.writes++
	d.observed = crypto.SHA256Hex(password)
	return nil
}
func (d *ownedServiceDriver) restart(context.Context, Service) (Runtime, error) {
	d.restarts++
	return d.runtime, nil
}
func ownedService() Service {
	return Service{Name: "owned-service", AccountSID: "S-1-5-21-100-200-300-1001", ConfigSHA256: strings.Repeat("a", 64), WasRunning: true}
}
func TestServiceNativeAuthorityA267(t *testing.T) {
	ctx := t.Context()
	expected := ownedService()
	for _, change := range []func(*Service){func(s *Service) { s.AccountSID = "S-1-5-21-100-200-300-1002" }, func(s *Service) { s.ConfigSHA256 = strings.Repeat("b", 64) }, func(s *Service) { s.Name = "different-service" }} {
		driver := &ownedServiceDriver{current: expected}
		change(&driver.current)
		adapter := Services{driver: driver}
		if err := adapter.UpdatePassword(ctx, expected, []byte("Tr5!owned-password-密碼")); err == nil || driver.writes != 0 {
			t.Fatal("changed native identity/config reached password mutation")
		}
		if _, err := adapter.RestartAndVerifyIdentity(ctx, expected); err == nil || driver.restarts != 0 {
			t.Fatal("changed native identity/config reached service restart")
		}
	}
	driver := &ownedServiceDriver{current: expected, runtime: Runtime{Running: true, ProcessID: 42, AccountSID: expected.AccountSID}}
	adapter := Services{driver: driver}
	password := []byte("Tr5!owned-password-密碼")
	if err := adapter.UpdatePassword(ctx, expected, password); err != nil || driver.writes != 1 || driver.observed != crypto.SHA256Hex(password) {
		t.Fatal("bound byte-backed native password update failed")
	}
	if _, err := adapter.RestartAndVerifyIdentity(ctx, expected); err != nil || driver.restarts != 1 {
		t.Fatal("native process identity verification failed")
	}
	driver.runtime.AccountSID = "S-1-5-21-100-200-300-1002"
	if _, err := adapter.RestartAndVerifyIdentity(ctx, expected); err == nil {
		t.Fatal("running as a different native SID was called verified")
	}
	driver.runtime = Runtime{Running: false}
	if _, err := adapter.RestartAndVerifyIdentity(ctx, expected); err == nil {
		t.Fatal("stopped required service was called verified")
	}
}
func TestServiceNativeBoundsBeforeEffectA267(t *testing.T) {
	expected := ownedService()
	driver := &ownedServiceDriver{current: expected}
	adapter := Services{driver: driver}
	for _, target := range []Service{{}, {Name: "../escape", AccountSID: expected.AccountSID, ConfigSHA256: expected.ConfigSHA256}, {Name: expected.Name, AccountSID: "S-1-5-18", ConfigSHA256: expected.ConfigSHA256}, {Name: expected.Name, AccountSID: expected.AccountSID, ConfigSHA256: "short"}} {
		if err := adapter.UpdatePassword(t.Context(), target, []byte("Tr5!owned-password")); err == nil {
			t.Fatal("invalid native authority admitted")
		}
	}
	for _, password := range [][]byte{nil, []byte("short"), append([]byte("Tr5!owned-password"), 0), append([]byte("Tr5!owned-password"), 255), make([]byte, 1025)} {
		if err := adapter.UpdatePassword(t.Context(), expected, password); err == nil {
			t.Fatal("invalid native password admitted")
		}
	}
	if driver.writes != 0 || driver.reads != 0 {
		t.Fatal("invalid request reached native I/O")
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := adapter.UpdatePassword(canceled, expected, []byte("Tr5!owned-password")); err == nil || driver.writes != 0 {
		t.Fatal("canceled native request reached an effect")
	}
}

func TestServiceNativeRejectsAlteredDependencyOrderA267(t *testing.T) {
	native := ownedService()
	native.Dependencies = []string{"owned-prerequisite"}
	driver := &ownedServiceDriver{current: native}
	adapter := Services{driver: driver}
	altered := native
	altered.Dependencies = []string{"different-prerequisite"}
	if err := adapter.UpdatePassword(t.Context(), altered, []byte("Tr5!owned-password")); err == nil || driver.writes != 0 {
		t.Fatal("altered restart dependencies reached a native password effect")
	}
}
