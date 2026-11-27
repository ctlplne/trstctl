// SPDX-License-Identifier: BUSL-1.1

package breakglass

import (
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

func TestConfiguredAdminActorIsBoundToItsTenant(t *testing.T) {
	svc := NewAdminService(AdminConfig{
		Enabled: true, TenantID: "tenant-a",
		Params: crypto.Argon2idParams{MemoryKiB: 1024, Iterations: 1, Parallelism: 1, SaltLen: 16, KeyLen: 32},
	})
	if err := svc.SetPassword("recovery-admin", []byte("local-test-password")); err != nil {
		t.Fatal(err)
	}
	if !svc.IsAdminActor("tenant-a", "recovery-admin") {
		t.Fatal("configured emergency actor was not recognized")
	}
	if svc.IsAdminActor("tenant-b", "recovery-admin") || svc.IsAdminActor("tenant-a", "other-member") {
		t.Fatal("emergency actor matched outside its exact tenant and subject")
	}
}
