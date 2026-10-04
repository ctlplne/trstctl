// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"testing"

	uuidlib "github.com/google/uuid"

	"trstctl.com/trstctl/internal/store"
)

func TestAuditCheckpointRLSIDPreservesUUIDAndMapsLegacyScope(t *testing.T) {
	if got, err := store.AuditCheckpointRLSID("  "); err == nil || got != "" {
		t.Fatalf("blank audit scope acquired RLS id %q, err %v", got, err)
	}
	const tenant = "33333333-3333-3333-3333-333333333333"
	if got, err := store.AuditCheckpointRLSID(tenant); err != nil || got != tenant {
		t.Fatalf("UUID tenant remapped to %s, err %v", got, err)
	}
	legacy, err := store.AuditCheckpointRLSID("provider-control-plane")
	if _, err := uuidlib.Parse(legacy); err != nil || legacy == store.ZeroUUID || legacy == tenant {
		t.Fatalf("legacy audit scope mapped to invalid or shared RLS id %q: %v", legacy, err)
	}
	if err != nil {
		t.Fatal(err)
	}
	if again, err := store.AuditCheckpointRLSID("provider-control-plane"); err != nil || again != legacy {
		t.Fatalf("legacy audit scope mapping changed: %q then %q, err %v", legacy, again, err)
	}
	for _, unsupported := range []string{"another-administrative-scope", "provider-control-plane/other", "provider-control-plane ", "00000000-0000-0000-0000-00000000000g"} {
		if got, err := store.AuditCheckpointRLSID(unsupported); err == nil || got != "" {
			t.Fatalf("unsupported audit scope %q acquired RLS id %q, err %v", unsupported, got, err)
		}
	}
}
