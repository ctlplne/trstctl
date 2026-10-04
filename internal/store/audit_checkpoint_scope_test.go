// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"testing"

	uuidlib "github.com/google/uuid"

	"trstctl.com/trstctl/internal/store"
)

func TestAuditCheckpointRLSIDPreservesUUIDAndMapsLegacyScope(t *testing.T) {
	if got := store.AuditCheckpointRLSID("  "); got != "" {
		t.Fatalf("blank audit scope acquired RLS id %q", got)
	}
	const tenant = "33333333-3333-3333-3333-333333333333"
	if got := store.AuditCheckpointRLSID(tenant); got != tenant {
		t.Fatalf("UUID tenant remapped to %s", got)
	}
	legacy := store.AuditCheckpointRLSID("provider-control-plane")
	if _, err := uuidlib.Parse(legacy); err != nil || legacy == store.ZeroUUID || legacy == tenant {
		t.Fatalf("legacy audit scope mapped to invalid or shared RLS id %q: %v", legacy, err)
	}
	if again := store.AuditCheckpointRLSID("provider-control-plane"); again != legacy {
		t.Fatalf("legacy audit scope mapping changed: %q then %q", legacy, again)
	}
	if other := store.AuditCheckpointRLSID("another-administrative-scope"); other == legacy {
		t.Fatalf("different audit scopes share RLS id %q", legacy)
	}
}
