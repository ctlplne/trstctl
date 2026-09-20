// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"strings"
	"testing"
	"time"
)

func TestApprovedEphemeralFenceRejectsSubMicrosecondEventTime(t *testing.T) {
	fence := ApprovedTargetFence{
		TenantID:       "11111111-1111-1111-1111-111111111111",
		TargetKind:     ApprovedTargetEphemeralCertificate,
		CommandKey:     "command",
		EventID:        "event",
		EventType:      "certificate.recorded",
		SchemaVersion:  3,
		EventTime:      time.Unix(1_780_000_000, 123_456_789).UTC(),
		Payload:        []byte(`{"command":"sealed"}`),
		SemanticDigest: strings.Repeat("a", 64),
	}
	if err := validateApprovedTargetFence(fence); err == nil ||
		err.Error() != "store: approved target fence time is not PostgreSQL-exact" {
		t.Fatalf("sub-microsecond ephemeral fence error = %v", err)
	}
}
