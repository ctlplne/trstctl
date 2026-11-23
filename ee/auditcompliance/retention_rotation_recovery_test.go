// SPDX-License-Identifier: LicenseRef-trstctl-EE

package auditcompliance

import (
	"context"
	"encoding/json"
	"testing"
	"trstctl.com/trstctl/internal/eventstest"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

// A234-L1: an archived event names the key that signed its segment. A later
// recovery of the same checkpoint — after the audit key rotated, so it knows
// no key, or naming the new one — matches the retained event, appends
// nothing and leaves the named key as it was; the key is evidence, not the
// event's identity.
func TestRecoveryAfterTheAuditKeyRotatesKeepsTheArchivedKeyA234L1(t *testing.T) {
	ctx := context.Background()
	log, err := eventstest.OpenFixture(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	const tenant = "11111111-1111-1111-1111-111111111111"
	if _, err := log.Append(ctx, events.Event{ID: "a234l1-record", TenantID: tenant, Type: "test.retained"}); err != nil {
		t.Fatal(err)
	}
	checkpoint := audit.Checkpoint{TenantID: tenant, BoundarySeq: 1, BoundaryHash: "checkpoint-head", RecordCount: 1, ArchiveURI: "local://signed-segment"}
	worker := &RetentionWorker{log: log}
	const signedBy = `{"keys":[{"kid":"audit-export-1"}]}`
	if err := worker.ensureArchivedEvent(ctx, checkpoint, signedBy); err != nil {
		t.Fatal(err)
	}
	head, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"", `{"keys":[{"kid":"audit-export-2"}]}`} {
		if err := worker.ensureArchivedEvent(ctx, checkpoint, key); err != nil {
			t.Fatalf("a recovery naming %q conflicted with the retained event: %v", key, err)
		}
	}
	if after, err := log.LastSequence(ctx); err != nil || after != head {
		t.Fatalf("the recoveries appended: head %d, want %d (%v)", after, head, err)
	}
	var named string
	if err := log.Replay(ctx, 1, func(e events.Event) error {
		if e.Type == audit.EventTypeArchived {
			var archived audit.ArchivedEvent
			if err := json.Unmarshal(e.Data, &archived); err != nil {
				return err
			}
			named = archived.SignerJWKS
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if named != signedBy {
		t.Fatalf("the archived event names %q, want the key that signed the segment", named)
	}
}
