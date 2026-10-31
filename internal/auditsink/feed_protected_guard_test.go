// SPDX-License-Identifier: BUSL-1.1

package auditsink

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/auditchain"
)

// This checks the presentation boundary only. Authenticated source resolution
// and real key removal are exercised separately by audit/receiver tests.
func TestCollectorRequiresExplicitReadableViewForProtectedRecords(t *testing.T) {
	for _, provider := range []string{ProviderSplunkHEC, ProviderSentinel} {
		t.Run(provider, func(t *testing.T) {
			record := auditchain.Record{Sequence: 7, ID: "source-7", Type: "authz.decision", TenantID: "tenant-a", Time: time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC), Data: json.RawMessage(`{"format":"trstctl.protected-audit-source/v1","schema_version":1,"protection":{"ciphertext":"fixture-only"}}`)}
			head := auditchain.Seal([]auditchain.Record{record})
			record.Hash = head
			var output bytes.Buffer
			err := WriteCollectorBatch(&output, FeedBatch{BatchID: "batch-7", Provider: provider, StartSequence: 7, EndSequence: 7, Records: []auditchain.Record{record}, ChainHead: head})
			if err == nil || output.Len() != 0 {
				t.Fatalf("protected collector source masqueraded as readable details: err=%v output_bytes=%d", err, output.Len())
			}
		})
	}
}
