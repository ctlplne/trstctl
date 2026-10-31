// SPDX-License-Identifier: BUSL-1.1

package auditsink

import (
	"encoding/json"
	"fmt"
	"io"

	"trstctl.com/trstctl/internal/auditchain"
	"trstctl.com/trstctl/internal/eventspec"
)

// ReadableEvent contains authorized presentation fields. It is never part of a
// signed record or the durable collector command. Caller authority owns reads.
type ReadableEvent struct {
	Sequence        uint64           `json:"sequence"`
	ID              string           `json:"id"`
	Data            json.RawMessage  `json:"data,omitempty"`
	Actor           *eventspec.Actor `json:"actor,omitempty"`
	SensitiveErased bool             `json:"sensitive_erased,omitempty"`
}

type collectorRecordKey struct {
	sequence uint64
	id       string
}

// This marker selects presentation only; authenticated source resolution belongs
// to the audit service and is required before receiver output.
func protectedCollectorRecord(record auditchain.Record) bool {
	var marker struct {
		Format string `json:"format"`
	}
	return json.Unmarshal(record.Data, &marker) == nil && marker.Format == "trstctl.protected-audit-source/v1"
}

// WriteCollectorBatchWithReadable keeps the immutable source beside separately
// readable details. Validate every association before writing the first byte.
// Output is a readable external copy and cannot be recalled by key destruction.
func WriteCollectorBatchWithReadable(w io.Writer, batch FeedBatch, details []ReadableEvent) error {
	keys := make(map[collectorRecordKey]bool, len(batch.Records))
	views := make(map[collectorRecordKey]ReadableEvent, len(details))
	for _, record := range batch.Records {
		key := collectorRecordKey{record.Sequence, record.ID}
		if _, exists := keys[key]; exists {
			return fmt.Errorf("auditsink: duplicate collector source identity")
		}
		keys[key] = protectedCollectorRecord(record)
	}
	for _, detail := range details {
		key := collectorRecordKey{detail.Sequence, detail.ID}
		protected, exists := keys[key]
		if !exists || !protected {
			return fmt.Errorf("auditsink: readable details escaped protected source authority")
		}
		if _, duplicate := views[key]; duplicate {
			return fmt.Errorf("auditsink: ambiguous readable details")
		}
		if detail.SensitiveErased && (len(detail.Data) != 0 || detail.Actor != nil) {
			return fmt.Errorf("auditsink: erased collector details retain readable fields")
		}
		views[key] = detail
	}
	for key, protected := range keys {
		if _, exists := views[key]; protected && !exists {
			return fmt.Errorf("auditsink: protected collector source requires readable status")
		}
	}
	return writeCollectorBatch(w, batch, views)
}

func collectorRecordWithReadable(record auditchain.Record, views map[collectorRecordKey]ReadableEvent) collectorRecord {
	out := collectorRecordFromAudit(record)
	detail, found := views[collectorRecordKey{record.Sequence, record.ID}]
	if !found {
		return out
	}
	out.SignedRecord = &record
	out.HashScope = "signed_record"
	out.Data = detail.Data
	out.ActorSubject = ""
	out.ActorRoles = nil
	out.SensitiveErased = detail.SensitiveErased
	if detail.Actor != nil {
		out.ActorSubject = detail.Actor.Subject
		out.ActorRoles = append([]string(nil), detail.Actor.Roles...)
	}
	return out
}
