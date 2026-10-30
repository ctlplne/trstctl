// SPDX-License-Identifier: BUSL-1.1

package audit

import (
	"encoding/json"

	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/events"
)

const protectedSourceRecordFormat = "trstctl.protected-audit-source/v1"

// ProtectedSourceRecordData is the stable hashed/signed core. It never includes
// readable Data/Actor or an erased flag that would change after key removal.
// ID/type/tenant/time in the outer Record are the original event AAD fields.
type ProtectedSourceRecordData struct {
	Format        string                `json:"format"`
	SchemaVersion int                   `json:"schema_version"`
	Protection    eventprotect.Envelope `json:"protection"`
}

// Source reading owns AEAD authentication or verified current erasure. This
// formatter validates public structure only; the resulting audit commitment
// binds all outer source headers and ciphertext without requiring a lost key.
func protectedSourceRecord(event events.Event, ordinal uint64) (Record, bool, error) {
	if event.Protection == nil {
		return Record{}, false, nil
	}
	context := eventprotect.Context{Scope: eventprotect.ScopeEvent, ID: event.ID, Type: event.Type, TenantID: event.TenantID, SchemaVersion: event.SchemaVersion, Time: event.Time}
	if err := eventprotect.ValidateEnvelope(context, event.Protection.PolicyDigest, *event.Protection); err != nil {
		return Record{}, false, err
	}
	wire, err := json.Marshal(ProtectedSourceRecordData{Format: protectedSourceRecordFormat, SchemaVersion: event.SchemaVersion, Protection: *event.Protection})
	if err != nil {
		return Record{}, false, err
	}
	return Record{Sequence: ordinal, StreamSequence: event.Sequence, ID: event.ID, Type: event.Type, TenantID: event.TenantID, Time: event.Time, Data: wire}, true, nil
}
