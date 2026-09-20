// SPDX-License-Identifier: LicenseRef-trstctl-EE

package clusterfuzz

import (
	"testing"

	"trstctl.com/trstctl/internal/agentid/delegation"
	"trstctl.com/trstctl/internal/events"
)

// FuzzEventEnvelopeDecode fuzzes the event-envelope parser on untrusted input: it
// must never panic and must never return both a nil payload and a nil error.
func FuzzEventEnvelopeDecode(f *testing.F) {
	f.Add(delegation.TypeDelegationRecorded, 1, []byte(`{"tenant_id":"t","depth_remaining":2}`))
	f.Add(delegation.TypeIssuanceRecorded, 1, []byte(`{"subject_id":"s"}`))
	f.Add(delegation.TypeRefusalRecorded, 2, []byte(`{"failed_check":"x"}`))
	f.Add("unknown.type", 3, []byte(`garbage`))
	f.Add(delegation.TypeRevocationDirective, 1, []byte(``))
	f.Fuzz(func(t *testing.T, typ string, ver int, data []byte) {
		p, err := delegation.Decode(events.Event{Type: typ, SchemaVersion: ver, Data: data})
		if err == nil && p == nil {
			t.Fatalf("Decode returned nil payload and nil error for type=%q ver=%d", typ, ver)
		}
	})
}
