// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"strings"
	"testing"
)

// B8-D1: protocols.spiffe.entries binds a workload's SPIFFE ID to the
// selectors a named host agent must observe; a malformed entry is refused at
// load rather than becoming an identity nobody can obtain or anyone can.
func TestSPIFFEEntriesAreValidatedB8D1(t *testing.T) {
	base := func(entries ...SPIFFEEntry) Protocols {
		return Protocols{SPIFFE: SPIFFEProtocol{Enabled: true, TenantID: "11111111-1111-1111-1111-111111111111",
			TrustDomain: "example.org", Entries: entries}}
	}
	good := SPIFFEEntry{SPIFFEID: "spiffe://example.org/payments", Selectors: []string{"unix:uid:1000", "unix:path:/usr/bin/payments"}, Agent: "host-a"}
	if errs := base(good).ValidateTenantBindings(""); len(errs) != 0 {
		t.Fatalf("a well-formed entry was refused: %v", errs)
	}
	for _, tc := range []struct {
		name string
		p    Protocols
		want string
	}{
		{"SPIFFE disabled", Protocols{SPIFFE: SPIFFEProtocol{TrustDomain: "example.org", Entries: []SPIFFEEntry{good}}}, "needs protocols.spiffe.enabled"},
		{"outside the trust domain", base(SPIFFEEntry{SPIFFEID: "spiffe://other.org/payments", Selectors: good.Selectors, Agent: "host-a"}), "outside protocols.spiffe.trust_domain"},
		{"not a SPIFFE ID", base(SPIFFEEntry{SPIFFEID: "https://example.org/payments", Selectors: good.Selectors, Agent: "host-a"}), "entries[0].spiffe_id"},
		{"the reserved namespace", base(SPIFFEEntry{SPIFFEID: "spiffe://example.org/_trstctl/agent/x", Selectors: good.Selectors, Agent: "host-a"}), "reserved namespace"},
		{"no selectors", base(SPIFFEEntry{SPIFFEID: good.SPIFFEID, Agent: "host-a"}), "at least one selector"},
		{"a bare unix selector", base(SPIFFEEntry{SPIFFEID: good.SPIFFEID, Selectors: []string{"unix"}, Agent: "host-a"}), "must name a type and a value"},
		{"a selector with a space", base(SPIFFEEntry{SPIFFEID: good.SPIFFEID, Selectors: []string{"unix:uid: 1000"}, Agent: "host-a"}), "must name a type and a value"},
		{"no agent", base(SPIFFEEntry{SPIFFEID: good.SPIFFEID, Selectors: good.Selectors}), "must be the name a host agent enrolled with"},
		{"an agent name with a slash", base(SPIFFEEntry{SPIFFEID: good.SPIFFEID, Selectors: good.Selectors, Agent: "host/a"}), "must be the name a host agent enrolled with"},
		{"a repeated entry", base(good, good), "repeats spiffe_id"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			errs := tc.p.ValidateTenantBindings("11111111-1111-1111-1111-111111111111")
			var joined []string
			for _, err := range errs {
				joined = append(joined, err.Error())
			}
			if !strings.Contains(strings.Join(joined, "\n"), tc.want) {
				t.Fatalf("errors %q do not name %q", joined, tc.want)
			}
		})
	}
	// The same entry for two different agents is two entries, not a repeat.
	other := good
	other.Agent = "host-b"
	if errs := base(good, other).ValidateTenantBindings(""); len(errs) != 0 {
		t.Fatalf("the same workload on two hosts was refused: %v", errs)
	}
}
