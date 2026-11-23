// SPDX-License-Identifier: BUSL-1.1
package projections

import (
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/eventstest"
)

func TestCR134DirectoryTrustPinsRequireNewClosedEventVersions(t *testing.T) {
	log, err := eventstest.OpenFixture(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}, events.WithRequiredPrivacyEventPolicies())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	const tenant = "11111111-1111-4111-8111-111111111111"
	for _, tc := range []struct {
		name, eventType string
		payload         []byte
		versions        []int
		allowed         int
	}{
		{"AD CS command", EventDiscoveryRunQueued,
			[]byte(`{"id":"run","source_id":"source","job_kind":"adcs.inventory","dry_run":false,"execution":"relay","required_agent_role":"network","tls_ca_ref":"secret://adcs/ca","tls_server_name":"dc.example.test"}`),
			[]int{1, 2, 3, DiscoveryDirectoryTLSQueuedSchemaVersion}, DiscoveryDirectoryTLSQueuedSchemaVersion},
		{"CRL command", EventRevocationProbeQueued,
			[]byte(`{"id":"run","bucket":"bucket","batch_index":1,"batch_count":1,"targets":[],"stale_within_seconds":60,"required_agent_role":"network","ldap_binding":{"source_id":"source","url":"ldaps://dc.example.test","configuration_dn":"CN=Configuration,DC=example","bind_dn":"CN=reader","password_ref":"secret://adcs/bind","tls_ca_ref":"secret://adcs/ca","tls_server_name":"dc.example.test"}}`),
			[]int{1, RevocationDirectoryTLSQueuedSchemaVersion}, RevocationDirectoryTLSQueuedSchemaVersion},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, version := range tc.versions {
				_, err := log.Append(t.Context(), events.Event{Type: tc.eventType, TenantID: tenant, SchemaVersion: version, Data: tc.payload})
				if (err == nil) != (version == tc.allowed) {
					t.Fatalf("version %d accepted=%t, want accepted=%t: %v", version, err == nil, version == tc.allowed, err)
				}
			}
		})
	}
}
