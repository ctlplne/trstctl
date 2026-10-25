// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/custody"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// Owner decision 2026-10-24: a certificate issued before its path recorded
// custody gets its origin only from a retained event whose shape proves it,
// and only from events older than the moment that path began recording
// custody itself. Each case is one issuing path's historical event shape.
func TestDeriveKeyOriginFromPreCustodyIssuanceEvents(t *testing.T) {
	at := func(value string) time.Time {
		t.Helper()
		parsed, err := time.Parse(time.RFC3339, value)
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	}
	replaces := "00000000-0000-4000-8000-000000000001"
	externalKey := "external-order-1"
	externalID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(tenantA+"\x00certificate.recorded\x00"+externalKey)).String()
	cases := []struct {
		name   string
		id     string
		time   string
		record projections.CertificateRecorded
		want   custody.DerivationRule
	}{
		{"ACME before protocol custody", "", "2026-07-01T00:00:00Z",
			projections.CertificateRecorded{Source: "protocol:acme", IssuanceIdempotencyKey: "protocol-issue:acme:" + strings.Repeat("a", 64)},
			custody.DerivedProtocolEnrollment},
		{"EST with a client key", "", "2026-09-10T00:00:00Z",
			projections.CertificateRecorded{Source: "protocol:est", IssuanceIdempotencyKey: "protocol-issue:pqc-migration:chosen-by-the-client"},
			custody.DerivedProtocolEnrollment},
		{"SCEP after protocol custody", "", "2026-10-01T00:00:00Z",
			projections.CertificateRecorded{Source: "protocol:scep", IssuanceIdempotencyKey: "protocol-issue:scep:tx-1"},
			custody.DerivationNone},
		{"PQC migration reissue, early key", "", "2026-07-01T00:00:00Z",
			projections.CertificateRecorded{Source: "protocol:acme", IssuanceIdempotencyKey: "protocol-issue:pqc-migration:run:asset"},
			custody.DerivedPQCMigrationReissue},
		{"PQC migration reissue, current key", "", "2026-10-20T00:00:00Z",
			projections.CertificateRecorded{Source: "protocol:acme", IssuanceIdempotencyKey: "protocol-issue:licensed-crypto-migration:run:asset"},
			custody.DerivedPQCMigrationReissue},
		{"identity renewal before renewal custody", "", "2026-08-03T12:00:00Z",
			projections.CertificateRecorded{Source: "issued", IssuanceIdempotencyKey: "renew:outbox-1", ReplacesID: &replaces},
			custody.DerivedIdentityRenewal},
		{"identity renewal after renewal custody", "", "2026-08-05T00:00:00Z",
			projections.CertificateRecorded{Source: "issued", IssuanceIdempotencyKey: "renew:outbox-1", ReplacesID: &replaces},
			custody.DerivationNone},
		{"renewal key without a predecessor", "", "2026-07-01T00:00:00Z",
			projections.CertificateRecorded{Source: "issued", IssuanceIdempotencyKey: "renew:outbox-1"},
			custody.DerivationNone},
		{"identity issuance before CSR-first issuance", "", "2026-07-01T00:00:00Z",
			projections.CertificateRecorded{Source: "issued", IssuanceIdempotencyKey: "issue:transition:k"},
			custody.DerivedIdentityIssuance},
		{"identity issuance once a CSR could be honored", "", "2026-08-03T12:00:00Z",
			projections.CertificateRecorded{Source: "issued", IssuanceIdempotencyKey: "issue:transition:k"},
			custody.DerivationNone},
		{"Kubernetes auto-issuance", "", "2026-07-01T00:00:00Z",
			projections.CertificateRecorded{Source: "discovery:k8s_ingress_gateway", IssuanceIdempotencyKey: "k8s-auto:run:fp"},
			custody.DerivedKubernetesAutoIssuance},
		{"Kubernetes auto-issuance after custody", "", "2026-08-05T00:00:00Z",
			projections.CertificateRecorded{Source: "discovery:k8s_ingress_gateway", IssuanceIdempotencyKey: "k8s-auto:run:fp"},
			custody.DerivationNone},
		{"ephemeral credential", "", "2026-07-01T00:00:00Z",
			projections.CertificateRecorded{Source: "ephemeral:k8s_sat", IssuanceIdempotencyKey: "ephemeral-issue:req"},
			custody.DerivedEphemeralCredential},
		{"attested SVID", "", "2026-08-20T00:00:00Z",
			projections.CertificateRecorded{Source: "attested:k8s_psat", IssuanceIdempotencyKey: "attested-issue:req"},
			custody.DerivedAttestedSVID},
		{"attested SVID after custody", "", "2026-08-31T00:00:00Z",
			projections.CertificateRecorded{Source: "attested:k8s_psat", IssuanceIdempotencyKey: "attested-issue:req"},
			custody.DerivationNone},
		{"agent broker", "", "2026-08-31T05:00:00Z",
			projections.CertificateRecorded{Source: "broker:mcp", IssuanceIdempotencyKey: "broker-issue:req"},
			custody.DerivedAgentBroker},
		{"external CA order", externalID, "2026-09-01T00:00:00Z",
			projections.CertificateRecorded{Source: "external-ca:pebble", IssuanceIdempotencyKey: externalKey, IssuanceRequestBinding: strings.Repeat("b", 64)},
			custody.DerivedExternalCAOrder},
		{"external CA shape once identity issuance could use it", externalID, "2026-09-06T00:00:00Z",
			projections.CertificateRecorded{Source: "external-ca:pebble", IssuanceIdempotencyKey: externalKey, IssuanceRequestBinding: strings.Repeat("b", 64)},
			custody.DerivationNone},
		{"external CA source without the worker's event identity", "", "2026-09-01T00:00:00Z",
			projections.CertificateRecorded{Source: "external-ca:pebble", IssuanceIdempotencyKey: externalKey, IssuanceRequestBinding: strings.Repeat("b", 64)},
			custody.DerivationNone},
		{"recorded custody is never re-derived", "", "2026-07-01T00:00:00Z",
			projections.CertificateRecorded{Source: "issued", IssuanceIdempotencyKey: "issue:transition:k", KeyOrigin: "requester"},
			custody.DerivationNone},
		{"an observation proves nothing", "", "2026-07-01T00:00:00Z",
			projections.CertificateRecorded{Source: "protocol:acme", IssuanceIdempotencyKey: "protocol-issue:acme:x", ObservationOnly: true},
			custody.DerivationNone},
		{"an import proves nothing", "", "2026-07-01T00:00:00Z",
			projections.CertificateRecorded{Source: "import", IssuanceIdempotencyKey: "issue:transition:k"},
			custody.DerivationNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id := tc.id
			if id == "" {
				id = uuid.NewString()
			}
			e := events.Event{ID: id, TenantID: tenantA, Type: projections.EventCertificateRecorded, Time: at(tc.time)}
			if tc.record.ObservationOnly {
				e.SchemaVersion = projections.CertificateObservationEventSchemaVersion
			}
			got, derived := projections.DeriveKeyOrigin(e, tc.record)
			if got != tc.want || derived != (tc.want != custody.DerivationNone) {
				t.Fatalf("DeriveKeyOrigin = %q, %v; want %q", got, derived, tc.want)
			}
			if derived && !custody.ValidDerivation(got, got.Origin()) {
				t.Fatalf("rule %q does not state one origin", got)
			}
		})
	}
	if custody.DerivedProtocolEnrollment.Origin() != custody.OriginRequester ||
		custody.DerivedIdentityIssuance.Origin() != custody.OriginControlPlane ||
		custody.ValidDerivation(custody.DerivedProtocolEnrollment, custody.OriginControlPlane) {
		t.Fatal("a rule must state exactly the origin its issuing path proves")
	}
}
