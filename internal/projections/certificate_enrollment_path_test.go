// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// A244-L4: certificate.recorded carries the enrollment path that issued the
// certificate, and the projection keeps the first recorded path: a later
// import observation of the same certificate (which names none) and a
// re-record naming another path leave it; a certificate recorded without one
// reads unrecorded.
func TestCertificateEnrollmentPathIsRecordedAndKeptA244L4(t *testing.T) {
	s, log := newStore(t), openLog(t)
	ctx := t.Context()
	p := projections.New(s)
	mustAppend(t, log, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegistered("Enrollment path")})
	record := func(id, fingerprint, path string, version int, observation bool) {
		t.Helper()
		data, err := json.Marshal(projections.CertificateRecorded{
			ID: id, Subject: "CN=" + fingerprint, Fingerprint: fingerprint, Source: "protocol:acme",
			IssuanceIdempotencyKey: "protocol-issue:acme:" + fingerprint, CertificateDER: []byte("der-" + fingerprint),
			EnrollmentProtocol: path, ObservationOnly: observation,
		})
		if err != nil {
			t.Fatal(err)
		}
		mustAppend(t, log, events.Event{ID: uuid.NewString(), TenantID: tenantA, Type: projections.EventCertificateRecorded,
			SchemaVersion: version, Data: data})
	}
	enrolled, unrecorded := uuid.NewString(), uuid.NewString()
	record(enrolled, "fp-a244l4-acme", "acme", 1, false)
	record(unrecorded, "fp-a244l4-none", "", 1, false)
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}
	path := func(id string) string {
		t.Helper()
		cert, err := s.GetCertificate(ctx, tenantA, id)
		if err != nil {
			t.Fatal(err)
		}
		return cert.EnrollmentProtocol
	}
	if got := path(enrolled); got != "acme" {
		t.Fatalf("the enrolled certificate reads path %q, want acme", got)
	}
	if got := path(unrecorded); got != "" {
		t.Fatalf("a certificate recorded without a path reads %q", got)
	}
	// An import observation of the same certificate, then a re-record naming
	// another path: the first recorded path stays.
	record(uuid.NewString(), "fp-a244l4-acme", "", projections.CertificateObservationEventSchemaVersion, true)
	record(uuid.NewString(), "fp-a244l4-acme", "est", 1, false)
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}
	if got := path(enrolled); got != "acme" {
		t.Fatalf("after an observation and a re-record the path reads %q, want acme kept", got)
	}
}
