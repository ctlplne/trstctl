// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/events"
)

func TestCertificateSubjectKeyCompromisedIsExactAndRetryStable(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	valid := func() CertificateSubjectKeyCompromised {
		return CertificateSubjectKeyCompromised{IdentityID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
			Fingerprint: strings.Repeat("b", 64), SPKISHA256: strings.Repeat("c", 64)}
	}
	if err := ValidateCertificateSubjectKeyCompromised(valid()); err != nil {
		t.Fatal(err)
	}
	for name, corrupt := range map[string]func(*CertificateSubjectKeyCompromised){
		"no_identity":           func(r *CertificateSubjectKeyCompromised) { r.IdentityID = "" },
		"noncanonical_identity": func(r *CertificateSubjectKeyCompromised) { r.IdentityID = strings.ToUpper(r.IdentityID) },
		"short_fingerprint":     func(r *CertificateSubjectKeyCompromised) { r.Fingerprint = strings.Repeat("b", 40) },
		"uppercase_spki":        func(r *CertificateSubjectKeyCompromised) { r.SPKISHA256 = strings.Repeat("C", 64) },
		"missing_spki":          func(r *CertificateSubjectKeyCompromised) { r.SPKISHA256 = "" },
	} {
		t.Run(name, func(t *testing.T) {
			record := valid()
			corrupt(&record)
			if err := ValidateCertificateSubjectKeyCompromised(record); err == nil {
				t.Fatal("an incomplete compromised key record was accepted")
			}
		})
	}
	// The projection accepts the record only under its retry-stable identity,
	// so a second append of the same fact cannot carry a fresh ID past it.
	record := valid()
	payload, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	fresh := events.Event{ID: uuid.NewString(), Type: EventCertificateSubjectKeyCompromised,
		TenantID: tenant, Time: time.Now().UTC(), Data: payload}
	if err := (&Projector{}).applyCertificateSubjectKeyCompromisedTx(t.Context(), nil, fresh); err == nil ||
		!strings.Contains(err.Error(), "retry-stable") {
		t.Fatalf("a record under a fresh event ID was projected: %v", err)
	}
	same := CertificateSubjectKeyCompromisedEventID(tenant, record.IdentityID, record.Fingerprint)
	if same != CertificateSubjectKeyCompromisedEventID(tenant, record.IdentityID, record.Fingerprint) {
		t.Fatal("the event identity is not deterministic")
	}
	for _, other := range []string{
		CertificateSubjectKeyCompromisedEventID("22222222-2222-4222-8222-222222222222", record.IdentityID, record.Fingerprint),
		CertificateSubjectKeyCompromisedEventID(tenant, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", record.Fingerprint),
		CertificateSubjectKeyCompromisedEventID(tenant, record.IdentityID, strings.Repeat("d", 64)),
	} {
		if other == same {
			t.Fatal("the event identity ignores its tenant, identity or certificate")
		}
	}
}
