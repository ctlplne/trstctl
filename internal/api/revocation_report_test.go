// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/store"
)

// A245: the revocation report keeps the CA status, the deployed material,
// new connections and existing sessions apart; one answering never stands in
// for another.
func TestRevocationReportKeepsTheFourFacetsApartA245(t *testing.T) {
	revoked := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	before, after := revoked.Add(-time.Hour), revoked.Add(time.Hour)
	cert := store.Certificate{ID: "c1", Serial: "0a", Fingerprint: "old", RevokedAt: &revoked, RevocationReason: "keyCompromise"}

	// Revoked at the CA, no CRL since; still deployed; an endpoint still presents
	// it; nothing stopped the listener.
	r := buildRevocationCertificateReport(cert, store.RevocationEvidence{
		CA:           store.RevocationCAEvidence{Recorded: true, RevokedAt: &revoked},
		Deliveries:   []store.RevocationDelivery{{Target: "edge", LatestStatus: "delivered", LatestPrint: "old", LatestAt: before}},
		Observations: []store.RevocationObservation{{EndpointID: "edge", Vantage: "relay", Reached: true, ObservedFingerprint: "old", CheckedAt: after}},
	})
	if r.CAStatus.State != revocationPending || r.DeployedMaterial.State != revocationPending ||
		r.NewConnections.State != revocationFailed || r.ExistingSessions.State != revocationNotObserved {
		t.Fatalf("revoked but still served: %+v / %+v / %+v / %+v", r.CAStatus, r.DeployedMaterial, r.NewConnections, r.ExistingSessions)
	}

	// The CRL lists it, the destination holds a replacement, the endpoint
	// presents the replacement, a containment stop ended the sessions.
	crl := after
	r = buildRevocationCertificateReport(cert, store.RevocationEvidence{
		CA:           store.RevocationCAEvidence{Recorded: true, RevokedAt: &revoked, CRLNumber: 7, CRLThisUpdate: &crl},
		Deliveries:   []store.RevocationDelivery{{Target: "edge", LatestStatus: "verified", LatestPrint: "new", LatestAt: after}},
		Observations: []store.RevocationObservation{{EndpointID: "edge", Vantage: "relay", Reached: true, ObservedFingerprint: "new", CheckedAt: after}},
		Stops:        []store.RevocationStop{{Target: "edge", Status: "containment_stopped", At: after}},
	})
	if r.CAStatus.State != revocationConfirmed || r.DeployedMaterial.State != revocationConfirmed || r.Destinations[0].Now != "replaced" ||
		r.NewConnections.State != revocationConfirmed || r.ExistingSessions.State != revocationConfirmed {
		t.Fatalf("fully enforced: %+v", r)
	}

	// An endpoint last checked before the revocation proves nothing about new
	// connections; a CA record not marked revoked is a failure; an external CA's
	// status is not read back; a removal that failed reads failed.
	r = buildRevocationCertificateReport(cert, store.RevocationEvidence{
		CA:           store.RevocationCAEvidence{Recorded: true},
		Deliveries:   []store.RevocationDelivery{{Target: "edge", LatestStatus: "purge_failed", LatestPrint: "old", LatestAt: after}},
		Observations: []store.RevocationObservation{{EndpointID: "edge", Vantage: "local", Reached: true, ObservedFingerprint: "new", CheckedAt: before}},
	})
	if r.CAStatus.State != revocationFailed || r.DeployedMaterial.State != revocationFailed || r.NewConnections.State != revocationNotObserved {
		t.Fatalf("unconfirmed: %+v / %+v / %+v", r.CAStatus, r.DeployedMaterial, r.NewConnections)
	}
	external := cert
	external.IssuingExternalCAID = "corp-digicert"
	if r := buildRevocationCertificateReport(external, store.RevocationEvidence{}); r.CAStatus.State != revocationNotObserved ||
		r.DeployedMaterial.State != revocationNotObserved || r.NewConnections.State != revocationNotObserved {
		t.Fatalf("no evidence must read not observed: %+v", r)
	}
}
