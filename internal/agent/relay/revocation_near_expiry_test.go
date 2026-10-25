// SPDX-License-Identifier: BUSL-1.1

package relay_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/revocationhealth"
)

// B13-R2: the scheduler asks for a 24 h warning window, and trstctl's own OCSP
// responder signs ten-minute responses, so a healthy managed CA's OCSP endpoint
// read "expiring" on every probe. "Near expiry" now means the last quarter of
// the response's own lifetime (capped by the window): a freshly signed
// short-lived answer is fresh, one in its last minutes still warns, a two-day
// response warns in its last twelve hours, and a seven-day CRL keeps the full
// 24 h warning.
func TestRevocationNearExpiryFollowsTheResponseLifetime(t *testing.T) {
	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(caKey.Destroy)
	caDER, err := crypto.SelfSignedCACert(caKey, "B13-R2 CA", 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(leafKey.Destroy)
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "b13r2.example"}, leafKey)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := crypto.SignLeafFromCSR(caDER, caKey, csrDER, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := certinfo.Inspect(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	served := map[string][]byte{}
	ocsp := func(path string, thisUpdate, nextUpdate time.Time) {
		t.Helper()
		der, err := crypto.SignOCSPResponse(caDER, caKey, crypto.OCSPGood, leaf.SerialNumber, thisUpdate, nextUpdate, time.Time{}, 0)
		if err != nil {
			t.Fatal(err)
		}
		served[path] = der
	}
	crl := func(path string, thisUpdate, nextUpdate time.Time) {
		t.Helper()
		der, err := crypto.CreateCRL(caDER, caKey, nil, 1, thisUpdate, nextUpdate)
		if err != nil {
			t.Fatal(err)
		}
		served[path] = der
	}
	ocsp("/ocsp-just-signed", now, now.Add(10*time.Minute))
	ocsp("/ocsp-last-minutes", now.Add(-8*time.Minute-30*time.Second), now.Add(90*time.Second))
	ocsp("/ocsp-two-day", now.Add(-28*time.Hour), now.Add(20*time.Hour))
	ocsp("/ocsp-two-day-late", now.Add(-38*time.Hour), now.Add(10*time.Hour))
	crl("/crl-seven-day", now.Add(-148*time.Hour), now.Add(20*time.Hour))
	crl("/crl-one-hour", now.Add(-20*time.Minute), now.Add(40*time.Minute))
	crl("/crl-one-hour-late", now.Add(-50*time.Minute), now.Add(10*time.Minute))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		der, ok := served[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/ocsp") {
			w.Header().Set("Content-Type", "application/ocsp-response")
		}
		_, _ = w.Write(der)
	}))
	t.Cleanup(server.Close)

	want := map[string]relay.RevocationFindingStatus{
		"/ocsp-just-signed":  relay.RevocationFresh,
		"/ocsp-last-minutes": relay.RevocationExpiring,
		"/ocsp-two-day":      relay.RevocationFresh,
		"/ocsp-two-day-late": relay.RevocationExpiring,
		"/crl-seven-day":     relay.RevocationExpiring,
		"/crl-one-hour":      relay.RevocationFresh,
		"/crl-one-hour-late": relay.RevocationExpiring,
	}
	var targets []revocationhealth.Target
	for path := range want {
		protocol := revocationhealth.ProtocolCRL
		if strings.HasPrefix(path, "/ocsp") {
			protocol = revocationhealth.ProtocolOCSP
		}
		targets = append(targets, revocationhealth.Target{
			Key: crypto.SHA256Hex([]byte(path)), Protocol: protocol, Endpoint: server.URL + path,
			IssuerSubject: "CN=B13-R2 CA", IssuerFingerprint: "issuer-fingerprint", IssuerDER: caDER,
			CertificateID: uuid.NewString(), CertificateSubject: leaf.Subject,
			CertificateFingerprint: leaf.SHA256Fingerprint, CertificateSerial: leaf.SerialNumber, CertificateDER: leafDER,
		})
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].Key < targets[j].Key })
	intent := relay.RevocationProbeIntent{
		ID: uuid.NewString(), Bucket: now.Format(time.RFC3339), BatchIndex: 1, BatchCount: 1,
		// The scheduler's window (revocationHealthStaleWithin).
		StaleWithinSeconds: int((24 * time.Hour).Seconds()), RequiredAgentRole: revocationhealth.RequiredRoleNetwork,
		Targets: targets,
	}
	report, err := relay.ProbeRevocation(context.Background(), server.Client(), intent)
	if err != nil {
		t.Fatalf("ProbeRevocation: %v", err)
	}
	if len(report.Findings) != len(want) {
		t.Fatalf("findings = %+v", report.Findings)
	}
	for _, finding := range report.Findings {
		path := strings.TrimPrefix(finding.Endpoint, server.URL)
		if !finding.SignatureVerified || finding.Status != want[path] {
			t.Errorf("%s: status %s (%s) verified %t, want %s", path, finding.Status, finding.DetailCode, finding.SignatureVerified, want[path])
		}
	}
}
