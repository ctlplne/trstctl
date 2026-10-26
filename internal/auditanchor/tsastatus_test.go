// SPDX-License-Identifier: BUSL-1.1

package auditanchor_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/auditanchor"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/tsa"
)

// revocationCA is a TSA root that also answers for its TSA certificates, as
// the served CA does through its CRL and OCSP responder.
type revocationCA struct {
	t       *testing.T
	root    *crypto.LockedSigner
	rootDER []byte
}

func newRevocationCA(t *testing.T) *revocationCA {
	t.Helper()
	root, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(root.Destroy)
	rootDER, err := crypto.SelfSignedCACert(root, "revocation TSA root", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return &revocationCA{t: t, root: root, rootDER: rootDER}
}

// token issues one timestamp at "at" from a fresh TSA certificate of this CA.
func (ca *revocationCA) authority(at *time.Time) (*tsa.Authority, string) {
	ca.t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		ca.t.Fatal(err)
	}
	ca.t.Cleanup(key.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "TSA"}, key)
	if err != nil {
		ca.t.Fatal(err)
	}
	cert, err := crypto.SignTimestampingCertFromCSR(ca.rootDER, ca.root, csr, 24*time.Hour)
	if err != nil {
		ca.t.Fatal(err)
	}
	a, err := tsa.New(tsa.Config{TenantID: "t1", TSACertDER: cert, TSASigner: key, Clock: func() time.Time { return *at }})
	if err != nil {
		ca.t.Fatal(err)
	}
	info, err := certinfo.Inspect(cert)
	if err != nil {
		ca.t.Fatal(err)
	}
	return a, info.SerialNumber
}

func (ca *revocationCA) ocsp(serial, status string, thisUpdate, revokedAt time.Time, reason int) []byte {
	ca.t.Helper()
	der, err := crypto.SignOCSPResponse(ca.rootDER, ca.root, status, serial, thisUpdate, thisUpdate.Add(time.Hour), revokedAt, reason)
	if err != nil {
		ca.t.Fatal(err)
	}
	return der
}

func (ca *revocationCA) crl(thisUpdate time.Time, revoked ...crypto.RevokedSerial) []byte {
	ca.t.Helper()
	der, err := crypto.CreateCRL(ca.rootDER, ca.root, revoked, 1, thisUpdate, thisUpdate.Add(24*time.Hour))
	if err != nil {
		ca.t.Fatal(err)
	}
	return der
}

func stamp(t *testing.T, a *tsa.Authority, data string) tsa.Token {
	t.Helper()
	token, err := a.Timestamp(context.Background(), crypto.SHA256Sum([]byte(data)))
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// A145/A146: the verifier establishes the status of every TSA certificate the
// export's timestamps rely on, from the export's OCSP evidence and the
// auditor's CRL, against the pinned root.
func TestTSARevocationDecidesEachCertificatesTimestamps(t *testing.T) {
	t.Parallel()
	ca := newRevocationCA(t)
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	clock := now
	a, serial := ca.authority(&clock)
	token := stamp(t, a, "head")
	later := now.Add(time.Hour)
	evidence := func(der []byte) *auditanchor.Validation {
		return &auditanchor.Validation{TSAStatus: []auditanchor.TSAStatusEvidence{{Serial: serial, OCSP: der}}, CapturedAt: later}
	}

	good, err := auditanchor.VerifyTSARevocation([]tsa.Token{token}, evidence(ca.ocsp(serial, crypto.OCSPGood, later, time.Time{}, 0)), ca.rootDER, auditanchor.TSARevocationPolicy{Require: true})
	if err != nil || len(good) != 1 || good[0].Status != "good" || good[0].Source != "ocsp" || good[0].Tokens != 1 {
		t.Fatalf("good = %+v, %v", good, err)
	}

	// Superseded after the timestamp: the timestamp stands.
	retired, err := auditanchor.VerifyTSARevocation([]tsa.Token{token},
		evidence(ca.ocsp(serial, crypto.OCSPRevoked, later, now.Add(30*time.Minute), 4)), ca.rootDER, auditanchor.TSARevocationPolicy{Require: true})
	if err != nil || retired[0].Status != "revoked" || retired[0].Reason != "superseded" {
		t.Fatalf("superseded after the token = %+v, %v", retired, err)
	}
	// Superseded before the timestamp: the timestamp is refused.
	if _, err := auditanchor.VerifyTSARevocation([]tsa.Token{token},
		evidence(ca.ocsp(serial, crypto.OCSPRevoked, later, now.Add(-time.Minute), 4)), ca.rootDER, auditanchor.TSARevocationPolicy{}); err == nil || !strings.Contains(err.Error(), "before its timestamp") {
		t.Fatalf("superseded before the token = %v", err)
	}
	// Key compromise after the timestamp: still refused.
	if _, err := auditanchor.VerifyTSARevocation([]tsa.Token{token},
		evidence(ca.ocsp(serial, crypto.OCSPRevoked, later, now.Add(30*time.Minute), 1)), ca.rootDER, auditanchor.TSARevocationPolicy{}); err == nil || !strings.Contains(err.Error(), "keyCompromise") {
		t.Fatalf("compromised after the token = %v", err)
	}
	if _, err := auditanchor.VerifyTSARevocation([]tsa.Token{token},
		evidence(ca.ocsp(serial, crypto.OCSPUnknown, later, time.Time{}, 0)), ca.rootDER, auditanchor.TSARevocationPolicy{}); err == nil || !strings.Contains(err.Error(), "does not know") {
		t.Fatalf("unknown to the CA = %v", err)
	}

	// Evidence issued before the timestamp vouches for nothing it covers.
	stale := evidence(ca.ocsp(serial, crypto.OCSPGood, now.Add(-time.Hour), time.Time{}, 0))
	if result, err := auditanchor.VerifyTSARevocation([]tsa.Token{token}, stale, ca.rootDER, auditanchor.TSARevocationPolicy{}); err != nil || result[0].Status != "unchecked" {
		t.Fatalf("stale evidence = %+v, %v", result, err)
	}
	if _, err := auditanchor.VerifyTSARevocation([]tsa.Token{token}, stale, ca.rootDER, auditanchor.TSARevocationPolicy{Require: true}); err == nil || !strings.Contains(err.Error(), "--tsa-crl") {
		t.Fatalf("stale evidence when required = %v", err)
	}
	if _, err := auditanchor.VerifyTSARevocation([]tsa.Token{token}, nil, ca.rootDER, auditanchor.TSARevocationPolicy{Require: true}); err == nil {
		t.Fatal("no evidence at all was accepted when required")
	}

	// The auditor's fresher CRL decides over the export's clean OCSP answer.
	crl := ca.crl(later.Add(time.Hour), crypto.RevokedSerial{Serial: serial, RevokedAt: now.Add(10 * time.Minute), Reason: 1})
	if _, err := auditanchor.VerifyTSARevocation([]tsa.Token{token}, evidence(ca.ocsp(serial, crypto.OCSPGood, later, time.Time{}, 0)), ca.rootDER,
		auditanchor.TSARevocationPolicy{CRLDER: crl}); err == nil || !strings.Contains(err.Error(), "keyCompromise") {
		t.Fatalf("a compromise on the auditor's CRL = %v", err)
	}
	if result, err := auditanchor.VerifyTSARevocation([]tsa.Token{token}, nil, ca.rootDER,
		auditanchor.TSARevocationPolicy{CRLDER: ca.crl(later), Require: true}); err != nil || result[0].Status != "good" || result[0].Source != "crl" {
		t.Fatalf("a clean CRL = %+v, %v", result, err)
	}

	// Evidence from another CA, or mislabeled, is refused.
	other := newRevocationCA(t)
	if _, err := auditanchor.VerifyTSARevocation([]tsa.Token{token}, evidence(other.ocsp(serial, crypto.OCSPGood, later, time.Time{}, 0)), ca.rootDER, auditanchor.TSARevocationPolicy{}); err == nil {
		t.Fatal("OCSP evidence from another CA was accepted")
	}
	if _, err := auditanchor.VerifyTSARevocation([]tsa.Token{token}, nil, ca.rootDER, auditanchor.TSARevocationPolicy{CRLDER: other.crl(later)}); err == nil {
		t.Fatal("a CRL from another CA was accepted")
	}
	mislabeled := &auditanchor.Validation{TSAStatus: []auditanchor.TSAStatusEvidence{{Serial: "abc", OCSP: ca.ocsp(serial, crypto.OCSPGood, later, time.Time{}, 0)}}}
	if _, err := auditanchor.VerifyTSARevocation([]tsa.Token{token}, mislabeled, ca.rootDER, auditanchor.TSARevocationPolicy{}); err == nil {
		t.Fatal("mislabeled OCSP evidence was accepted")
	}
}

// Tokens from two TSA certificates (before and after a rotation) are judged per
// certificate, and a delegated responder's answer counts.
func TestTSARevocationJudgesEachCertificateSeparately(t *testing.T) {
	t.Parallel()
	ca := newRevocationCA(t)
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	clock := now
	first, firstSerial := ca.authority(&clock)
	early := stamp(t, first, "early")
	clock = now.Add(2 * time.Hour)
	second, secondSerial := ca.authority(&clock)
	late := stamp(t, second, "late")

	responderKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(responderKey.Destroy)
	responderCert, err := crypto.CreateOCSPResponderCertificate(ca.rootDER, ca.root, responderKey, "delegated responder", now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	checked := now.Add(3 * time.Hour)
	delegated, err := crypto.SignDelegatedOCSPResponse(ca.rootDER, responderCert, responderKey, crypto.OCSPRevoked, firstSerial, checked, checked.Add(time.Hour), now.Add(time.Hour), 4)
	if err != nil {
		t.Fatal(err)
	}
	validation := &auditanchor.Validation{TSAStatus: []auditanchor.TSAStatusEvidence{
		{Serial: firstSerial, OCSP: delegated},
		{Serial: secondSerial, OCSP: ca.ocsp(secondSerial, crypto.OCSPGood, checked, time.Time{}, 0)},
	}}
	result, err := auditanchor.VerifyTSARevocation([]tsa.Token{early, late}, validation, ca.rootDER, auditanchor.TSARevocationPolicy{Require: true})
	if err != nil || len(result) != 2 {
		t.Fatalf("two certificates = %+v, %v", result, err)
	}
	for _, status := range result {
		switch status.Serial {
		case firstSerial:
			if status.Status != "revoked" || status.Reason != "superseded" {
				t.Fatalf("rotated-out certificate = %+v", status)
			}
		case secondSerial:
			if status.Status != "good" {
				t.Fatalf("current certificate = %+v", status)
			}
		}
	}
}
