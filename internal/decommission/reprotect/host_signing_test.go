// SPDX-License-Identifier: BUSL-1.1

package reprotect

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	corestore "trstctl.com/trstctl/internal/store"
)

func TestHostReprotectCSRKeepsExactPredecessorKeyAndNames(t *testing.T) {
	ca, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer ca.Destroy()
	caDER, err := crypto.SelfSignedCACert(ca, "test root", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	subject, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer subject.Destroy()
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "host.qa.invalid", DNSNames: []string{"host.qa.invalid"}}, subject)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := crypto.SignLeafFromCSR(caDER, ca, csr, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	info, err := certinfo.Inspect(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	plan := CredentialPlan{IdentityID: "identity-1", SuccessorAuthorityID: "successor-1", PredecessorFingerprint: info.SHA256Fingerprint,
		PredecessorSPKISHA256: info.SPKISHA256, TargetID: "target-1", TargetRevisionID: "revision-1",
		RequiredAgentID: "agent-1", Connector: "apache", VerifyAddress: "127.0.0.1:10443", VerifyServerName: "host.qa.invalid", TTLSeconds: 600}
	plan.Job.TenantID = "tenant-1"
	plan.Job.ID = "job-1"
	plan.Job.Dependent.ID = "cert-1"
	intent := hostReprotectIntent{Connector: plan.Connector, TargetID: plan.TargetID, Revision: plan.TargetRevisionID,
		IdentityID: plan.IdentityID, PredecessorCertificateID: plan.Job.Dependent.ID, IssuingAuthoritySource: "private",
		IssuingAuthorityID: plan.SuccessorAuthorityID, RequiredAgentID: plan.RequiredAgentID, ReprotectJobID: plan.Job.ID,
		ReprotectPredecessorFingerprint: plan.PredecessorFingerprint, ReprotectPredecessorSPKISHA256: plan.PredecessorSPKISHA256,
		ReprotectTTLSeconds: plan.TTLSeconds, VerifyAddress: plan.VerifyAddress, VerifyServerName: plan.VerifyServerName,
		SubjectCommonName: info.CommonName, SubjectDNSNames: info.DNSNames}
	predecessor := corestore.Certificate{ID: "cert-1", Fingerprint: info.SHA256Fingerprint, CertificateDER: leafDER}
	if err := validateHostCSRPublicBinding(plan, intent, predecessor, csr); err != nil {
		t.Fatalf("same retained key: %v", err)
	}
	other, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Destroy()
	otherCSR, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "host.qa.invalid", DNSNames: []string{"host.qa.invalid"}}, other)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateHostCSRPublicBinding(plan, intent, predecessor, otherCSR); err == nil {
		t.Fatal("different subject key admitted")
	}
	wider, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "host.qa.invalid", DNSNames: []string{"host.qa.invalid", "admin.qa.invalid"}}, subject)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateHostCSRPublicBinding(plan, intent, predecessor, wider); err == nil {
		t.Fatal("wider SAN set admitted")
	}
	intent.ReprotectJobID = "other-job"
	if err := validateHostCSRPublicBinding(plan, intent, predecessor, csr); err == nil {
		t.Fatal("different job admitted")
	}
}
