// SPDX-License-Identifier: BUSL-1.1

package ephemeral_test

import (
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	ephemeral "trstctl.com/trstctl/internal/ephemeral"
)

const approvalTestTenant = "11111111-1111-4111-8111-111111111111"

func TestApprovalBindingDecodesScopedSubjectWithoutChangingAuthority(t *testing.T) {
	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer caKey.Destroy()
	caDER, err := crypto.SelfSignedCACert(caKey, "scoped-approval-test-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer leafKey.Destroy()
	const prefix = "spiffe://approval.test/_trstctl/v1/tenant/11111111-1111-4111-8111-111111111111/ephemeral/method/"
	for _, tc := range []struct{ method, subject, path string }{
		{"k8s_sat", "ns/default/sa/worker", "ns/default/sa/worker"},
		{"github_oidc", "repo:org/project:ref:refs/heads/main", "trstctl-hex-7265706f3a6f7267/trstctl-hex-70726f6a6563743a7265663a72656673/heads/main"},
		{"k8s_sat", "trstctl-hex-613a62", "trstctl-hex-7472737463746c2d6865782d363133613632"},
	} {
		id := prefix + tc.method + "/subject/" + tc.path
		binding, err := ephemeral.NewApprovalBinding("1a382d7d-930b-42ba-aa1b-a9c4459d821b", caDER, "scoped-request", tc.method, tc.subject, nil, leafKey.Public().DER, id, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		certDER, err := crypto.SignSVID(caDER, caKey, leafKey.Public().DER, id, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := binding.ValidateCertificate(certDER, "ephemeral:"+tc.method, approvalTestTenant, time.Now().UTC()); err != nil {
			t.Errorf("exact scoped approval rejected for %s: %v", tc.method, err)
		}
		if _, err := binding.ValidateCertificate(certDER, "ephemeral:"+tc.method, "22222222-2222-4222-8222-222222222222", time.Now().UTC()); err == nil {
			t.Fatal("signed identity accepted in another tenant's event")
		}
		wrongMethod := binding
		wrongMethod.AttestationMethod = "different-method"
		if _, err := wrongMethod.ValidateCertificate(certDER, "ephemeral:different-method", approvalTestTenant, time.Now().UTC()); err == nil {
			t.Fatal("signed identity accepted with a substituted attestation method")
		}
		for _, change := range []func(*ephemeral.ApprovalBinding){
			func(b *ephemeral.ApprovalBinding) {
				b.AttestationSubjectSHA256 = crypto.SHA256Hex([]byte("different-subject"))
			},
			func(b *ephemeral.ApprovalBinding) {
				b.SPIFFEIDSHA256 = crypto.SHA256Hex([]byte(strings.Replace(id, "/ephemeral/", "/attested/", 1)))
			},
			func(b *ephemeral.ApprovalBinding) { b.PublicKeySHA256 = crypto.SHA256Hex([]byte("different-key")) },
		} {
			changed := binding
			change(&changed)
			if _, err := changed.ValidateCertificate(certDER, "ephemeral:"+tc.method, approvalTestTenant, time.Now().UTC()); err == nil {
				t.Fatal("changed approval accepted")
			}
		}
	}
}

func TestSubjectFromSPIFFEIDRejectsMalformedReservedNames(t *testing.T) {
	const prefix = "spiffe://approval.test/_trstctl/v1/tenant/11111111-1111-4111-8111-111111111111/ephemeral/method/k8s_sat/subject/"
	for _, raw := range []string{
		prefix + "trstctl-hex-", prefix + "trstctl-hex-xyz", prefix + "trstctl-hex-776562", // alternate encoding of plain web
		prefix + "trstctl-hex-612f62", // an encoded slash cannot collapse subject hierarchy
		strings.Replace(prefix+"web", "/v1/", "/v2/", 1),
		strings.Replace(prefix+"web", "/ephemeral/", "/attested/", 1),
		strings.Replace(prefix+"web", "/tenant/11111111-1111-4111-8111-111111111111/", "/tenant/other/", 1),
		"spiffe://approval.test/_trstctl/unknown",
	} {
		if _, err := ephemeral.SubjectFromSPIFFEID(raw); err == nil {
			t.Errorf("malformed reserved name accepted: %s", raw)
		}
	}
	// Historical unreserved names are interpreted literally, not remapped.
	if subject, err := ephemeral.SubjectFromSPIFFEID("spiffe://approval.test/trstctl-hex-613a62"); err != nil || subject != "trstctl-hex-613a62" {
		t.Fatal("historical literal subject changed")
	}
}

func TestApprovalBindingValidatesSignedCertificateLifetimeAndIdentity(t *testing.T) {
	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	defer caKey.Destroy()
	caDER, err := crypto.SelfSignedCACert(caKey, "ephemeral-approval-test-ca", time.Hour)
	if err != nil {
		t.Fatalf("generate CA certificate: %v", err)
	}
	leafKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	defer leafKey.Destroy()

	const spiffeID = "spiffe://approval.test/ns/default/sa/worker"
	const approvedTTL = 10 * time.Second
	binding, err := ephemeral.NewApprovalBinding(
		"1a382d7d-930b-42ba-aa1b-a9c4459d821b", caDER, "request-7", "k8s_sat",
		"ns/default/sa/worker", []string{"sa:worker", "ns:default"},
		leafKey.Public().DER, spiffeID, approvedTTL,
	)
	if err != nil {
		t.Fatalf("build approval binding: %v", err)
	}
	certDER, err := crypto.SignSVID(caDER, caKey, leafKey.Public().DER, spiffeID, approvedTTL)
	if err != nil {
		t.Fatalf("sign SVID: %v", err)
	}
	eventTime := time.Now().UTC()
	if _, err := binding.ValidateCertificate(certDER, "ephemeral:k8s_sat", approvalTestTenant, eventTime); err != nil {
		t.Fatalf("validate exact approved certificate: %v", err)
	}
	notBefore, notAfter, err := crypto.CertValidity(certDER)
	if err != nil {
		t.Fatalf("read approved certificate validity: %v", err)
	}
	delayedRecordTime := notBefore.Add(time.Duration(binding.NotBeforeBackdateSeconds)*time.Second + 3*time.Second)
	if !delayedRecordTime.Before(notAfter) {
		t.Fatalf("fixture record time %s is not before certificate expiry %s", delayedRecordTime, notAfter)
	}
	if _, err := binding.ValidateCertificate(certDER, "ephemeral:k8s_sat", approvalTestTenant, delayedRecordTime); err != nil {
		t.Fatalf("bounded post-sign record delay was rejected: %v", err)
	}
	stalledRecordTime := notBefore.Add(time.Duration(binding.NotBeforeBackdateSeconds)*time.Second + 7*time.Second)
	if !stalledRecordTime.Before(notAfter) {
		t.Fatalf("fixture stalled record time %s is not before certificate expiry %s", stalledRecordTime, notAfter)
	}
	if _, err := binding.ValidateCertificate(certDER, "ephemeral:k8s_sat", approvalTestTenant, stalledRecordTime); err == nil {
		t.Fatal("certificate recorded after the bounded post-sign window was accepted")
	}

	shorterAuthority := binding
	shorterAuthority.TTLSeconds = 1
	if _, err := shorterAuthority.ValidateCertificate(certDER, "ephemeral:k8s_sat", approvalTestTenant, eventTime); err == nil {
		t.Fatal("certificate whose signed lifetime exceeds approved TTL was accepted")
	}
	tighterBackdate := binding
	tighterBackdate.NotBeforeBackdateSeconds = 1
	if _, err := tighterBackdate.ValidateCertificate(certDER, "ephemeral:k8s_sat", approvalTestTenant, eventTime); err == nil {
		t.Fatal("certificate whose signed NotBefore exceeds approved backdate was accepted")
	}
	wrongMethod := binding
	wrongMethod.AttestationMethod = "tpm_quote"
	if _, err := wrongMethod.ValidateCertificate(certDER, "ephemeral:k8s_sat", approvalTestTenant, eventTime); err == nil {
		t.Fatal("certificate from a different attestation method was accepted")
	}
}
