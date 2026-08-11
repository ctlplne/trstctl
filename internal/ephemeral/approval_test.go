// SPDX-License-Identifier: MPL-2.0

package ephemeral_test

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	ephemeral "trstctl.com/trstctl/internal/ephemeral"
)

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
	if _, err := binding.ValidateCertificate(certDER, "ephemeral:k8s_sat", eventTime); err != nil {
		t.Fatalf("validate exact approved certificate: %v", err)
	}

	shorterAuthority := binding
	shorterAuthority.TTLSeconds = 1
	if _, err := shorterAuthority.ValidateCertificate(certDER, "ephemeral:k8s_sat", eventTime); err == nil {
		t.Fatal("certificate whose signed lifetime exceeds approved TTL was accepted")
	}
	tighterBackdate := binding
	tighterBackdate.NotBeforeBackdateSeconds = 1
	if _, err := tighterBackdate.ValidateCertificate(certDER, "ephemeral:k8s_sat", eventTime); err == nil {
		t.Fatal("certificate whose signed NotBefore exceeds approved backdate was accepted")
	}
	wrongMethod := binding
	wrongMethod.AttestationMethod = "tpm_quote"
	if _, err := wrongMethod.ValidateCertificate(certDER, "ephemeral:k8s_sat", eventTime); err == nil {
		t.Fatal("certificate from a different attestation method was accepted")
	}
}
