// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/revocationhealth"
)

// stubCRLDirectory stands in for a bound AD CS directory: CRLs by entry DN.
type stubCRLDirectory struct {
	crls   map[string][]byte
	reads  []string
	closed bool
}

func (d *stubCRLDirectory) ReadCRL(_ context.Context, dn string) ([]byte, error) {
	d.reads = append(d.reads, dn)
	body, ok := d.crls[strings.ToLower(dn)]
	if !ok {
		return nil, errLDAPCRLEntryMissing
	}
	return body, nil
}

func (d *stubCRLDirectory) Close() error {
	d.closed = true
	return nil
}

const ldapTestConfigurationDN = "CN=Configuration,DC=lab,DC=test"

func ldapTestTarget(key, endpoint string, issuerDER []byte) revocationhealth.Target {
	return revocationhealth.Target{Key: key, Protocol: revocationhealth.ProtocolCRL, Endpoint: endpoint,
		IssuerSubject: "CN=Lab Issuing CA", IssuerDER: issuerDER, CertificateID: "certificate-1",
		CertificateSubject: "CN=web.lab.test", CertificateFingerprint: strings.Repeat("c", 64), CertificateSerial: "0a"}
}

// A107: an AD CS LDAP distribution point is read through the tenant's AD CS
// binding. One bound connection serves the batch; it is opened with the bind
// credential redeemed for the attempt and closed after; the CRL is evaluated
// exactly as an HTTP one; a host the binding does not name and a missing entry
// are reported for what they are.
func TestLDAPCRLDistributionPointsAreReadThroughTheADCSBinding(t *testing.T) {
	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(caKey.Destroy)
	caDER, err := crypto.SelfSignedCACert(caKey, "Lab Issuing CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	crl, err := crypto.CreateCRL(caDER, caKey, nil, 1, now.Add(-time.Hour), now.Add(72*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	cdpDN := "CN=Lab Issuing CA,CN=dc1,CN=CDP,CN=Public Key Services,CN=Services," + ldapTestConfigurationDN
	stub := &stubCRLDirectory{crls: map[string][]byte{strings.ToLower(cdpDN): crl}}
	var opened revocationhealth.LDAPBinding
	var openedWith string
	restore := openCRLDirectory
	t.Cleanup(func() { openCRLDirectory = restore })
	openCRLDirectory = func(binding revocationhealth.LDAPBinding, password []byte) (crlDirectory, error) {
		opened, openedWith = binding, string(password)
		return stub, nil
	}
	binding := &revocationhealth.LDAPBinding{SourceID: "6f1f8f84-3c3e-4f6f-9a43-1f4f3f0d0a10", URL: "ldaps://dc1.lab.test:636", // #nosec G101 -- a non-secret secret:// reference fixture, not secret material (CWE-798).
		ConfigurationDN: ldapTestConfigurationDN, BindDN: "CN=svc-pki,CN=Users,DC=lab,DC=test", PasswordRef: "secret://adcs/bind"}
	fresh := ldapTestTarget(strings.Repeat("1", 64), "ldap:///"+strings.ReplaceAll(cdpDN, " ", "%20")+
		"?certificateRevocationList?base?objectClass=cRLDistributionPoint", caDER)
	otherHost := ldapTestTarget(strings.Repeat("2", 64), "ldap://dc9.other.test/CN=Lab Issuing CA,CN=CDP,"+ldapTestConfigurationDN, caDER)
	missing := ldapTestTarget(strings.Repeat("3", 64), "ldap:///CN=Gone CA,CN=CDP,"+ldapTestConfigurationDN, caDER)
	intent := RevocationProbeIntent{ID: "8a0c2f43-1d5e-4f21-9b7c-0e9c2a1f3b44", Bucket: "2026-10-24T00:00:00Z", BatchIndex: 1, BatchCount: 1,
		Targets: []revocationhealth.Target{fresh, otherHost, missing}, StaleWithinSeconds: 3600,
		RequiredAgentRole: revocationhealth.RequiredRoleNetwork, LDAPBinding: binding}

	report, err := ProbeRevocationWithDirectory(context.Background(), http.DefaultClient, intent, Material{"secret://adcs/bind": []byte("bind-pw")})
	if err != nil {
		t.Fatal(err)
	}
	if opened.URL != binding.URL || openedWith != "bind-pw" || !stub.closed {
		t.Fatalf("directory opened=%+v with=%q closed=%v; want the binding, the redeemed credential, and a close", opened, openedWith, stub.closed)
	}
	byKey := map[string]RevocationFinding{}
	for _, f := range report.Findings {
		byKey[f.TargetKey] = f
	}
	if f := byKey[fresh.Key]; f.Status != RevocationFresh || !f.SignatureVerified || f.NextUpdate == nil {
		t.Fatalf("bound LDAP CRL = %+v; want fresh and verified", f)
	}
	if f := byKey[otherHost.Key]; f.Status != RevocationUnparseable || f.DetailCode != "ldap_host_not_bound" {
		t.Fatalf("LDAP CDP on another host = %+v", f)
	}
	if f := byKey[missing.Key]; f.Status != RevocationUnreachable || f.DetailCode != "ldap_entry_missing" {
		t.Fatalf("LDAP CDP with no entry = %+v", f)
	}
	if len(stub.reads) != 2 {
		t.Fatalf("directory reads = %v; the unbound host must not be read", stub.reads)
	}

	// No credential redeemed: nothing is dialed and every bound target says why.
	stub.closed, opened = false, revocationhealth.LDAPBinding{}
	report, err = ProbeRevocationWithDirectory(context.Background(), http.DefaultClient, intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	if f := report.Findings[0]; f.DetailCode != "ldap_bind_failed" || !strings.Contains(f.Detail, "not redeemed") || opened.URL != "" {
		t.Fatalf("probe without the bind credential = %+v (dialed %q)", f, opened.URL)
	}
	// A refused bind is reported, not mistaken for a stale CRL.
	openCRLDirectory = func(revocationhealth.LDAPBinding, []byte) (crlDirectory, error) {
		return nil, errors.New("the directory refused the bind")
	}
	report, err = ProbeRevocationWithDirectory(context.Background(), http.DefaultClient, intent, Material{"secret://adcs/bind": []byte("x")})
	if err != nil {
		t.Fatal(err)
	}
	if f := report.Findings[0]; f.Status != RevocationUnreachable || !strings.Contains(f.Detail, "refused the bind") {
		t.Fatalf("probe after a refused bind = %+v", f)
	}
}

// A batch with an LDAP binding redeems its bind credential for the attempt;
// an HTTP batch never asks.
func TestRevocationProbeRedeemsOnlyForAnLDAPBatch(t *testing.T) {
	restore := openCRLDirectory
	t.Cleanup(func() { openCRLDirectory = restore })
	var password string
	openCRLDirectory = func(_ revocationhealth.LDAPBinding, pw []byte) (crlDirectory, error) {
		password = string(pw)
		return &stubCRLDirectory{}, nil
	}
	bound := RevocationProbeIntent{ID: "8a0c2f43-1d5e-4f21-9b7c-0e9c2a1f3b45", Bucket: "b", BatchIndex: 1, BatchCount: 1,
		Targets:           []revocationhealth.Target{ldapTestTarget(strings.Repeat("4", 64), "ldap:///CN=CA,CN=CDP,"+ldapTestConfigurationDN, []byte{1})},
		RequiredAgentRole: revocationhealth.RequiredRoleNetwork,
		LDAPBinding: &revocationhealth.LDAPBinding{SourceID: "6f1f8f84-3c3e-4f6f-9a43-1f4f3f0d0a10", URL: "ldaps://dc1.lab.test", // #nosec G101 -- a non-secret secret:// reference fixture, not secret material (CWE-798).
			ConfigurationDN: ldapTestConfigurationDN, BindDN: "CN=svc", PasswordRef: "secret://adcs/bind"}}
	payload, err := json.Marshal(bound)
	if err != nil {
		t.Fatal(err)
	}
	ch := &redeemRecordingChannel{material: map[string][]byte{"secret://adcs/bind": []byte("bind-pw")}}
	runRevocationProbe(context.Background(), ch, http.DefaultClient, Job{JobID: 7, Attempt: 2, Kind: KindRevocationProbe, Payload: payload})
	if ch.redeemed != 1 || password != "bind-pw" || len(ch.outcomes) != 1 {
		t.Fatalf("bound batch: redeemed=%d password=%q outcomes=%v", ch.redeemed, password, ch.outcomes)
	}
	plain := bound
	plain.LDAPBinding = nil
	plain.Targets = []revocationhealth.Target{ldapTestTarget(strings.Repeat("5", 64), "http://127.0.0.1:1/crl", []byte{1})}
	payload, err = json.Marshal(plain)
	if err != nil {
		t.Fatal(err)
	}
	ch = &redeemRecordingChannel{}
	runRevocationProbe(context.Background(), ch, http.DefaultClient, Job{JobID: 8, Attempt: 1, Kind: KindRevocationProbe, Payload: payload})
	if ch.redeemed != 0 || len(ch.outcomes) != 1 {
		t.Fatalf("HTTP batch: redeemed=%d outcomes=%v", ch.redeemed, ch.outcomes)
	}
}

type redeemRecordingChannel struct {
	material map[string][]byte
	redeemed int
	outcomes []string
}

func (c *redeemRecordingChannel) ClaimJobs(context.Context, []string, int, int) ([]Job, error) {
	return nil, nil
}

func (c *redeemRecordingChannel) RedeemJobCredential(context.Context, int64, int) (map[string][]byte, error) {
	c.redeemed++
	out := map[string][]byte{}
	for k, v := range c.material {
		out[k] = append([]byte(nil), v...)
	}
	return out, nil
}

func (c *redeemRecordingChannel) ReportJobResult(_ context.Context, _ int64, _ int, outcome, _, _ string) (bool, error) {
	c.outcomes = append(c.outcomes, outcome)
	return true, nil
}
