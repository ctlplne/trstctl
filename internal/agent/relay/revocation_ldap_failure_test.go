// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/revocationhealth"
)

// B13-R3: against the lab Samba DC the relay reported ldap_bind_failed while
// the bind never happened: Go refused the DC's TLS certificate (negative serial
// number). Each way the directory read fails before a CRL is read now has its
// own code: the connection, the TLS handshake (naming the TLS stack's reason),
// the bind itself, and a credential that was not redeemed.
func TestLDAPDirectoryFailuresAreNamedApart(t *testing.T) {
	const sambaStartTLS = `LDAP Result Code 200 "Network Error": TLS handshake failed (tls: failed to parse certificate from server: x509: negative serial number)`
	if got := tlsFailureReason(errors.New(sambaStartTLS)); got != "tls: failed to parse certificate from server: x509: negative serial number" {
		t.Fatalf("TLS reason = %q", got)
	}
	if got := tlsFailureReason(errors.New(`LDAP Result Code 200 "Network Error": dial tcp 127.0.0.1:1: connect: connection refused`)); got != "" {
		t.Fatalf("a refused connection read as a TLS failure: %q", got)
	}

	// Real sockets: a closed port, and a listener that hangs up instead of
	// answering StartTLS.
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := closed.Addr().String()
	_ = closed.Close()
	hangup, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hangup.Close() })
	go func() {
		for {
			conn, err := hangup.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	if _, err := dialCRLDirectory(revocationhealth.LDAPBinding{URL: "ldap://" + closedAddr, BindDN: "alice"}, []byte("x")); !errors.Is(err, errLDAPConnect) {
		t.Fatalf("closed port = %v, want a connection failure", err)
	}
	if _, err := dialCRLDirectory(revocationhealth.LDAPBinding{URL: "ldap://" + hangup.Addr().String(), BindDN: "alice"}, []byte("x")); !errors.Is(err, errLDAPTLS) {
		t.Fatalf("StartTLS hang-up = %v, want a TLS failure", err)
	}

	binding := &revocationhealth.LDAPBinding{SourceID: "6f1f8f84-3c3e-4f6f-9a43-1f4f3f0d0a10", URL: "ldap://dc1.lab.test:389", // #nosec G101 -- a non-secret secret:// reference fixture, not secret material (CWE-798).
		ConfigurationDN: ldapTestConfigurationDN, BindDN: "alice@lab.test", PasswordRef: "secret://adcs/bind"}
	target := ldapTestTarget(strings.Repeat("1", 64), "ldap:///CN=Lab%20Issuing%20CA,CN=CDP,"+strings.ReplaceAll(ldapTestConfigurationDN, " ", "%20")+
		"?certificateRevocationList?base?objectClass=cRLDistributionPoint", []byte("issuer"))
	intent := RevocationProbeIntent{ID: "8a0c2f43-1d5e-4f21-9b7c-0e9c2a1f3b46", Bucket: "2026-10-24T21:00:00Z", BatchIndex: 1, BatchCount: 1,
		Targets: []revocationhealth.Target{target}, StaleWithinSeconds: 3600,
		RequiredAgentRole: revocationhealth.RequiredRoleNetwork, LDAPBinding: binding}
	original := openCRLDirectory
	t.Cleanup(func() { openCRLDirectory = original })
	for _, tc := range []struct {
		err  error
		code string
	}{
		{errors.New("could not connect") /* untyped */, "ldap_bind_failed"},
		{errLDAPConnect, "ldap_connect_failed"},
		{errors.Join(errLDAPTLS, errors.New("tls: failed to parse certificate from server: x509: negative serial number")), "ldap_tls_failed"},
		{errLDAPBind, "ldap_bind_failed"},
	} {
		openCRLDirectory = func(revocationhealth.LDAPBinding, []byte) (crlDirectory, error) { return nil, tc.err }
		report, err := ProbeRevocationWithDirectory(context.Background(), http.DefaultClient, intent, Material{"secret://adcs/bind": []byte("x")})
		if err != nil {
			t.Fatal(err)
		}
		if f := report.Findings[0]; f.DetailCode != tc.code || f.Status != RevocationUnreachable {
			t.Errorf("directory error %v = %s/%s, want unreachable/%s", tc.err, f.Status, f.DetailCode, tc.code)
		}
	}
	report, err := ProbeRevocationWithDirectory(context.Background(), http.DefaultClient, intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	if f := report.Findings[0]; f.DetailCode != "ldap_credential_unavailable" {
		t.Fatalf("no redeemed credential = %s", f.DetailCode)
	}
	for _, code := range []string{"ldap_connect_failed", "ldap_tls_failed", "ldap_credential_unavailable"} {
		finding := report.Findings[0]
		finding.DetailCode = code
		if err := revocationhealth.ValidateReport(intent, RevocationReport{Findings: []RevocationFinding{finding}}); err != nil {
			t.Fatalf("the control plane's report contract refuses %s: %v", code, err)
		}
	}
}
