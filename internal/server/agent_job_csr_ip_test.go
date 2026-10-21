// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/store"
)

// IP-address identities on the host-generated CSR path (A35).
//
// A renewal, migration or re-protection binding may now carry iPAddress SANs
// next to its DNS names. The rule is unchanged in kind: the binding is the
// authorization, the CSR is checked against it, and an identifier type the
// binding cannot express (rfc822Name, URI) is still refused outright.

func TestPermittedIPAddressesAreReadFromTheJobPayload(t *testing.T) {
	t.Parallel()
	payload, err := json.Marshal(RelayDeployIntent{
		Connector: "nginx", Target: "edge-1",
		SubjectCommonName:  "10.0.0.5",
		SubjectDNSNames:    []string{"api.example.test"},
		SubjectIPAddresses: []string{"10.0.0.5", " 2001:DB8:0:0::1 ", "not-an-ip", "10.0.0.5"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ips := signJobCSRPermittedIPAddresses(payload)
	if len(ips) != 2 || ips[0] != "10.0.0.5" || ips[1] != "2001:db8::1" {
		t.Fatalf("permitted IPs = %v, want the two distinct normalized addresses; an unparseable entry authorizes nothing", ips)
	}
	// A common name that is an IP literal belongs to the IP set, not the DNS set:
	// a CSR could otherwise assert it as a dNSName the binding never meant.
	names := signJobCSRPermittedNames(payload)
	if len(names) != 1 || names[0] != "api.example.test" {
		t.Fatalf("permitted DNS names = %v, want only the DNS name", names)
	}
	if ips := signJobCSRPermittedIPAddresses([]byte("not json")); len(ips) != 0 {
		t.Fatalf("an undecodable payload authorized %v", ips)
	}
}

func TestACSRMayAssertOnlyTheIPAddressesItsJobCarries(t *testing.T) {
	t.Parallel()
	csr := func(cn string, dns []string, ips ...string) []byte {
		signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
		if err != nil {
			t.Fatal(err)
		}
		defer signer.Destroy()
		tmpl := crypto.CertificateRequestTemplate{CommonName: cn, DNSNames: dns}
		for _, ip := range ips {
			tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP(ip))
		}
		der, err := crypto.CreateCertificateRequest(tmpl, signer)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	dns := []string{"api.example.test"}
	ips := []string{"10.0.0.7", "2001:db8::1"}
	for name, tc := range map[string]struct {
		csr  []byte
		ips  []string
		code codes.Code
		want string
	}{
		"bound ip":            {csr("api.example.test", dns, "10.0.0.7"), ips, codes.OK, ""},
		"ipv6 spelled longer": {csr("api.example.test", dns, "2001:db8:0:0::1"), ips, codes.OK, ""},
		"ip-only subject":     {csr("10.0.0.7", nil, "10.0.0.7"), ips, codes.OK, ""},
		"subset of ips":       {csr("api.example.test", dns), ips, codes.OK, ""},
		"unbound ip":          {csr("api.example.test", dns, "10.0.0.8"), ips, codes.PermissionDenied, "10.0.0.8"},
		"dns-only binding":    {csr("api.example.test", dns, "10.0.0.7"), nil, codes.PermissionDenied, "10.0.0.7"},
		"ip literal as dns":   {csr("api.example.test", []string{"api.example.test", "10.0.0.7"}), ips, codes.PermissionDenied, "10.0.0.7"},
		"ip common name":      {csr("10.0.0.8", dns), ips, codes.PermissionDenied, "10.0.0.8"},
	} {
		t.Run(name, func(t *testing.T) {
			err := authorizeAgentCSRWithInspector(tc.csr, []string{"api.example.test"}, tc.ips, crypto.InspectCSR)
			if status.Code(err) != tc.code {
				t.Fatalf("authorize = %v, want %v", err, tc.code)
			}
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refusal %q does not name the offending address %q", err, tc.want)
			}
		})
	}
}

func TestHostRenewalSubjectKeepsIPIdentifiers(t *testing.T) {
	t.Parallel()
	caSigner, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer caSigner.Destroy()
	caDER, err := crypto.SelfSignedCACert(caSigner, "renewal subject test CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf := func(tmpl crypto.CertificateRequestTemplate) store.Certificate {
		signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
		if err != nil {
			t.Fatal(err)
		}
		defer signer.Destroy()
		csrDER, err := crypto.CreateCertificateRequest(tmpl, signer)
		if err != nil {
			t.Fatal(err)
		}
		der, err := crypto.SignLeafFromCSR(caDER, caSigner, csrDER, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return store.Certificate{CertificateDER: der}
	}
	dnsNames, ips, ok := hostRenewalSubject(leaf(crypto.CertificateRequestTemplate{
		CommonName: "api.example.test", DNSNames: []string{"api.example.test"},
		IPAddresses: []net.IP{net.ParseIP("10.0.0.7")},
	}))
	if !ok || len(dnsNames) != 1 || len(ips) != 1 || ips[0] != "10.0.0.7" {
		t.Fatalf("dns+ip predecessor: dns=%v ips=%v ok=%v; want both identifier sets kept", dnsNames, ips, ok)
	}
	dnsNames, ips, ok = hostRenewalSubject(leaf(crypto.CertificateRequestTemplate{
		CommonName: "10.0.0.7", IPAddresses: []net.IP{net.ParseIP("10.0.0.7")},
	}))
	if !ok || len(dnsNames) != 0 || len(ips) != 1 {
		t.Fatalf("ip-only predecessor: dns=%v ips=%v ok=%v; want renewable", dnsNames, ips, ok)
	}
	if _, _, ok := hostRenewalSubject(leaf(crypto.CertificateRequestTemplate{
		CommonName: "api.example.test", DNSNames: []string{"api.example.test"},
		EmailAddresses: []string{"ops@example.test"},
	})); ok {
		t.Fatal("an rfc822Name predecessor was offered to a path that cannot preserve it")
	}
	if _, _, ok := hostRenewalSubject(leaf(crypto.CertificateRequestTemplate{
		CommonName: "api.example.test", DNSNames: []string{"api.example.test"},
		URIs: []string{"spiffe://example.test/api"},
	})); ok {
		t.Fatal("a URI predecessor was offered to a path that cannot preserve it")
	}
}

// Served: a host renewal bound to an IP address certifies it, and a CSR naming
// a different address is refused with that address in the reason.
func TestServedHostGeneratedRenewalCertifiesBoundIPAddresses(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleHost}, agentJobKindEndpointRenew)
	owner, err := h.srv.orch.CreateOwner(ctx, h.tenant, string(store.OwnerTeam), "Platform Team", "platform@example.test")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := h.srv.orch.CreateIdentity(ctx, h.tenant, store.Identity{
		Kind: store.KindX509Certificate, Name: "ip.example.test", OwnerID: owner.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(RelayDeployIntent{
		Connector: "nginx", Target: "edge-1", IdentityID: identity.ID,
		SubjectCommonName: "ip.example.test", SubjectDNSNames: []string{"ip.example.test"},
		SubjectIPAddresses: []string{"10.0.0.7"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key, required_agent_id)
			 VALUES ($1, $2, $3, $4, $5)`,
			h.tenant, agentJobKindEndpointRenew, payload, "renew:ip-san", agentRowID(h.tenant, h.agent))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	job := claimOneRenewal(t, ctx, h)

	unbound := csrWithExtraSAN(t, "ip.example.test", func(tmpl *crypto.CertificateRequestTemplate) {
		tmpl.IPAddresses = []net.IP{net.ParseIP("10.0.0.8")}
	})
	_, err = h.client.SignJobCSR(ctx, &transport.SignJobCSRRequest{JobID: job.JobID, Attempt: job.Attempt, CSRDER: unbound})
	if status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), "10.0.0.8") {
		t.Fatalf("a CSR for an address outside the binding was not refused by name: %v", err)
	}

	bound := csrWithExtraSAN(t, "ip.example.test", func(tmpl *crypto.CertificateRequestTemplate) {
		tmpl.IPAddresses = []net.IP{net.ParseIP("10.0.0.7")}
	})
	resp, err := h.client.SignJobCSR(ctx, &transport.SignJobCSRRequest{JobID: job.JobID, Attempt: job.Attempt, CSRDER: bound})
	if err != nil {
		t.Fatalf("sign bound ip csr: %v", err)
	}
	info, err := certinfo.Inspect(resp.CertificatePEM)
	if err != nil {
		t.Fatal(err)
	}
	if len(info.IPAddresses) != 1 || info.IPAddresses[0] != "10.0.0.7" || len(info.DNSNames) != 1 {
		t.Fatalf("issued SANs dns=%v ip=%v; want the bound DNS name and IP address", info.DNSNames, info.IPAddresses)
	}
}
