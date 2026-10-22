// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/store"
)

// A35 extension: the host binding carries rfc822Name and URI identifiers on
// their own halves. A renewal bound to an email address and a SPIFFE URI
// certifies exactly those; a CSR naming a different email or URI, or one of
// either kind against a binding that carries none, is refused by name.
func TestACSRMayAssertOnlyTheEmailAndURINamesItsJobCarries(t *testing.T) {
	t.Parallel()
	csr := func(cn string, emails, uris []string) []byte {
		signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
		if err != nil {
			t.Fatal(err)
		}
		defer signer.Destroy()
		der, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
			CommonName: cn, DNSNames: []string{cn}, EmailAddresses: emails, URIs: uris,
		}, signer)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	emails := []string{"Ops@example.test"}
	uris := []string{"spiffe://example.test/api"}
	for name, tc := range map[string]struct {
		csr          []byte
		emails, uris []string
		code         codes.Code
		want         string
	}{
		"bound email and uri":  {csr("api.example.test", emails, uris), emails, uris, codes.OK, ""},
		"email case differs":   {csr("api.example.test", []string{"ops@EXAMPLE.test"}, nil), emails, uris, codes.OK, ""},
		"subset":               {csr("api.example.test", nil, nil), emails, uris, codes.OK, ""},
		"unbound email":        {csr("api.example.test", []string{"other@example.test"}, nil), emails, uris, codes.PermissionDenied, "other@example.test"},
		"unbound uri":          {csr("api.example.test", nil, []string{"spiffe://example.test/other"}), emails, uris, codes.PermissionDenied, "spiffe://example.test/other"},
		"uri case differs":     {csr("api.example.test", nil, []string{"spiffe://example.test/API"}), emails, uris, codes.PermissionDenied, "spiffe://example.test/API"},
		"binding carries none": {csr("api.example.test", emails, nil), nil, nil, codes.PermissionDenied, "Ops@example.test"},
	} {
		t.Run(name, func(t *testing.T) {
			err := authorizeAgentCSRWithInspector(tc.csr, []string{"api.example.test"}, nil, tc.emails, tc.uris, crypto.InspectCSR)
			if status.Code(err) != tc.code {
				t.Fatalf("authorize = %v, want %v", err, tc.code)
			}
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refusal %q does not name the offending identifier %q", err, tc.want)
			}
		})
	}
}

func TestServedHostGeneratedRenewalCertifiesBoundEmailAndURINames(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleHost}, agentJobKindEndpointRenew)
	owner, err := h.srv.orch.CreateOwner(ctx, h.tenant, string(store.OwnerTeam), "Platform Team", "platform@example.test")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := h.srv.orch.CreateIdentity(ctx, h.tenant, store.Identity{
		Kind: store.KindX509Certificate, Name: "mail.example.test", OwnerID: owner.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(RelayDeployIntent{
		Connector: "nginx", Target: "edge-1", IdentityID: identity.ID,
		SubjectCommonName: "mail.example.test", SubjectDNSNames: []string{"mail.example.test"},
		SubjectEmailAddresses: []string{"ops@example.test"}, SubjectURIs: []string{"spiffe://example.test/mail"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key, required_agent_id)
			 VALUES ($1, $2, $3, $4, $5)`,
			h.tenant, agentJobKindEndpointRenew, payload, "renew:email-uri-san", agentRowID(h.tenant, h.agent))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	job := claimOneRenewal(t, ctx, h)

	unbound := csrWithExtraSAN(t, "mail.example.test", func(tmpl *crypto.CertificateRequestTemplate) {
		tmpl.EmailAddresses = []string{"ops@example.test"}
		tmpl.URIs = []string{"spiffe://example.test/other"}
	})
	_, err = h.client.SignJobCSR(ctx, &transport.SignJobCSRRequest{JobID: job.JobID, Attempt: job.Attempt, CSRDER: unbound})
	if status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), "spiffe://example.test/other") {
		t.Fatalf("a CSR for a URI outside the binding was not refused by name: %v", err)
	}

	bound := csrWithExtraSAN(t, "mail.example.test", func(tmpl *crypto.CertificateRequestTemplate) {
		tmpl.EmailAddresses = []string{"ops@example.test"}
		tmpl.URIs = []string{"spiffe://example.test/mail"}
	})
	resp, err := h.client.SignJobCSR(ctx, &transport.SignJobCSRRequest{JobID: job.JobID, Attempt: job.Attempt, CSRDER: bound})
	if err != nil {
		t.Fatalf("sign bound email+uri csr: %v", err)
	}
	info, err := certinfo.Inspect(resp.CertificatePEM)
	if err != nil {
		t.Fatal(err)
	}
	if len(info.EmailAddresses) != 1 || info.EmailAddresses[0] != "ops@example.test" || len(info.URIs) != 1 || info.URIs[0] != "spiffe://example.test/mail" || len(info.DNSNames) != 1 {
		t.Fatalf("issued SANs dns=%v email=%v uri=%v; want the bound DNS name, email and URI exactly", info.DNSNames, info.EmailAddresses, info.URIs)
	}
}
