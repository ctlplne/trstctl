// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	xacme "golang.org/x/crypto/acme"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/acmekey"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/profile"
	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
)

// A162-L4: an ACME client revokes a certificate trstctl's ACME issued through
// a profile's upstream CA (A159) the same way it revokes one trstctl's own CA
// issued, and the revocation goes to that upstream. With an AD CS upstream
// that has a revocation relay, revokeCert answers 200 and queues the exact
// external revocation the bulk API queues (an outbox delivery on the
// upstream's lane, naming the certificate and the reason); the certificate
// stays active until the CA confirms, a repeated revokeCert queues nothing
// more, and trstctl's own revocation ledger never lists the upstream's serial.
// With an upstream that cannot revoke, the client is told so as unauthorized
// (403), not as a server error. Before, both failed as a 500 "issuer
// revocation is not supported".
func TestServedACMERevokesAnUpstreamIssuedCertificateAtTheUpstreamA162L4(t *testing.T) {
	issueThroughADCS := func(t *testing.T, withRelay bool) (*servedHarness, *xacme.Client, []byte) {
		t.Helper()
		standIn, certsrv := newADCSCertsrvStandIn(t)
		upstreams := adcsUpstreamConfig(t, certsrv.URL)
		if withRelay {
			upstreams = adcsRevocationConfig(t, certsrv.URL, "a162l4-relay")
		}
		dns := newServedDNSWebhookFixture(t, "a162l4-client-dns")
		validators := acmesrv.Validators{DNS01: acmesrv.DNS01Validator{Resolver: dns}}
		h := newServedHarness(t,
			config.Protocols{ACME: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}},
			func(d *Deps) {
				d.ACMEValidators = &validators
				d.ExternalCAs = upstreams
				d.DefaultProfile = "adcs-web"
			},
		)
		registerServedTenant(t, h, "A162-L4 ACME upstream tenant")
		startServedOutboxPump(t, h.srv)
		storeServerTestProfile(t, h.store, h.tenant, "adcs-web", profile.CertificateProfile{
			Name: "adcs-web", AllowedProtocols: []string{"acme"}, AllowedDNSSuffixes: []string{"served.test"},
			MaxValidity: profile.Duration(7 * 24 * time.Hour), UpstreamExternalCA: "corp-adcs-web",
		})
		ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
		t.Cleanup(cancel)
		client, err := acmekey.NewRSAClient(h.ts.URL + "/directory")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
			t.Fatal(err)
		}
		domain := "a162l4.served.test"
		order, err := client.AuthorizeOrder(ctx, xacme.DomainIDs(domain))
		if err != nil {
			t.Fatal(err)
		}
		authz, err := client.GetAuthorization(ctx, order.AuthzURLs[0])
		if err != nil {
			t.Fatal(err)
		}
		for _, challenge := range authz.Challenges {
			if challenge.Type != acmesrv.ChallengeDNS01 {
				continue
			}
			value, err := client.DNS01ChallengeRecord(challenge.Token)
			if err != nil {
				t.Fatal(err)
			}
			dns.mu.Lock()
			dns.records[acmesrv.DNS01RecordName(domain)] = map[string]bool{value: true}
			dns.mu.Unlock()
			if _, err := client.Accept(ctx, challenge); err != nil {
				t.Fatal(err)
			}
		}
		if order, err = client.WaitOrder(ctx, order.URI); err != nil {
			t.Fatal(err)
		}
		chain, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, buildServedCSR(t, domain), true)
		if err != nil || len(chain) == 0 {
			t.Fatalf("finalize through the AD CS upstream: %v (chain %d)", err, len(chain))
		}
		if err := crypto.VerifyLeafSignedByCA(chain[0], standIn.caDER); err != nil {
			t.Fatalf("the ACME certificate was not issued by the AD CS upstream: %v", err)
		}
		return h, client, chain[0]
	}

	t.Run("an upstream with a revocation relay", func(t *testing.T) {
		h, client, leaf := issueThroughADCS(t, true)
		info, err := certinfo.Inspect(leaf)
		if err != nil {
			t.Fatal(err)
		}
		// A deadline bounds the client's retries of a server error, so a
		// failure reports the server's answer instead of retrying forever.
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		if err := client.RevokeCert(ctx, nil, leaf, xacme.CRLReasonKeyCompromise); err != nil {
			t.Fatalf("revokeCert of the upstream-issued certificate: %v", err)
		}
		var payload []byte
		if err := h.store.SystemPool().QueryRow(t.Context(),
			`SELECT payload FROM outbox WHERE tenant_id = $1 AND destination = 'revocation.publish'
			   AND effect_lane = 'revocation.publish:authority:corp-adcs-web'`, h.tenant).Scan(&payload); err != nil {
			t.Fatalf("no external revocation was queued for the upstream: %v", err)
		}
		var queued struct {
			Fingerprint  string `json:"fingerprint"`
			Serial       string `json:"serial"`
			ExternalCAID string `json:"external_ca_id"`
			Reason       string `json:"reason"`
		}
		if err := json.Unmarshal(payload, &queued); err != nil || queued.Fingerprint != info.SHA256Fingerprint ||
			queued.ExternalCAID != "corp-adcs-web" || queued.Reason != "keyCompromise" {
			t.Fatalf("queued external revocation = %+v (%v); want this certificate at corp-adcs-web for keyCompromise", queued, err)
		}
		certificate, err := h.store.GetCertificateByFingerprint(t.Context(), h.tenant, info.SHA256Fingerprint)
		if err != nil || certificate.Status != "active" {
			t.Fatalf("the certificate before the CA confirms = %q (%v); want active", certificate.Status, err)
		}
		// A repeated revokeCert is the same exact command: it queues nothing
		// more (the served ACME answers a repeat as it does for a leaf
		// trstctl's own CA issued).
		if err := client.RevokeCert(ctx, nil, leaf, xacme.CRLReasonKeyCompromise); err != nil {
			t.Fatalf("a repeated revokeCert: %v", err)
		}
		var deliveries int
		if err := h.store.SystemPool().QueryRow(t.Context(),
			`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination = 'revocation.publish'
			   AND effect_lane = 'revocation.publish:authority:corp-adcs-web'`, h.tenant).Scan(&deliveries); err != nil || deliveries != 1 {
			t.Fatalf("external revocations after a repeated revokeCert = %d (%v); want the one", deliveries, err)
		}
		var listedLocally int
		if err := h.store.SystemPool().QueryRow(t.Context(),
			`SELECT count(*) FROM ca_issued_certs WHERE tenant_id = $1 AND serial = $2 AND revoked_at IS NOT NULL`, h.tenant, info.SerialNumber).Scan(&listedLocally); err != nil {
			t.Fatal(err)
		}
		if listedLocally != 0 {
			t.Fatal("trstctl's own revocation ledger lists the upstream's serial")
		}
	})

	t.Run("an upstream that cannot revoke", func(t *testing.T) {
		_, client, leaf := issueThroughADCS(t, false)
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		var refused *xacme.Error
		err := client.RevokeCert(ctx, nil, leaf, xacme.CRLReasonKeyCompromise)
		if !errors.As(err, &refused) || refused.StatusCode != http.StatusForbidden || !strings.HasSuffix(refused.ProblemType, ":unauthorized") ||
			!strings.Contains(refused.Detail, "configured without a way to revoke") {
			t.Fatalf("revokeCert at an upstream that cannot revoke = %v; want 403 unauthorized naming why", err)
		}
	})
}
