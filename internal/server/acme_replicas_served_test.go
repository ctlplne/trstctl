// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	xacme "golang.org/x/crypto/acme"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/acmekey"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
)

// P15-L1: two control-plane replicas serve ACME from one state log, with no
// affinity between them. Behind a test load balancer the client registers
// and orders an email certificate on replica A; replica B takes the client's
// challenge response and the reply through its own intake, validating a
// challenge it never created; A then reports the authorization valid, B
// finalizes the order, and A serves the certificate B issued. IDs minted on
// the replicas carry a random part, so the two never name different objects
// alike.
func TestServedACMEReplicasShareOneStateP15L1(t *testing.T) {
	relay := startP15SMTPRelay(t)
	protocols := config.Protocols{
		ACME: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
		ACMEEmail: config.ACMEEmail{From: "acme@ca.p15l1.test", Domains: []string{"p15l1.test"},
			Profile: "smime-signing", RelayAddr: relay.addr},
	}
	h := newOperatingServedHarness(t, protocols)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	spec, err := json.Marshal(map[string]any{"name": "smime-signing", "max_validity": "2160h",
		"allowed_ekus": []string{"emailProtection"}, "allowed_email_domains": []string{"p15l1.test"}, "allowed_protocols": []string{"acme"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.orch.CreateProfile(ctx, h.tenant, "smime-signing", spec); err != nil {
		t.Fatal(err)
	}
	startServedDirectOutboxPump(t, h.srv)

	// Replica B: a second served ACME mount on the same log and store, built
	// before any ACME state exists, as a second process would be.
	replicaB, err := h.srv.buildServedACME(ctx, protocols, servedTestTenant, h.srv.newProtocolIssuer(), nil)
	if err != nil {
		t.Fatal(err)
	}
	replicaA := h.ts.Config.Handler
	var onB atomic.Bool
	balancer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if onB.Load() {
			replicaB.ServeHTTP(w, r)
			return
		}
		replicaA.ServeHTTP(w, r)
	}))
	t.Cleanup(balancer.Close)

	client, err := acmekey.NewClient(balancer.URL + "/directory")
	if err != nil {
		t.Fatal(err)
	}
	client.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	if _, err := client.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
		t.Fatal(err)
	}
	thumbprint, err := xacme.JWKThumbprint(client.Key.Public())
	if err != nil {
		t.Fatal(err)
	}
	order, err := client.AuthorizeOrder(ctx, []xacme.AuthzID{{Type: "email", Value: "alice@p15l1.test"}})
	if err != nil {
		t.Fatal(err)
	}
	if parts := strings.Split(order.URI[strings.LastIndex(order.URI, "/")+1:], "-"); len(parts) != 3 || len(parts[2]) != 16 {
		t.Fatalf("a served order ID %q has no random part", order.URI)
	}
	authz, err := client.GetAuthorization(ctx, order.AuthzURLs[0])
	if err != nil || len(authz.Challenges) != 1 {
		t.Fatalf("authorization = %+v %v", authz, err)
	}
	chal := authz.Challenges[0]
	var mail string
	select {
	case mail = <-relay.mails:
	case <-ctx.Done():
		t.Fatal("no challenge mail reached the relay")
	}
	tokenPart1 := ""
	for _, line := range strings.Split(strings.SplitN(mail, "\r\n\r\n", 2)[0], "\r\n") {
		if v, ok := strings.CutPrefix(line, "Subject: ACME: "); ok {
			tokenPart1 = v
		}
	}
	digest, err := crypto.Digest(crypto.SHA256, []byte(tokenPart1+chal.Token+"."+thumbprint))
	if err != nil || tokenPart1 == "" {
		t.Fatalf("the challenge mail's token: %q %v", tokenPart1, err)
	}

	// Replica B takes the client's response and the reply.
	onB.Store(true)
	if accepted, err := client.Accept(ctx, chal); err != nil || accepted.Status != "processing" {
		t.Fatalf("replica B's challenge response = %+v %v", accepted, err)
	}
	if _, err := replicaB.AcceptEmailReply(ctx, acmesrv.EmailReply{From: "alice@p15l1.test", SubjectToken: tokenPart1,
		Response: base64.RawURLEncoding.EncodeToString(digest)}); err != nil {
		t.Fatalf("replica B's reply intake: %v", err)
	}

	// Replica A reports what B validated.
	onB.Store(false)
	if valid, err := client.WaitAuthorization(ctx, authz.URI); err != nil || valid.Status != xacme.StatusValid {
		t.Fatalf("replica A's authorization = %+v %v", valid, err)
	}

	// Replica B finalizes; replica A serves the certificate.
	onB.Store(true)
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	ku, err := crypto.KeyUsageRequestExtension(true, false, false)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		EmailAddresses: []string{"alice@p15l1.test"}, ExtraExtensions: []crypto.CertificateExtension{ku}}, key)
	if err != nil {
		t.Fatal(err)
	}
	chain, certURL, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil || len(chain) == 0 {
		t.Fatalf("replica B's finalize: %v", err)
	}
	onB.Store(false)
	fetched, err := client.FetchCert(ctx, certURL, false)
	if err != nil || len(fetched) == 0 || string(fetched[0]) != string(chain[0]) {
		t.Fatalf("replica A's certificate = %d %v", len(fetched), err)
	}
	leaf, err := certinfo.Inspect(fetched[0])
	if err != nil || strings.Join(leaf.EmailAddresses, ",") != "alice@p15l1.test" {
		t.Fatalf("the certificate names %v (%v)", leaf.EmailAddresses, err)
	}
	t.Logf("P15L1_REPLICAS_OK order=%s cert=%s", order.URI[strings.LastIndex(order.URI, "/")+1:], certURL[strings.LastIndex(certURL, "/")+1:])
}
