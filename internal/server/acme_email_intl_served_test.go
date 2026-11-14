// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/smtp"
	"strings"
	"testing"
	"time"

	xacme "golang.org/x/crypto/acme"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/acmekey"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/dkim"
)

// P15-L4 part 1: a mailbox with a quoted local part and a mailbox at an
// internationalized domain are ordered, proven and issued end to end. The
// order names the IDN mailbox in U-labels and the server keeps it in
// A-labels; each challenge mail goes to the canonical address; each reply
// comes through the SMTP intake — the IDN one with its From domain in
// U-labels and its DKIM d= in A-labels — and validates its challenge; each
// certificate names the canonical mailbox as its rfc822Name.
func TestServedEmailOrdersForQuotedAndInternationalMailboxesP15L4(t *testing.T) {
	const (
		quoted     = `"john doe"@p15l4.test`
		idnASCII   = "alice@xn--bcher-kva.p15l4.test"
		idnUnicode = "alice@bücher.p15l4.test"
	)
	relay := startP15SMTPRelay(t)
	dkimKey, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dkimKey.Destroy)
	record := "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(dkimKey.Public().DER)
	h := newOperatingServedHarness(t, config.Protocols{
		ACME: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
		ACMEEmail: config.ACMEEmail{From: "acme@ca.p15l4.test", Domains: []string{"p15l4.test", "xn--bcher-kva.p15l4.test"},
			Profile: "smime-signing", RelayAddr: relay.addr, SMTPListen: "127.0.0.1:0",
			DKIMKeys: map[string]string{"lab._domainkey.p15l4.test": record, "lab._domainkey.xn--bcher-kva.p15l4.test": record}},
	})
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	spec, err := json.Marshal(map[string]any{"name": "smime-signing", "max_validity": "2160h", "allowed_ekus": []string{"emailProtection"},
		"allowed_email_domains": []string{"p15l4.test", "xn--bcher-kva.p15l4.test"}, "allowed_protocols": []string{"acme"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.orch.CreateProfile(ctx, h.tenant, "smime-signing", spec); err != nil {
		t.Fatal(err)
	}
	startServedDirectOutboxPump(t, h.srv)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go h.srv.serveACMEEmailIntake(ctx, ln, nil)
	client, err := acmekey.NewClient(h.ts.URL + "/directory")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
		t.Fatal(err)
	}
	thumbprint, err := xacme.JWKThumbprint(client.Key.Public())
	if err != nil {
		t.Fatal(err)
	}

	type pending struct {
		order *xacme.Order
		authz *xacme.Authorization
	}
	orders := map[string]pending{}
	for requested, canonical := range map[string]string{quoted: quoted, idnUnicode: idnASCII} {
		order, err := client.AuthorizeOrder(ctx, []xacme.AuthzID{{Type: "email", Value: requested}})
		if err != nil {
			t.Fatalf("order %s: %v", requested, err)
		}
		authz, err := client.GetAuthorization(ctx, order.AuthzURLs[0])
		if err != nil || authz.Identifier.Value != canonical {
			t.Fatalf("the order for %s names %+v (%v), want %s", requested, authz, err, canonical)
		}
		orders[canonical] = pending{order: order, authz: authz}
	}
	tokens := map[string]string{}
	for range orders {
		var mail string
		select {
		case mail = <-relay.mails:
		case <-ctx.Done():
			t.Fatal("a challenge mail did not reach the relay")
		}
		to, subject := "", ""
		for _, line := range strings.Split(strings.SplitN(mail, "\r\n\r\n", 2)[0], "\r\n") {
			if v, ok := strings.CutPrefix(line, "To: "); ok {
				to = v
			}
			if v, ok := strings.CutPrefix(line, "Subject: ACME: "); ok {
				subject = v
			}
		}
		if _, ok := orders[to]; !ok || subject == "" {
			t.Fatalf("a challenge mail went to %q", to)
		}
		tokens[to] = subject
	}

	send := func(msg []byte) string {
		t.Helper()
		c, err := smtp.Dial(ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		if err := c.Hello("mta.p15l4.test"); err != nil {
			t.Fatal(err)
		}
		if err := c.Mail("postmaster@p15l4.test"); err != nil {
			t.Fatal(err)
		}
		if err := c.Rcpt("acme@ca.p15l4.test"); err != nil {
			return err.Error()
		}
		wc, err := c.Data()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := wc.Write(msg); err != nil {
			t.Fatal(err)
		}
		if err := wc.Close(); err != nil {
			return err.Error()
		}
		_ = c.Quit()
		return "250"
	}
	for canonical, fromHeader := range map[string]string{quoted: quoted, idnASCII: idnUnicode} {
		p := orders[canonical]
		chal := p.authz.Challenges[0]
		digest, err := crypto.Digest(crypto.SHA256, []byte(tokens[canonical]+chal.Token+"."+thumbprint))
		if err != nil {
			t.Fatal(err)
		}
		msg := []byte("From: " + fromHeader + "\r\nTo: acme@ca.p15l4.test\r\nSubject: Re: ACME: " + tokens[canonical] + "\r\n" +
			"Date: Sat, 14 Nov 2026 12:00:00 +0000\r\nMessage-ID: <r" + tokens[canonical][:6] + "@p15l4.test>\r\n" +
			"Content-Type: text/plain; charset=UTF-8\r\n\r\nYes.\r\n\r\n-----BEGIN ACME RESPONSE-----\r\n" +
			base64.RawURLEncoding.EncodeToString(digest) + "\r\n-----END ACME RESPONSE-----\r\n")
		domain := canonical[strings.LastIndexByte(canonical, '@')+1:]
		signed, err := dkim.Sign(msg, domain, "lab", []string{"From", "To", "Subject", "Date", "Message-ID", "Content-Type"}, dkimKey, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if got := send(signed); got != "250" {
			t.Fatalf("the reply from %s: %s", fromHeader, got)
		}
		if _, err := client.Accept(ctx, chal); err != nil {
			t.Fatal(err)
		}
		if valid, err := client.WaitAuthorization(ctx, p.authz.URI); err != nil || valid.Status != xacme.StatusValid {
			t.Fatalf("the authorization for %s = %+v %v", canonical, valid, err)
		}
		key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
		if err != nil {
			t.Fatal(err)
		}
		ku, err := crypto.KeyUsageRequestExtension(true, false, false)
		if err != nil {
			t.Fatal(err)
		}
		csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
			EmailAddresses: []string{canonical}, ExtraExtensions: []crypto.CertificateExtension{ku}}, key)
		key.Destroy()
		if err != nil {
			t.Fatal(err)
		}
		chain, _, err := client.CreateOrderCert(ctx, p.order.FinalizeURL, csr, true)
		if err != nil || len(chain) == 0 {
			t.Fatalf("finalize %s: %v", canonical, err)
		}
		leaf, err := certinfo.Inspect(chain[0])
		if err != nil || strings.Join(leaf.EmailAddresses, ",") != canonical {
			t.Fatalf("the certificate for %s names %v (%v)", canonical, leaf.EmailAddresses, err)
		}
	}
	t.Logf("P15L4_PART1_OK quoted=%s idn=%s", quoted, idnASCII)
}
