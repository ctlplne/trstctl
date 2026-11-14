// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/smtp"
	"strings"
	"sync"
	"testing"
	"time"

	xacme "golang.org/x/crypto/acme"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/acmekey"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/dkim"
)

// p15l4UTF8Relay is an SMTP relay stand-in that offers SMTPUTF8 (RFC 6531)
// and records the MAIL command and each message it takes.
type p15l4UTF8Relay struct {
	addr  string
	mails chan string
	mu    sync.Mutex
	mail  []string
}

func startP15L4UTF8Relay(t *testing.T) *p15l4UTF8Relay {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	r := &p15l4UTF8Relay{addr: ln.Addr().String(), mails: make(chan string, 4)}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				rd := bufio.NewReader(conn)
				reply := func(line string) { _, _ = conn.Write([]byte(line + "\r\n")) }
				reply("220 relay.p15l4.test ESMTP")
				for {
					line, err := rd.ReadString('\n')
					if err != nil {
						return
					}
					line = strings.TrimSpace(line)
					switch verb := strings.ToUpper(strings.SplitN(line, " ", 2)[0]); verb {
					case "EHLO":
						reply("250-relay.p15l4.test")
						reply("250 SMTPUTF8")
					case "MAIL":
						r.mu.Lock()
						r.mail = append(r.mail, line)
						r.mu.Unlock()
						reply("250 ok")
					case "DATA":
						reply("354 go ahead")
						var msg strings.Builder
						for {
							l, err := rd.ReadString('\n')
							if err != nil {
								return
							}
							if l == ".\r\n" {
								break
							}
							msg.WriteString(l)
						}
						r.mails <- msg.String()
						reply("250 queued")
					case "QUIT":
						reply("221 bye")
						return
					default:
						reply("250 ok")
					}
				}
			}()
		}
	}()
	return r
}

// P15-L4 part 2: a mailbox whose local part has non-ASCII characters is
// ordered, proven and certified end to end. The challenge mail goes through
// a relay that offers SMTPUTF8, with the SMTPUTF8 parameter; the reply comes
// through the intake with SMTPUTF8 and a UTF-8 From field (RFC 6532) and
// validates the challenge; the certificate names the mailbox as an
// SmtpUTF8Mailbox otherName (RFC 9598), not an rfc822Name.
func TestServedEmailOrderForAnInternationalMailboxP15L4(t *testing.T) {
	const mailbox = "ålice@p15l4.test"
	relay := startP15L4UTF8Relay(t)
	dkimKey, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dkimKey.Destroy)
	h := newOperatingServedHarness(t, config.Protocols{
		ACME: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
		ACMEEmail: config.ACMEEmail{From: "acme@ca.p15l4.test", Domains: []string{"p15l4.test"},
			Profile: "smime-signing", RelayAddr: relay.addr, SMTPListen: "127.0.0.1:0",
			DKIMKeys: map[string]string{"lab._domainkey.p15l4.test": "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(dkimKey.Public().DER)}},
	})
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	spec, err := json.Marshal(map[string]any{"name": "smime-signing", "max_validity": "2160h", "allowed_ekus": []string{"emailProtection"},
		"allowed_email_domains": []string{"p15l4.test"}, "allowed_protocols": []string{"acme"}})
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
	order, err := client.AuthorizeOrder(ctx, []xacme.AuthzID{{Type: "email", Value: mailbox}})
	if err != nil {
		t.Fatal(err)
	}
	authz, err := client.GetAuthorization(ctx, order.AuthzURLs[0])
	if err != nil || authz.Identifier.Value != mailbox {
		t.Fatalf("authorization = %+v %v", authz, err)
	}
	var mail string
	select {
	case mail = <-relay.mails:
	case <-ctx.Done():
		t.Fatal("no challenge mail reached the relay")
	}
	token := ""
	for _, line := range strings.Split(strings.SplitN(mail, "\r\n\r\n", 2)[0], "\r\n") {
		if v, ok := strings.CutPrefix(line, "Subject: ACME: "); ok {
			token = v
		}
	}
	relay.mu.Lock()
	mailCommands := strings.Join(relay.mail, "\n")
	relay.mu.Unlock()
	if !strings.Contains(mail, "To: "+mailbox+"\r\n") || token == "" || !strings.Contains(mailCommands, "SMTPUTF8") {
		t.Fatalf("the challenge mail (MAIL %q) = %.200q", mailCommands, mail)
	}

	digest, err := crypto.Digest(crypto.SHA256, []byte(token+authz.Challenges[0].Token+"."+thumbprint))
	if err != nil {
		t.Fatal(err)
	}
	reply := []byte("From: " + mailbox + "\r\nTo: acme@ca.p15l4.test\r\nSubject: Re: ACME: " + token + "\r\n" +
		"Date: Sat, 14 Nov 2026 12:00:00 +0000\r\nMessage-ID: <r" + token[:6] + "@p15l4.test>\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n\r\nYes.\r\n\r\n-----BEGIN ACME RESPONSE-----\r\n" +
		base64.RawURLEncoding.EncodeToString(digest) + "\r\n-----END ACME RESPONSE-----\r\n")
	signed, err := dkim.Sign(reply, "p15l4.test", "lab", []string{"From", "To", "Subject", "Date", "Message-ID", "Content-Type"}, dkimKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	c, err := smtp.Dial(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err := c.Hello("mta.p15l4.test"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := c.Extension("SMTPUTF8"); !ok {
		t.Fatal("the intake does not offer SMTPUTF8")
	}
	if err := c.Mail(mailbox); err != nil {
		t.Fatal(err)
	}
	if err := c.Rcpt("acme@ca.p15l4.test"); err != nil {
		t.Fatal(err)
	}
	wc, err := c.Data()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wc.Write(signed); err != nil {
		t.Fatal(err)
	}
	if err := wc.Close(); err != nil {
		t.Fatalf("the intake refused the reply: %v", err)
	}
	_ = c.Quit()
	if _, err := client.Accept(ctx, authz.Challenges[0]); err != nil {
		t.Fatal(err)
	}
	if valid, err := client.WaitAuthorization(ctx, authz.URI); err != nil || valid.Status != xacme.StatusValid {
		t.Fatalf("the authorization = %+v %v", valid, err)
	}

	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	ku, err := crypto.KeyUsageRequestExtension(true, false, false)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{SmtpUTF8Mailboxes: []string{mailbox},
		ExtraExtensions: []crypto.CertificateExtension{ku}}, key)
	if err != nil {
		t.Fatal(err)
	}
	chain, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil || len(chain) == 0 {
		t.Fatalf("finalize: %v", err)
	}
	leaf, err := certinfo.Inspect(chain[0])
	if err != nil || len(leaf.EmailAddresses) != 0 || len(leaf.SmtpUTF8Mailboxes) != 1 || leaf.SmtpUTF8Mailboxes[0] != mailbox {
		t.Fatalf("the certificate names rfc822 %v and SmtpUTF8Mailbox %v (%v)", leaf.EmailAddresses, leaf.SmtpUTF8Mailboxes, err)
	}
	t.Logf("P15L4_PART2_OK mailbox=%s", mailbox)
}
