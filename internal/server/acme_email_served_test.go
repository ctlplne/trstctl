// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
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
	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
)

// p15SMTPRelay is a loopback SMTP relay that keeps every message it accepts.
type p15SMTPRelay struct {
	addr  string
	mails chan string
}

func startP15SMTPRelay(t *testing.T) *p15SMTPRelay {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	r := &p15SMTPRelay{addr: ln.Addr().String(), mails: make(chan string, 8)}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go r.serve(conn)
		}
	}()
	return r
}

func (r *p15SMTPRelay) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	rd := bufio.NewReader(conn)
	reply := func(line string) { _, _ = conn.Write([]byte(line + "\r\n")) }
	reply("220 relay.p15.test ESMTP")
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			return
		}
		switch strings.ToUpper(strings.TrimSpace(line)) {
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
			reply("250 relay.p15.test")
		}
	}
}

// p15ChallengeFrom records the "from" each email-reply-00 challenge names.
type p15ChallengeFrom struct {
	mu   sync.Mutex
	from map[string]string
}

func (c *p15ChallengeFrom) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil || resp.Body == nil {
		return resp, err
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	var doc struct {
		Challenges []struct {
			Type string `json:"type"`
			URL  string `json:"url"`
			From string `json:"from"`
		} `json:"challenges"`
	}
	if json.Unmarshal(body, &doc) == nil {
		c.mu.Lock()
		for _, ch := range doc.Challenges {
			if ch.Type == acmesrv.ChallengeEmailReply00 {
				c.from[ch.URL] = ch.From
			}
		}
		c.mu.Unlock()
	}
	return resp, nil
}

// P15 (server half): an RFC 8823 S/MIME order against the served ACME server.
// The challenge object carries token-part2 and the from address; the challenge
// mail leaves through the SMTP relay with token-part1 and RFC 8823's headers; a
// reply from the wrong mailbox or with the wrong token validates nothing; the
// right reply validates the challenge (the client POSTed first, so it was
// processing); finalize refuses a CSR that asks for encryption and issues a
// signing-only certificate whose only identity is the mailbox, with the
// emailProtection EKU. The reply goes to the ACME server's intake directly here;
// the SMTP intake that verifies DKIM is the next commit.
func TestServedACMEEmailChallengeIssuesSigningOnlySMIMEP15(t *testing.T) {
	relay := startP15SMTPRelay(t)
	h := newOperatingServedHarness(t, config.Protocols{
		ACME: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
		ACMEEmail: config.ACMEEmail{From: "acme@ca.p15.test", Domains: []string{"p15.test"},
			Profile: "smime-signing", RelayAddr: relay.addr},
	})
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	spec, err := json.Marshal(map[string]any{"name": "smime-signing", "max_validity": "2160h",
		"allowed_ekus": []string{"emailProtection"}, "allowed_email_domains": []string{"p15.test"}, "allowed_protocols": []string{"acme"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.orch.CreateProfile(ctx, h.tenant, "smime-signing", spec); err != nil {
		t.Fatal(err)
	}
	startServedDirectOutboxPump(t, h.srv)
	client, err := acmekey.NewClient(h.ts.URL + "/directory")
	if err != nil {
		t.Fatal(err)
	}
	seen := &p15ChallengeFrom{from: map[string]string{}}
	client.HTTPClient = &http.Client{Transport: seen, Timeout: 30 * time.Second}
	if _, err := client.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
		t.Fatal(err)
	}
	thumbprint, err := xacme.JWKThumbprint(client.Key.Public())
	if err != nil {
		t.Fatal(err)
	}

	if _, err := client.AuthorizeOrder(ctx, []xacme.AuthzID{{Type: "email", Value: "alice@other.test"}}); err == nil {
		t.Fatal("an address outside the configured mail domains was ordered")
	}
	if _, err := client.AuthorizeOrder(ctx, []xacme.AuthzID{{Type: "email", Value: "alice@p15.test"}, {Type: "dns", Value: "p15.test"}}); err == nil {
		t.Fatal("an order mixing email and dns identifiers was accepted")
	}
	order, err := client.AuthorizeOrder(ctx, []xacme.AuthzID{{Type: "email", Value: "alice@p15.test"}})
	if err != nil {
		t.Fatal(err)
	}
	authz, err := client.GetAuthorization(ctx, order.AuthzURLs[0])
	if err != nil {
		t.Fatal(err)
	}
	if authz.Identifier.Type != "email" || authz.Identifier.Value != "alice@p15.test" || len(authz.Challenges) != 1 ||
		authz.Challenges[0].Type != acmesrv.ChallengeEmailReply00 {
		t.Fatalf("authorization = %+v", authz)
	}
	chal := authz.Challenges[0]
	if seen.from[chal.URI] != "acme@ca.p15.test" {
		t.Fatalf("the challenge names from %q", seen.from[chal.URI])
	}

	// The challenge mail, sent through the relay by the outbox worker.
	var mail string
	select {
	case mail = <-relay.mails:
	case <-ctx.Done():
		t.Fatal("no challenge mail reached the relay")
	}
	headers := map[string]string{}
	for _, line := range strings.Split(strings.SplitN(mail, "\r\n\r\n", 2)[0], "\r\n") {
		if name, value, ok := strings.Cut(line, ": "); ok {
			headers[name] = value
		}
	}
	tokenPart1, ok := strings.CutPrefix(headers["Subject"], "ACME: ")
	if !ok || headers["From"] != "acme@ca.p15.test" || headers["To"] != "alice@p15.test" ||
		headers["Auto-Submitted"] != "auto-generated; type=acme" || headers["Message-ID"] == "" {
		t.Fatalf("challenge mail headers = %v", headers)
	}
	digest, err := crypto.Digest(crypto.SHA256, []byte(tokenPart1+chal.Token+"."+thumbprint))
	if err != nil {
		t.Fatal(err)
	}
	response := base64.RawURLEncoding.EncodeToString(digest)

	acme := h.srv.protocols.acme
	for name, reply := range map[string]acmesrv.EmailReply{
		"another mailbox":      {From: "bob@p15.test", SubjectToken: tokenPart1, Response: response},
		"another token-part 1": {From: "alice@p15.test", SubjectToken: tokenPart1[1:], Response: response},
	} {
		if _, err := acme.AcceptEmailReply(ctx, reply); !errors.Is(err, acmesrv.ErrEmailReplyUnmatched) {
			t.Fatalf("a reply from %s: %v", name, err)
		}
	}
	// The client says it has replied before the reply arrives: processing.
	accepted, err := client.Accept(ctx, chal)
	if err != nil || accepted.Status != "processing" {
		t.Fatalf("accept = %+v %v", accepted, err)
	}
	if _, err := acme.AcceptEmailReply(ctx, acmesrv.EmailReply{From: "alice@p15.test", SubjectToken: tokenPart1, Response: response}); err != nil {
		t.Fatalf("the right reply: %v", err)
	}
	if valid, err := client.WaitAuthorization(ctx, authz.URI); err != nil || valid.Status != xacme.StatusValid {
		t.Fatalf("authorization after the reply = %+v %v", valid, err)
	}

	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csrFor := func(ds, ke bool) []byte {
		t.Helper()
		ku, err := crypto.KeyUsageRequestExtension(ds, false, ke)
		if err != nil {
			t.Fatal(err)
		}
		der, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
			EmailAddresses: []string{"alice@p15.test"}, ExtraExtensions: []crypto.CertificateExtension{ku}}, key)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	if _, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csrFor(true, true), true); err == nil || !strings.Contains(err.Error(), "signing-only") {
		t.Fatalf("a CSR asking for encryption: %v", err)
	}
	chain, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csrFor(true, false), true)
	if err != nil || len(chain) == 0 {
		t.Fatalf("finalize: %v", err)
	}
	leaf, err := certinfo.Inspect(chain[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(leaf.EmailAddresses, ",") != "alice@p15.test" || len(leaf.DNSNames) != 0 ||
		strings.Join(leaf.ExtKeyUsages, ",") != "emailProtection" || !leaf.KeyUsageDigitalSig || leaf.KeyUsageEncipher || leaf.KeyUsageCertSign {
		t.Fatalf("issued certificate: emails %v dns %v eku %v digitalSignature %v keyEncipherment %v",
			leaf.EmailAddresses, leaf.DNSNames, leaf.ExtKeyUsages, leaf.KeyUsageDigitalSig, leaf.KeyUsageEncipher)
	}
	t.Logf("P15A_OK leaf_emails=%v eku=%v digitalSignature=%v", leaf.EmailAddresses, leaf.ExtKeyUsages, leaf.KeyUsageDigitalSig)
}

// P15 part b: replies reach the ACME server over SMTP through the intake,
// which verifies each one's DKIM signature for its From domain before the
// ACME server matches it. An unsigned reply, one signed with an unknown key, a
// mailing-list message, a reply from another mailbox or with another token,
// and mail for another recipient are refused with their reason; the signed
// reply from the right mailbox validates the challenge and the order issues.
func TestServedACMEEmailReplyIntakeVerifiesDKIMP15(t *testing.T) {
	relay := startP15SMTPRelay(t)
	dkimKey, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dkimKey.Destroy)
	h := newOperatingServedHarness(t, config.Protocols{
		ACME: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
		ACMEEmail: config.ACMEEmail{From: "acme@ca.p15.test", Domains: []string{"p15.test"},
			Profile: "smime-signing", RelayAddr: relay.addr, SMTPListen: "127.0.0.1:0",
			DKIMKeys: map[string]string{
				"lab._domainkey.p15.test":   "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(dkimKey.Public().DER),
				"lab._domainkey.other.test": "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(dkimKey.Public().DER),
			}},
	})
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	spec, err := json.Marshal(map[string]any{"name": "smime-signing", "max_validity": "2160h",
		"allowed_ekus": []string{"emailProtection"}, "allowed_email_domains": []string{"p15.test"}, "allowed_protocols": []string{"acme"}})
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
	order, err := client.AuthorizeOrder(ctx, []xacme.AuthzID{{Type: "email", Value: "alice@p15.test"}})
	if err != nil {
		t.Fatal(err)
	}
	authz, err := client.GetAuthorization(ctx, order.AuthzURLs[0])
	if err != nil {
		t.Fatal(err)
	}
	var mail string
	select {
	case mail = <-relay.mails:
	case <-ctx.Done():
		t.Fatal("no challenge mail reached the relay")
	}
	tokenPart1 := ""
	messageID := ""
	for _, line := range strings.Split(strings.SplitN(mail, "\r\n\r\n", 2)[0], "\r\n") {
		if v, ok := strings.CutPrefix(line, "Subject: ACME: "); ok {
			tokenPart1 = v
		}
		if v, ok := strings.CutPrefix(line, "Message-ID: "); ok {
			messageID = v
		}
	}
	digest, err := crypto.Digest(crypto.SHA256, []byte(tokenPart1+authz.Challenges[0].Token+"."+thumbprint))
	if err != nil {
		t.Fatal(err)
	}
	response := base64.RawURLEncoding.EncodeToString(digest)
	reply := func(from, token string, extra string) []byte {
		return []byte("From: " + from + "\r\nTo: acme@ca.p15.test\r\nSubject: Re: ACME: " + token + "\r\n" +
			"Date: Sun, 01 Nov 2026 12:00:00 +0000\r\nMessage-ID: <r" + token[:6] + "@p15.test>\r\nIn-Reply-To: " + messageID + "\r\n" +
			extra + "Content-Type: text/plain; charset=US-ASCII\r\n\r\nYes.\r\n\r\n-----BEGIN ACME RESPONSE-----\r\n" + response + "\r\n-----END ACME RESPONSE-----\r\n")
	}
	signAs := func(msg []byte, domain, selector string) []byte {
		t.Helper()
		signed, err := dkim.Sign(msg, domain, selector, []string{"From", "To", "Subject", "Date", "Message-ID", "In-Reply-To", "Content-Type"}, dkimKey, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	sign := func(msg []byte, selector string) []byte { return signAs(msg, "p15.test", selector) }
	send := func(rcpt string, msg []byte) string {
		t.Helper()
		c, err := smtp.Dial(ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		if err := c.Hello("mta.p15.test"); err != nil {
			t.Fatal(err)
		}
		if err := c.Mail("alice@p15.test"); err != nil {
			t.Fatal(err)
		}
		if err := c.Rcpt(rcpt); err != nil {
			return strings.ReplaceAll(err.Error(), `"`, "")
		}
		wc, err := c.Data()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := wc.Write(msg); err != nil {
			t.Fatal(err)
		}
		if err := wc.Close(); err != nil {
			return strings.ReplaceAll(err.Error(), `"`, "")
		}
		_ = c.Quit()
		return "250"
	}
	for name, tc := range map[string]struct {
		rcpt string
		msg  []byte
		want string
	}{
		"another recipient":      {"postmaster@ca.p15.test", sign(reply("alice@p15.test", tokenPart1, ""), "lab"), "550 5.1.1"},
		"an unsigned reply":      {"acme@ca.p15.test", reply("alice@p15.test", tokenPart1, ""), "550 5.7.20"},
		"an unknown key":         {"acme@ca.p15.test", sign(reply("alice@p15.test", tokenPart1, ""), "other"), "550 5.7.20"},
		"another signing domain": {"acme@ca.p15.test", signAs(reply("alice@p15.test", tokenPart1, ""), "other.test", "lab"), "550 5.7.20"},
		"a mailing list":         {"acme@ca.p15.test", sign(reply("alice@p15.test", tokenPart1, "List-Id: <team.p15.test>\r\n"), "lab"), "550 5.6.0"},
		"another mailbox":        {"acme@ca.p15.test", sign(reply("bob@p15.test", tokenPart1, ""), "lab"), "550 5.7.1 no pending"},
		"another token-part 1":   {"acme@ca.p15.test", sign(reply("alice@p15.test", "x"+tokenPart1, ""), "lab"), "550 5.7.1 no pending"},
	} {
		if got := send(tc.rcpt, tc.msg); !strings.HasPrefix(got, tc.want) {
			t.Fatalf("%s: SMTP answered %q, want %s", name, got, tc.want)
		}
	}
	if got := send("acme@ca.p15.test", sign(reply("alice@p15.test", tokenPart1, ""), "lab")); got != "250" {
		t.Fatalf("the signed reply: %s", got)
	}
	if valid, err := client.WaitAuthorization(ctx, authz.URI); err != nil || valid.Status != xacme.StatusValid {
		t.Fatalf("authorization after the reply = %+v %v", valid, err)
	}
	ku, err := crypto.KeyUsageRequestExtension(true, false, false)
	if err != nil {
		t.Fatal(err)
	}
	// Stock S/MIME clients name the mailbox as the common name too; it is never a DNS name.
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "alice@p15.test",
		EmailAddresses: []string{"alice@p15.test"}, ExtraExtensions: []crypto.CertificateExtension{ku}}, dkimKey)
	if err != nil {
		t.Fatal(err)
	}
	chain, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil || len(chain) == 0 {
		t.Fatalf("finalize: %v", err)
	}
	leaf, err := certinfo.Inspect(chain[0])
	if err != nil || strings.Join(leaf.EmailAddresses, ",") != "alice@p15.test" || strings.Join(leaf.ExtKeyUsages, ",") != "emailProtection" {
		t.Fatalf("issued certificate %+v %v", leaf, err)
	}
	t.Logf("P15B_OK intake=%s leaf=%v", ln.Addr(), leaf.EmailAddresses)
}
