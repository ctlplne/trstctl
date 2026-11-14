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
	"trstctl.com/trstctl/internal/dkim"
	"trstctl.com/trstctl/internal/events"
)

// P15-L6: with require_spf, the reply intake checks SPF for each reply's
// envelope sender and the address that delivered it. A correctly signed
// reply sent under an envelope sender whose SPF record refuses this host is
// refused 550 5.7.23 and recorded as an spf refusal; the same reply under a
// sender whose record admits it validates the challenge. The reply's DKIM
// signature, aligned with its From domain, is what DMARC asks of it.
func TestServedReplyIntakeChecksSPFWhenRequiredP15L6(t *testing.T) {
	relay := startP15SMTPRelay(t)
	dkimKey, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dkimKey.Destroy)
	h := newOperatingServedHarness(t, config.Protocols{
		ACME: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
		ACMEEmail: config.ACMEEmail{From: "acme@ca.p15l6.test", Domains: []string{"p15l6.test"},
			Profile: "smime-signing", RelayAddr: relay.addr, SMTPListen: "127.0.0.1:0", RequireSPF: true,
			DKIMKeys: map[string]string{"lab._domainkey.p15l6.test": "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(dkimKey.Public().DER)},
			SPFRecords: map[string]string{
				"p15l6.test":         "v=spf1 ip4:127.0.0.1 -all",
				"spoofed.p15l6.test": "v=spf1 ip4:192.0.2.0/24 -all",
			}},
	})
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	spec, err := json.Marshal(map[string]any{"name": "smime-signing", "max_validity": "2160h", "allowed_ekus": []string{"emailProtection"},
		"allowed_email_domains": []string{"p15l6.test"}, "allowed_protocols": []string{"acme"}})
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
	order, err := client.AuthorizeOrder(ctx, []xacme.AuthzID{{Type: "email", Value: "alice@p15l6.test"}})
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
	token := ""
	for _, line := range strings.Split(strings.SplitN(mail, "\r\n\r\n", 2)[0], "\r\n") {
		if v, ok := strings.CutPrefix(line, "Subject: ACME: "); ok {
			token = v
		}
	}
	digest, err := crypto.Digest(crypto.SHA256, []byte(token+authz.Challenges[0].Token+"."+thumbprint))
	if err != nil || token == "" {
		t.Fatalf("the challenge token: %q %v", token, err)
	}
	reply := []byte("From: alice@p15l6.test\r\nTo: acme@ca.p15l6.test\r\nSubject: Re: ACME: " + token + "\r\n" +
		"Date: Sat, 14 Nov 2026 12:00:00 +0000\r\nMessage-ID: <r" + token[:6] + "@p15l6.test>\r\n" +
		"Content-Type: text/plain; charset=US-ASCII\r\n\r\nYes.\r\n\r\n-----BEGIN ACME RESPONSE-----\r\n" +
		base64.RawURLEncoding.EncodeToString(digest) + "\r\n-----END ACME RESPONSE-----\r\n")
	signed, err := dkim.Sign(reply, "p15l6.test", "lab", []string{"From", "To", "Subject", "Date", "Message-ID", "Content-Type"}, dkimKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	send := func(mailFrom string) string {
		t.Helper()
		c, err := smtp.Dial(ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		if err := c.Hello("mta.p15l6.test"); err != nil {
			t.Fatal(err)
		}
		if err := c.Mail(mailFrom); err != nil {
			t.Fatal(err)
		}
		if err := c.Rcpt("acme@ca.p15l6.test"); err != nil {
			return strings.ReplaceAll(err.Error(), `"`, "")
		}
		wc, err := c.Data()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := wc.Write(signed); err != nil {
			t.Fatal(err)
		}
		if err := wc.Close(); err != nil {
			return strings.ReplaceAll(err.Error(), `"`, "")
		}
		_ = c.Quit()
		return "250"
	}
	if got := send("bounce@spoofed.p15l6.test"); !strings.HasPrefix(got, "550 5.7.23") {
		t.Fatalf("a reply whose envelope sender's SPF refuses this host = %q", got)
	}
	refused := 0
	if err := h.log.Replay(t.Context(), 0, func(e events.Event) error {
		if e.TenantID == h.tenant && e.Type == "acme.email_reply.refused" && strings.Contains(string(e.Data), `"outcome":"spf"`) {
			refused++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if refused != 1 {
		t.Fatalf("spf refusals recorded = %d, want 1", refused)
	}
	if got := send("alice@p15l6.test"); got != "250" {
		t.Fatalf("the reply under a sender whose SPF admits this host = %q", got)
	}
	if _, err := client.Accept(ctx, authz.Challenges[0]); err != nil {
		t.Fatal(err)
	}
	if valid, err := client.WaitAuthorization(ctx, authz.URI); err != nil || valid.Status != xacme.StatusValid {
		t.Fatalf("the authorization = %+v %v", valid, err)
	}
	t.Logf("P15L6_SPF_OK refused=5.7.23 accepted=pass")
}
