// SPDX-License-Identifier: BUSL-1.1

package acme

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

type capturedChallengeMail struct{ mails []EmailChallengeMail }

func (c *capturedChallengeMail) QueueChallengeMail(_ context.Context, mail EmailChallengeMail) error {
	c.mails = append(c.mails, mail)
	return nil
}

func TestNormalizeEmailIdentifierP15(t *testing.T) {
	for raw, want := range map[string]string{
		"alice@example.com":       "alice@example.com",
		"Alice.B+tag@Example.COM": "Alice.B+tag@example.com",
		"o'neil@mail.example.org": "o'neil@mail.example.org",
		// P15-L4: a quoted local part is accepted, unquoted when it is a
		// dot-atom, and a non-ASCII local part is kept exactly.
		"\"q\"@example.com": "q@example.com",
		"álice@example.com": "álice@example.com",
	} {
		if got, err := NormalizeEmailIdentifier(raw); err != nil || got != want {
			t.Fatalf("NormalizeEmailIdentifier(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
	for _, raw := range []string{"", "alice", "@example.com", "alice@", "*@example.com", "a*b@example.com",
		"a..b@example.com", ".a@example.com", "a@localhost", "a@exa_mple.com",
		"a@-bad.example.com", strings.Repeat("a", 65) + "@example.com"} {
		if got, err := NormalizeEmailIdentifier(raw); err == nil {
			t.Fatalf("NormalizeEmailIdentifier(%q) accepted %q", raw, got)
		}
	}
}

func TestEmailResponseDigestAndExtractionP15(t *testing.T) {
	// base64url(SHA-256("tp1" || "tp2" "." "thumb")), unpadded.
	if got := emailExpectedResponse("tp1", "tp2", "thumb"); got != "rynD6QGlltZhNIRS96cbWcLyzZlut_RdklODCHrA7U8" {
		t.Fatalf("expected response = %q", got)
	}
	body := "Thanks!\r\n\r\n-----BEGIN ACME RESPONSE-----\r\nrynD6QGlltZhNIRS96cbWcLyzZ\r\nlut_RdklODCHrA7U8=\r\n-----END ACME RESPONSE-----\r\n-- \r\nsig\r\n"
	if got, ok := ExtractEmailResponse(body); !ok || got != "rynD6QGlltZhNIRS96cbWcLyzZlut_RdklODCHrA7U8" {
		t.Fatalf("ExtractEmailResponse = %q, %v", got, ok)
	}
	for _, bad := range []string{"no block", "-----BEGIN ACME RESPONSE-----\r\nabc", "-----BEGIN ACME RESPONSE-----\r\n\r\n-----END ACME RESPONSE-----"} {
		if got, ok := ExtractEmailResponse(bad); ok {
			t.Fatalf("ExtractEmailResponse(%q) = %q", bad, got)
		}
	}
}

func TestEmailChallengeMailCarriesRFC8823HeadersP15(t *testing.T) {
	mail := EmailChallengeMail{MessageID: "<m1@ca.example>", From: "acme@ca.example", To: "alice@example.com",
		Subject: "ACME: tokenpart1", Date: time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)}
	got := string(mail.RFC5322())
	for _, want := range []string{"From: acme@ca.example\r\n", "To: alice@example.com\r\n", "Subject: ACME: tokenpart1\r\n",
		"Message-ID: <m1@ca.example>\r\n", "Auto-Submitted: auto-generated; type=acme\r\n",
		"Content-Type: text/plain; charset=US-ASCII\r\n", "Content-Transfer-Encoding: 7bit\r\n", "\r\n\r\n"} {
		if !strings.Contains(got, want) {
			t.Fatalf("challenge mail lacks %q:\n%s", want, got)
		}
	}
}

func p15CSR(t *testing.T, tmpl crypto.CertificateRequestTemplate) []byte {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	der, err := crypto.CreateCertificateRequest(tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func p15KU(t *testing.T, ds, nr, ke bool) []crypto.CertificateExtension {
	t.Helper()
	ext, err := crypto.KeyUsageRequestExtension(ds, nr, ke)
	if err != nil {
		t.Fatal(err)
	}
	return []crypto.CertificateExtension{ext}
}

// RFC 8823 §3 step 8 and §3.3: the CSR names exactly the order's addresses,
// nothing else, and asks for a signing-only key usage.
func TestCSREmailIdentifiersMatchOrderP15(t *testing.T) {
	order := []string{"alice@example.com"}
	ok := []crypto.CertificateRequestTemplate{
		{EmailAddresses: []string{"alice@EXAMPLE.com"}, ExtraExtensions: p15KU(t, true, false, false)},
		{CommonName: "alice@example.com", EmailAddresses: []string{"alice@example.com"}, ExtraExtensions: p15KU(t, true, true, false)},
		{EmailAddresses: []string{"alice@example.com"}, ExtraExtensions: p15KU(t, false, true, false)},
	}
	for i, tmpl := range ok {
		if err := csrEmailIdentifiersMatchOrder(p15CSR(t, tmpl), order); err != nil {
			t.Fatalf("case %d refused: %v", i, err)
		}
	}
	for name, tmpl := range map[string]crypto.CertificateRequestTemplate{
		"encryption bit":   {EmailAddresses: []string{"alice@example.com"}, ExtraExtensions: p15KU(t, true, false, true)},
		"no key usage":     {EmailAddresses: []string{"alice@example.com"}},
		"another address":  {EmailAddresses: []string{"alice@example.com", "bob@example.com"}, ExtraExtensions: p15KU(t, true, false, false)},
		"missing address":  {EmailAddresses: []string{"bob@example.com"}, ExtraExtensions: p15KU(t, true, false, false)},
		"a dns name":       {EmailAddresses: []string{"alice@example.com"}, DNSNames: []string{"example.com"}, ExtraExtensions: p15KU(t, true, false, false)},
		"a personal name":  {CommonName: "Alice Example", EmailAddresses: []string{"alice@example.com"}, ExtraExtensions: p15KU(t, true, false, false)},
		"wrong local case": {EmailAddresses: []string{"Alice@example.com"}, ExtraExtensions: p15KU(t, true, false, false)},
	} {
		if err := csrEmailIdentifiersMatchOrder(p15CSR(t, tmpl), order); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

func p15EmailServer(t *testing.T) (*Server, *capturedChallengeMail) {
	t.Helper()
	mailer := &capturedChallengeMail{}
	s := New(nil, AcceptAll{}).WithEmailChallenges("acme@ca.example", []string{"example.com"}, "smime-signing", mailer)
	if s.email == nil {
		t.Fatal("email challenges were not offered")
	}
	return s, mailer
}

func p15EmailOrder(s *Server, id, address string) (*order, *authorization, *challenge, EmailChallengeMail) {
	o := &order{id: "o" + id, accountURL: "https://acme.test/acct/1", status: statusPending, identType: IdentifierEmail, domains: []string{address}}
	az := &authorization{id: "a" + id, orderID: o.id, domain: address, identType: IdentifierEmail, status: statusPending}
	ch := &challenge{id: "c" + id, typ: ChallengeEmailReply00, token: randomToken(), status: statusPending, authzID: az.id}
	mail := s.newEmailChallenge(ch, address, "thumb", time.Now())
	az.challenges = []*challenge{ch}
	o.authzIDs = []string{az.id}
	s.orders[o.id], s.authzs[az.id], s.challenges[ch.id] = o, az, ch
	return o, az, ch, mail
}

// A reply from the wrong mailbox or with the wrong token-part1 matches
// nothing; a wrong response from the right mailbox spends the one guess; the
// right reply validates the challenge and readies the order.
func TestAcceptEmailReplyP15(t *testing.T) {
	s, _ := p15EmailServer(t)
	_, az, ch, mail := p15EmailOrder(s, "1", "alice@example.com")
	tp1 := strings.TrimPrefix(mail.Subject, "ACME: ")
	if strings.Contains(ch.emailTokenPart1SHA256, tp1) || ch.emailTokenPart1SHA256 == "" || ch.emailResponseSHA256 == "" {
		t.Fatalf("challenge state = %+v", ch)
	}
	right := emailExpectedResponse(tp1, ch.token, "thumb")
	ctx := context.Background()
	if _, err := s.AcceptEmailReply(ctx, EmailReply{From: "bob@example.com", SubjectToken: tp1, Response: right}); !errors.Is(err, ErrEmailReplyUnmatched) {
		t.Fatalf("a reply from another mailbox: %v", err)
	}
	if _, err := s.AcceptEmailReply(ctx, EmailReply{From: "alice@example.com", SubjectToken: tp1 + "x", Response: right}); !errors.Is(err, ErrEmailReplyUnmatched) {
		t.Fatalf("a reply with another token-part1: %v", err)
	}
	if ch.status != statusPending {
		t.Fatalf("unmatched replies changed the challenge: %s", ch.status)
	}
	if _, err := s.AcceptEmailReply(ctx, EmailReply{From: "alice@example.com", SubjectToken: tp1, Response: right[1:]}); !errors.Is(err, ErrEmailReplyWrongResponse) {
		t.Fatalf("a wrong response: %v", err)
	}
	if ch.status != statusInvalid || az.status != statusInvalid {
		t.Fatalf("after a wrong response: challenge %s authz %s", ch.status, az.status)
	}
	if _, err := s.AcceptEmailReply(ctx, EmailReply{From: "alice@example.com", SubjectToken: tp1, Response: right}); !errors.Is(err, ErrEmailReplyUnmatched) {
		t.Fatalf("a second try after the one guess: %v", err)
	}

	o2, az2, ch2, mail2 := p15EmailOrder(s, "2", "alice@example.com")
	ch2.status = statusProcessing // the client already POSTed the challenge
	tp1 = strings.TrimPrefix(mail2.Subject, "ACME: ")
	padded := emailExpectedResponse(tp1, ch2.token, "thumb") + "="
	// The local part is exact (RFC 5321): "Alice" is another mailbox.
	if _, err := s.AcceptEmailReply(ctx, EmailReply{From: "Alice@example.com", SubjectToken: tp1, Response: padded}); !errors.Is(err, ErrEmailReplyUnmatched) {
		t.Fatalf("a reply from a differently cased local part: %v", err)
	}
	if id, err := s.AcceptEmailReply(ctx, EmailReply{From: "alice@EXAMPLE.com", SubjectToken: " " + tp1 + "\r\n", Response: padded}); err != nil || id != ch2.id {
		t.Fatalf("the right reply: %q %v", id, err)
	}
	if ch2.status != statusValid || az2.status != statusValid || o2.status != statusReady {
		t.Fatalf("after the right reply: challenge %s authz %s order %s", ch2.status, az2.status, o2.status)
	}
}
