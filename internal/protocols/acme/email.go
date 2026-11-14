// SPDX-License-Identifier: BUSL-1.1

package acme

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/idna"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
)

// ACME for S/MIME (RFC 8823, P15). An "email" identifier proves control of a
// mailbox with the email-reply-00 challenge. The challenge object carries
// token-part2 and the address the challenge mail comes from; the server mails
// token-part1 to the address (Subject "ACME: <token-part1>"); the client's
// DKIM-signed reply carries base64url(SHA-256(token-part1 || token-part2 "."
// account-key thumbprint)). Only SHA-256 digests of token-part1 and of the
// expected response are kept in state, never the values. A wrong response
// from the right mailbox invalidates the challenge: the RFC allows one guess.
// Certificates are signing-only; a CSR that asks for encryption is refused,
// because key escrow is not offered.

const (
	// IdentifierDNS is the RFC 8555 dns identifier type.
	IdentifierDNS = "dns"
	// IdentifierEmail is the RFC 8823 email identifier type.
	IdentifierEmail = "email"
	// ChallengeEmailReply00 is RFC 8823's email-reply-00 challenge.
	ChallengeEmailReply00 = "email-reply-00"
)

// emailResponseBegin and emailResponseEnd delimit the response in a reply body.
const (
	emailResponseBegin = "-----BEGIN ACME RESPONSE-----"
	emailResponseEnd   = "-----END ACME RESPONSE-----"
)

// EmailChallengeMail is one challenge mail (RFC 8823 §3.1). It carries
// token-part1 in its Subject, so it is handed only to the mailer.
type EmailChallengeMail struct {
	TenantID    string
	ChallengeID string
	MessageID   string
	From        string
	To          string
	Subject     string
	Date        time.Time
}

// RFC5322 renders the mail: 7-bit US-ASCII text with the headers RFC 8823
// requires (Auto-Submitted: auto-generated; type=acme). It must be
// DKIM-signed for the From domain (RFC 8823 §3.1 item 6): by trstctl when a
// signing key is configured (P15-L2), otherwise by the relay that sends it.
func (m EmailChallengeMail) RFC5322() []byte {
	var b bytes.Buffer
	for _, h := range [][2]string{
		{"From", m.From}, {"To", m.To}, {"Subject", m.Subject},
		{"Date", m.Date.UTC().Format(time.RFC1123Z)}, {"Message-ID", m.MessageID},
		{"Auto-Submitted", "auto-generated; type=acme"}, {"MIME-Version", "1.0"},
		{"Content-Type", "text/plain; charset=US-ASCII"}, {"Content-Transfer-Encoding", "7bit"},
	} {
		b.WriteString(h[0] + ": " + h[1] + "\r\n")
	}
	b.WriteString("\r\n")
	b.WriteString("This message asks you to confirm that you control this mailbox, so that a\r\n")
	b.WriteString("certificate authority can issue an S/MIME certificate for it (RFC 8823).\r\n")
	b.WriteString("If you did not request a certificate, ignore this message.\r\n")
	return b.Bytes()
}

// EmailChallengeMailer queues a challenge mail for delivery. The served
// implementation puts it on the outbox (AN-6).
type EmailChallengeMailer interface {
	QueueChallengeMail(ctx context.Context, mail EmailChallengeMail) error
}

type emailChallengeConfig struct {
	from    string
	domains map[string]bool
	profile string
	mailer  EmailChallengeMailer
}

// WithEmailChallenges offers email identifiers and email-reply-00 for
// addresses in domains: challenge mails come from from and go out through
// mailer, and certificates are issued under the named profile. Without a
// from address, a domain or a mailer the offer stays off.
func (s *Server) WithEmailChallenges(from string, domains []string, profileName string, mailer EmailChallengeMailer) *Server {
	s.email = nil
	normalized, err := NormalizeEmailIdentifier(from)
	if err != nil || mailer == nil || strings.TrimSpace(profileName) == "" {
		return s
	}
	cfg := &emailChallengeConfig{from: normalized, domains: map[string]bool{}, profile: strings.TrimSpace(profileName), mailer: mailer}
	for _, d := range domains {
		if d = strings.ToLower(strings.TrimSpace(d)); d != "" {
			cfg.domains[d] = true
		}
	}
	if len(cfg.domains) > 0 {
		s.email = cfg
	}
	return s
}

// NormalizeEmailIdentifier returns an email identifier's comparable form
// (RFC 9598 §5): the local part exact, never case-folded or normalized, and
// the domain lowercased in A-labels. Since P15-L4 the local part may be a
// quoted string (stored quoted only when it is not a dot-atom, with the
// fewest escapes) and may hold non-ASCII characters (RFC 6531; such a mailbox
// is certified as an SmtpUTF8Mailbox), and the domain may be internationalized
// (U-labels become A-labels). A wildcard is never allowed (RFC 8823 §3),
// quoted or not, nor a control character or byte order mark.
func NormalizeEmailIdentifier(v string) (string, error) {
	if len(v) == 0 || len(v) > 1024 {
		return "", errors.New("acme: an email identifier is 1-254 characters")
	}
	at := strings.LastIndexByte(v, '@')
	if at <= 0 || at == len(v)-1 {
		return "", errors.New("acme: an email identifier is local-part@domain")
	}
	local, err := canonicalLocalPart(v[:at])
	if err != nil {
		return "", err
	}
	domain, err := emailDomainALabels(v[at+1:])
	if err != nil {
		return "", err
	}
	out := local + "@" + domain
	if len(out) > 254 {
		return "", errors.New("acme: an email identifier is 1-254 characters")
	}
	return out, nil
}

// canonicalLocalPart checks a local part written as a dot-atom or a quoted
// string (RFC 5321 §4.1.2) and returns its canonical form: a quoted string
// whose content is a dot-atom is written unquoted, as RFC 5321 asks.
func canonicalLocalPart(local string) (string, error) {
	if len(local) >= 2 && local[0] == '"' && local[len(local)-1] == '"' {
		var content strings.Builder
		for i := 1; i < len(local)-1; i++ {
			c := local[i]
			if c == '\\' {
				i++
				if i >= len(local)-1 || local[i] < 32 || local[i] > 126 {
					return "", errors.New("acme: an email identifier's quoted local part has a bad escape")
				}
				c = local[i]
			} else if c == '"' || c < 32 || c == 127 {
				// Bytes from 0x80 are UTF-8, checked as characters below.
				return "", errors.New("acme: an email identifier's quoted local part has a control character or a bare quote")
			}
			content.WriteByte(c)
		}
		return CanonicalLocalPartContent(content.String())
	}
	// Unquoted, the local part is a dot-atom (RFC 5321 Dot-string): a quote,
	// a space or an empty label outside a quoted string is malformed.
	if local == "" || local[0] == '.' || local[len(local)-1] == '.' || strings.Contains(local, "..") {
		return "", errors.New("acme: an email identifier's local part is not a dot-atom or a quoted string")
	}
	for i := 0; i < len(local); i++ {
		if !dotAtomByte(local[i]) && local[i] != '*' && local[i] < 0x80 {
			return "", errors.New("acme: an email identifier's local part is not a dot-atom or a quoted string")
		}
	}
	return CanonicalLocalPartContent(local)
}

// CanonicalLocalPartContent returns the canonical local part for its
// unquoted content (as a mail parser returns it): unquoted when the content
// is a dot-atom, otherwise quoted with only '"' and '\' escaped.
func CanonicalLocalPartContent(content string) (string, error) {
	if content == "" {
		return "", errors.New("acme: an email identifier's local part is empty")
	}
	if strings.ContainsRune(content, '*') {
		return "", errors.New("acme: an email identifier's local part has a wildcard, which is never allowed")
	}
	if !utf8.ValidString(content) {
		return "", errors.New("acme: an email identifier's local part is not UTF-8")
	}
	dotAtom := content[0] != '.' && content[len(content)-1] != '.' && !strings.Contains(content, "..")
	for _, r := range content {
		switch {
		case r < 32 || r == 127 || unicode.IsControl(r) || r == 0xFEFF:
			return "", errors.New("acme: an email identifier's local part has a control character or a byte order mark")
		case r >= 0x80:
			// RFC 6531: a non-ASCII character is atext.
		case !dotAtomByte(byte(r)):
			dotAtom = false
		}
	}
	out := content
	if !dotAtom {
		out = `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(content) + `"`
	}
	if len(out) > 64 {
		return "", errors.New("acme: an email identifier's local part is longer than 64 octets")
	}
	return out, nil
}

// emailDomainALabels returns a mail domain lowercased in A-labels (RFC 9598
// §3): a U-label is converted (IDNA2008 with UTS #46 mapping for lookup) and
// an A-label checked.
func emailDomainALabels(domain string) (string, error) {
	ascii, err := idna.Lookup.ToASCII(domain)
	if err != nil || !validEmailDomain(strings.ToLower(ascii)) {
		return "", errors.New("acme: an email identifier's domain is not a DNS name")
	}
	return strings.ToLower(ascii), nil
}

func validEmailDomain(domain string) bool {
	if len(domain) > 253 || !strings.Contains(domain, ".") {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			if !ldhByte(label[i]) {
				return false
			}
		}
	}
	return true
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// dotAtomByte reports whether c may appear in an ASCII dot-atom local part
// (RFC 5322 atext or "."), without "*".
func dotAtomByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte(".!#$%&'+-/=?^_`{|}~", c) >= 0
}

// ldhByte reports whether c may appear in a lowercase DNS label.
func ldhByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-'
}

func emailDomain(address string) string {
	return address[strings.LastIndexByte(address, '@')+1:]
}

// sha256Hex is the state digest of a token or response: SHA-256, hex.
func sha256Hex(s string) string {
	d, err := crypto.Digest(crypto.SHA256, []byte(s))
	if err != nil {
		return ""
	}
	return hex.EncodeToString(d)
}

// emailExpectedResponse is base64url(SHA-256(token-part1 || token-part2 "."
// thumbprint)) without padding (RFC 8823 §3 step 6, RFC 8555 §8.1).
func emailExpectedResponse(tokenPart1, tokenPart2, thumbprint string) string {
	d, err := crypto.Digest(crypto.SHA256, []byte(tokenPart1+tokenPart2+"."+thumbprint))
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(d)
}

// canonicalEmailToken drops what RFC 8823 says to ignore inside a token or a
// response — white space and line breaks — and any base64 padding.
func canonicalEmailToken(s string) string {
	return strings.TrimRight(strings.Join(strings.Fields(s), ""), "=")
}

// EmailReply is a reply mail the intake has authenticated: From is the
// mailbox its DKIM signature vouches for, SubjectToken the token-part1 from
// its Subject (after "ACME:"), Response the digest from its ACME RESPONSE
// block.
type EmailReply struct {
	From         string
	SubjectToken string
	Response     string
}

var (
	// ErrEmailReplyUnmatched: no pending challenge for that mailbox carries
	// that token-part1 (a wrong mailbox, a wrong token, or nothing pending).
	ErrEmailReplyUnmatched = errors.New("acme: the reply matches no pending email challenge for its mailbox")
	// ErrEmailReplyWrongResponse: the right mailbox and token-part1 but a wrong
	// response; the challenge is now invalid.
	ErrEmailReplyWrongResponse = errors.New("acme: the reply's response is wrong; the challenge is now invalid")
)

// AcceptEmailReply validates an authenticated reply against the pending
// email-reply-00 challenge it answers and returns that challenge's ID. A
// reply may arrive before the client POSTs the challenge (RFC 8823 §3 steps 6
// and 7): it validates the challenge either way, and the POST then reports it.
func (s *Server) AcceptEmailReply(ctx context.Context, reply EmailReply) (string, error) {
	from, err := NormalizeEmailIdentifier(strings.TrimSpace(reply.From))
	if err != nil {
		return "", ErrEmailReplyUnmatched
	}
	tokenHash := sha256Hex(canonicalEmailToken(reply.SubjectToken))
	// Like a request, the reply runs under the live tenant registration.
	ctx, release, err := s.beginStateScope(ctx)
	if err != nil {
		return "", err
	}
	defer release()
	s.mu.Lock()
	defer s.mu.Unlock()
	var ch *challenge
	var az *authorization
	for _, candidate := range s.challenges {
		if candidate.typ != ChallengeEmailReply00 || (candidate.status != statusPending && candidate.status != statusProcessing) {
			continue
		}
		owner := s.authzs[candidate.authzID]
		if owner == nil || owner.identType != IdentifierEmail || owner.domain != from ||
			!crypto.ConstantTimeEqual([]byte(candidate.emailTokenPart1SHA256), []byte(tokenHash)) {
			continue
		}
		ch, az = candidate, owner
		break
	}
	if ch == nil {
		return "", ErrEmailReplyUnmatched
	}
	o := s.orders[az.orderID]
	if !crypto.ConstantTimeEqual([]byte(sha256Hex(canonicalEmailToken(reply.Response))), []byte(ch.emailResponseSHA256)) {
		event := challengeValidatedEventFrom(ch, az, o, statusInvalid)
		event.ChallengeStatus, event.AuthzStatus = statusInvalid, statusInvalid
		if err := s.appendStateEventLocked(ctx, acmeEventChallengeValidated, event); err != nil {
			return ch.id, err
		}
		if err := s.applyChallengeValidatedEventLocked(event); err != nil {
			return ch.id, err
		}
		return ch.id, ErrEmailReplyWrongResponse
	}
	orderStatus := ""
	if o != nil {
		orderStatus = o.status
		if s.allAuthzValidExcept(o, az.id) {
			orderStatus = statusReady
		}
	}
	event := challengeValidatedEventFrom(ch, az, o, orderStatus)
	if err := s.appendStateEventLocked(ctx, acmeEventChallengeValidated, event); err != nil {
		return ch.id, err
	}
	if err := s.applyChallengeValidatedEventLocked(event); err != nil {
		return ch.id, err
	}
	return ch.id, nil
}

// allAuthzValidExcept reports whether every authorization of o other than
// except is valid.
func (s *Server) allAuthzValidExcept(o *order, except string) bool {
	for _, id := range o.authzIDs {
		if id == except {
			continue
		}
		if other := s.authzs[id]; other == nil || other.status != statusValid {
			return false
		}
	}
	return true
}

// newEmailChallenge prepares an email-reply-00 challenge for address: token-part2
// is the challenge's token, token-part1 goes only into the returned mail, and
// the challenge keeps digests of token-part1 and of the expected response.
func (s *Server) newEmailChallenge(ch *challenge, address, thumbprint string, now time.Time) EmailChallengeMail {
	tokenPart1 := randomToken()
	ch.emailTokenPart1SHA256 = sha256Hex(tokenPart1)
	ch.emailResponseSHA256 = sha256Hex(emailExpectedResponse(tokenPart1, ch.token, thumbprint))
	ch.emailMessageID = "<" + randomToken() + "@" + emailDomain(s.email.from) + ">"
	return EmailChallengeMail{
		TenantID: s.stateTenantID, ChallengeID: ch.id, MessageID: ch.emailMessageID,
		From: s.email.from, To: address, Subject: "ACME: " + tokenPart1, Date: now,
	}
}

// emailOrderProblem checks an email order's identifiers against the offer and
// returns their normalized values, or an ACME problem type and detail.
func (s *Server) emailOrderIdentifiers(req OrderRequest) ([]string, string, string) {
	if s.email == nil {
		return nil, "unsupportedIdentifier", "email identifiers are not offered by this server"
	}
	out := make([]string, 0, len(req.Identifiers))
	seen := map[string]bool{}
	for _, id := range req.Identifiers {
		if id.Type != IdentifierEmail {
			return nil, "rejectedIdentifier", "an order holds either dns or email identifiers, not both"
		}
		address, err := NormalizeEmailIdentifier(id.Value)
		if err != nil {
			return nil, "rejectedIdentifier", err.Error()
		}
		if !s.email.domains[emailDomain(address)] {
			return nil, "rejectedIdentifier", fmt.Sprintf("this server does not issue for the mail domain %s", emailDomain(address))
		}
		if !seen[address] {
			seen[address] = true
			out = append(out, address)
		}
	}
	return out, "", ""
}

// ExtractEmailResponse returns the digest inside a reply body's ACME RESPONSE
// block (RFC 8823 §3.2 item 7): the lines between the markers, line breaks
// removed. Text before and after the block is ignored.
func ExtractEmailResponse(body string) (string, bool) {
	start := strings.Index(body, emailResponseBegin)
	if start < 0 {
		return "", false
	}
	rest := body[start+len(emailResponseBegin):]
	end := strings.Index(rest, emailResponseEnd)
	if end < 0 {
		return "", false
	}
	response := canonicalEmailToken(rest[:end])
	return response, response != ""
}

// identifierTypeOf is an order's or authorization's identifier type; ""
// (every order before P15) is dns.
func identifierTypeOf(identType string) string {
	if identType == "" {
		return IdentifierDNS
	}
	return identType
}

// hasIdentifierType reports whether any identifier of the order has typ.
func (o OrderRequest) hasIdentifierType(typ string) bool {
	for _, id := range o.Identifiers {
		if id.Type == typ {
			return true
		}
	}
	return false
}

// csrEmailIdentifiersMatchOrder enforces RFC 8823 §3 step 8 and §3.3 on an
// S/MIME finalize CSR: its rfc822Name SANs are exactly the order's addresses,
// it names nothing else (a common name, if any, is one of those addresses),
// and its key usage is signing-only — digitalSignature and/or
// nonRepudiation and nothing else. No key usage, or an encryption bit, asks
// for an encryption certificate, which needs key escrow this server does not
// offer.
func csrEmailIdentifiersMatchOrder(csrDER []byte, authorized []string) error {
	ids, err := crypto.CSRRequestedIdentifiers(csrDER)
	if err != nil {
		return fmt.Errorf("acme: finalize CSR is unreadable: %w", err)
	}
	if len(ids.DNSNames) > 0 || len(ids.IPAddresses) > 0 || len(ids.URIs) > 0 {
		return errors.New("acme: an S/MIME finalize CSR names identifiers other than email addresses")
	}
	allowed := map[string]bool{}
	for _, address := range authorized {
		allowed[address] = true
	}
	requested := map[string]bool{}
	for _, raw := range ids.EmailAddresses {
		address, err := NormalizeEmailIdentifier(raw)
		if err != nil || !allowed[address] {
			return errors.New("acme: finalize CSR requests an email address the order did not authorize")
		}
		requested[address] = true
	}
	// P15-L4: a mailbox with a non-ASCII local part is requested as an
	// SmtpUTF8Mailbox, exactly in its comparable form (the domain lowercase in
	// A-labels); an ASCII local part never is (RFC 9598 §3).
	for _, raw := range ids.SmtpUTF8Mailboxes {
		address, err := NormalizeEmailIdentifier(raw)
		if err != nil || address != raw || !allowed[address] {
			return errors.New("acme: finalize CSR requests an SmtpUTF8Mailbox the order did not authorize, or not in its A-label form")
		}
		if isASCII(address[:strings.LastIndexByte(address, '@')]) {
			return errors.New("acme: finalize CSR names an ASCII mailbox as an SmtpUTF8Mailbox; RFC 9598 requires an rfc822Name")
		}
		requested[address] = true
	}
	for address := range allowed {
		if !requested[address] {
			return errors.New("acme: finalize CSR omits an email address the order authorized")
		}
	}
	if cn := strings.TrimSpace(ids.CommonName); cn != "" {
		if address, err := NormalizeEmailIdentifier(cn); err != nil || !allowed[address] {
			return errors.New("acme: an S/MIME finalize CSR's common name must be one of the order's email addresses")
		}
	}
	usage, err := crypto.CSRRequestedKeyUsage(csrDER)
	if err != nil {
		return fmt.Errorf("acme: finalize CSR is unreadable: %w", err)
	}
	signingOnly := usage.Present && !usage.Other && (usage.DigitalSignature || usage.ContentCommitment)
	if !signingOnly {
		return errors.New("acme: this server issues signing-only S/MIME certificates: the CSR must ask for digitalSignature and/or nonRepudiation key usage and nothing else (encryption certificates need key escrow, which is not offered)")
	}
	return nil
}

// acmeEventEmailReplyRefused records a reply the RFC 8823 intake refused
// (P15-L9): which check refused it and the sender's domain, never the
// mailbox or the message. The ACME state replay ignores it.
const acmeEventEmailReplyRefused = "acme.email_reply.refused"

// Email reply refusal outcomes, one per check the intake makes.
const (
	EmailReplyRefusedMalformed     = "malformed"
	EmailReplyRefusedDKIM          = "dkim"
	EmailReplyRefusedUnmatched     = "unmatched"
	EmailReplyRefusedWrongResponse = "wrong_response"
	EmailReplyRefusedError         = "error"
	// EmailReplyRefusedSPF: SPF did not pass where it is required (P15-L6).
	EmailReplyRefusedSPF = "spf"
)

type acmeEmailReplyRefusedEvent struct {
	Outcome     string `json:"outcome"`
	FromDomain  string `json:"from_domain,omitempty"`
	ChallengeID string `json:"challenge_id,omitempty"`
}

// RecordEmailReplyRefused appends a refused reply to the tenant's audit
// record (P15-L9): its outcome, the From domain when the message named one,
// and the challenge a wrong response invalidated. A log failure does not
// change the refusal the sender already got, so it is not returned.
func (s *Server) RecordEmailReplyRefused(ctx context.Context, outcome, fromDomain, challengeID string) {
	if s == nil || s.stateLog == nil || s.stateTenantID == "" {
		return
	}
	body, err := json.Marshal(acmeEmailReplyRefusedEvent{Outcome: outcome, FromDomain: fromDomain, ChallengeID: challengeID})
	if err != nil {
		return
	}
	// Like the reply itself, the record runs under the live tenant registration.
	ctx, release, err := s.beginStateScope(ctx)
	if err != nil {
		return
	}
	defer release()
	_, _ = s.stateLog.Append(ctx, events.Event{Type: acmeEventEmailReplyRefused, TenantID: s.stateTenantID, Data: body})
}
