// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	xacme "golang.org/x/crypto/acme"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/acmekey"
	"trstctl.com/trstctl/internal/dkim"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/protocols/acme"
)

// p15l2DKIMKey writes an RSA DKIM signing key as a PEM file the way an
// operator would, and returns its file: reference and its key record.
func p15l2DKIMKey(t *testing.T) (string, string) {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	der, err := key.PKCS8()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "dkim.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return "file:" + path, "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(key.Public().DER)
}

// P15-L2: with a DKIM selector and key configured, trstctl signs its own
// challenge mail before it reaches the relay: the signature (rsa-sha256,
// d= the from domain) verifies against the key's record and fails on a
// changed Subject; a key that cannot be read sends nothing rather than an
// unsigned mail; without a key the mail goes out as before for the relay to
// sign.
func TestChallengeMailIsDKIMSignedByTrstctlP15L2(t *testing.T) {
	ref, record := p15l2DKIMKey(t)
	mail := acme.EmailChallengeMail{ChallengeID: "c-p15l2", MessageID: "<c-p15l2@ca.p15l2.test>", From: "acme@ca.p15l2.test",
		To: "alice@p15l2.test", Subject: "ACME: p15l2-token-part-one", Date: time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)}
	payload, err := json.Marshal(acmeEmailOutboxPayload{ChallengeID: mail.ChallengeID, From: mail.From, To: mail.To,
		MessageID: mail.MessageID, Message: mail.RFC5322()})
	if err != nil {
		t.Fatal(err)
	}
	var sent [][]byte
	mailer := func(cfg config.ACMEEmail) *servedACMEEmailMailer {
		return &servedACMEEmailMailer{cfg: cfg, send: func(_ context.Context, _ string, _ []string, msg []byte) error {
			sent = append(sent, append([]byte(nil), msg...))
			return nil
		}}
	}
	ctx := context.Background()
	signing := mailer(config.ACMEEmail{From: mail.From, DKIMSelector: "trstctl", DKIMKeyRef: ref})
	if err := signing.Deliver(ctx, orchestrator.Message{TenantID: servedTestTenant, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 1 || !strings.HasPrefix(string(sent[0]), "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=ca.p15l2.test; s=trstctl;") {
		t.Fatalf("the sent mail = %.120q", sent)
	}
	verifier := dkim.Verifier{Pinned: map[string]string{"trstctl._domainkey.ca.p15l2.test": record}}
	if err := verifier.VerifyDomain(ctx, sent[0], "ca.p15l2.test"); err != nil {
		t.Fatalf("trstctl's signature does not verify: %v", err)
	}
	tampered := []byte(strings.Replace(string(sent[0]), "Subject: ACME: p15l2-token-part-one", "Subject: ACME: p15l2-token-part-two", 1))
	if err := verifier.VerifyDomain(ctx, tampered, "ca.p15l2.test"); err == nil {
		t.Fatal("a changed Subject still verified")
	}

	missing := mailer(config.ACMEEmail{From: mail.From, DKIMSelector: "trstctl", DKIMKeyRef: "file:" + filepath.Join(t.TempDir(), "absent.pem")})
	if err := missing.Deliver(ctx, orchestrator.Message{TenantID: servedTestTenant, Payload: payload}); err == nil || len(sent) != 1 {
		t.Fatalf("an unreadable key = %v after %d mails; want an error and nothing sent", err, len(sent))
	}

	relaySigns := mailer(config.ACMEEmail{From: mail.From})
	if err := relaySigns.Deliver(ctx, orchestrator.Message{TenantID: servedTestTenant, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 2 || strings.Contains(string(sent[1]), "DKIM-Signature") {
		t.Fatal("a mail without a configured key was signed")
	}
	if err := verifier.VerifyDomain(ctx, sent[1], "ca.p15l2.test"); err == nil || errors.Is(err, context.Canceled) {
		t.Fatal("an unsigned mail verified")
	}
}

// P15-L2: the served ACME mount's challenge mail reaches the relay already
// signed by trstctl for the from domain.
func TestServedChallengeMailIsSignedByTrstctlP15L2(t *testing.T) {
	ref, record := p15l2DKIMKey(t)
	relay := startP15SMTPRelay(t)
	h := newOperatingServedHarness(t, config.Protocols{
		ACME: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
		ACMEEmail: config.ACMEEmail{From: "acme@ca.p15l2.test", Domains: []string{"p15l2.test"},
			Profile: "smime-signing", RelayAddr: relay.addr, DKIMSelector: "trstctl", DKIMKeyRef: ref},
	})
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	spec, err := json.Marshal(map[string]any{"name": "smime-signing", "max_validity": "2160h",
		"allowed_ekus": []string{"emailProtection"}, "allowed_email_domains": []string{"p15l2.test"}, "allowed_protocols": []string{"acme"}})
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
	if _, err := client.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
		t.Fatal(err)
	}
	if _, err := client.AuthorizeOrder(ctx, []xacme.AuthzID{{Type: "email", Value: "alice@p15l2.test"}}); err != nil {
		t.Fatal(err)
	}
	var mail string
	select {
	case mail = <-relay.mails:
	case <-ctx.Done():
		t.Fatal("no challenge mail reached the relay")
	}
	verifier := dkim.Verifier{Pinned: map[string]string{"trstctl._domainkey.ca.p15l2.test": record}}
	if !strings.HasPrefix(mail, "DKIM-Signature:") || verifier.VerifyDomain(ctx, []byte(mail), "ca.p15l2.test") != nil {
		t.Fatalf("the relay received a mail trstctl did not sign: %.200q", mail)
	}
	t.Logf("P15L2_SIGNED_CHALLENGE_OK d=ca.p15l2.test s=trstctl")
}
