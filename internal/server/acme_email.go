// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/dkim"
	"trstctl.com/trstctl/internal/notify/email"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/protocols/acme"
	"trstctl.com/trstctl/internal/store"
)

// ACME email challenges (RFC 8823, P15). The ACME server hands each challenge
// mail to the outbox (AN-6); the outbox worker sends it through the configured
// SMTP relay, resolving the relay password for that one send. The relay must
// DKIM-sign the mail for the From domain.

const destinationACMEEmailChallenge = "acme.email_challenge"

type servedACMEEmailMailer struct {
	store    *store.Store
	outbox   *orchestrator.Outbox
	wake     func()
	cfg      config.ACMEEmail
	tenantID string
	resolver integrationCredentialResolver
	// send replaces the relay in tests; nil uses the configured relay.
	send func(ctx context.Context, from string, to []string, msg []byte) error
}

type acmeEmailOutboxPayload struct {
	ChallengeID string `json:"challenge_id"`
	From        string `json:"from"`
	To          string `json:"to"`
	MessageID   string `json:"message_id"`
	Message     []byte `json:"message"`
}

// QueueChallengeMail puts one challenge mail on the outbox, keyed by its
// challenge so a retried order cannot send it twice.
func (m *servedACMEEmailMailer) QueueChallengeMail(ctx context.Context, mail acme.EmailChallengeMail) error {
	body, err := json.Marshal(acmeEmailOutboxPayload{
		ChallengeID: mail.ChallengeID, From: mail.From, To: mail.To, MessageID: mail.MessageID, Message: mail.RFC5322(),
	})
	if err != nil {
		return err
	}
	tenantID := firstNonEmpty(mail.TenantID, m.tenantID)
	if err := m.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := m.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{
			TenantID: tenantID, Destination: destinationACMEEmailChallenge,
			IdempotencyKey: "acme-email-challenge:" + mail.ChallengeID, Payload: body,
		})
		return err
	}); err != nil {
		return err
	}
	if m.wake != nil {
		m.wake()
	}
	return nil
}

// Deliver sends one queued challenge mail through the relay.
func (m *servedACMEEmailMailer) Deliver(ctx context.Context, msg orchestrator.Message) error {
	var payload acmeEmailOutboxPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return orchestrator.DefiniteNoEffect(fmt.Errorf("server: decode acme email challenge: %w", err))
	}
	if payload.From == "" || payload.To == "" || len(payload.Message) == 0 {
		return orchestrator.DefiniteNoEffect(errors.New("server: acme email challenge payload is incomplete"))
	}
	message := payload.Message
	if strings.TrimSpace(m.cfg.DKIMKeyRef) != "" {
		signed, err := m.dkimSign(ctx, msg.TenantID, payload.From, message)
		if err != nil {
			// A mail meant to be signed never leaves unsigned: the delivery
			// retries until the key can be read.
			return fmt.Errorf("server: DKIM-sign the challenge mail: %w", err)
		}
		message = signed
	}
	if m.send != nil {
		return m.send(ctx, payload.From, []string{payload.To}, message)
	}
	var password []byte
	if ref := strings.TrimSpace(m.cfg.RelayPasswordRef); ref != "" {
		buf, err := m.resolver.resolve(ctx, msg.TenantID, ref)
		if err != nil {
			return fmt.Errorf("server: resolve the SMTP relay password: %w", err)
		}
		defer buf.Destroy()
		password = buf.Bytes()
	}
	return email.NewRelaySender(strings.TrimSpace(m.cfg.RelayAddr), strings.TrimSpace(m.cfg.RelayUsername), password).
		Send(ctx, payload.From, []string{payload.To}, message)
}

// acmeChallengeMailSignedHeaders are the challenge mail's header fields a
// DKIM signature covers (P15-L2).
var acmeChallengeMailSignedHeaders = []string{"From", "To", "Subject", "Date", "Message-ID", "Auto-Submitted", "MIME-Version",
	"Content-Type", "Content-Transfer-Encoding"}

// dkimSign adds trstctl's own DKIM-Signature to a challenge mail (P15-L2):
// rsa-sha256 for the from address's domain under the configured selector,
// with the key read from its reference for this one mail and destroyed after.
func (m *servedACMEEmailMailer) dkimSign(ctx context.Context, tenantID, from string, message []byte) ([]byte, error) {
	at := strings.LastIndexByte(from, '@')
	if at <= 0 || at == len(from)-1 {
		return nil, errors.New("the from address has no domain")
	}
	key, err := m.resolver.resolve(ctx, tenantID, strings.TrimSpace(m.cfg.DKIMKeyRef))
	if err != nil {
		return nil, fmt.Errorf("resolve the DKIM key: %w", err)
	}
	defer key.Destroy()
	var signed []byte
	err = crypto.WithPEMKeySigner(key.Bytes(), func(signer crypto.DigestSigner) error {
		var signErr error
		signed, signErr = dkim.Sign(message, strings.ToLower(from[at+1:]), strings.TrimSpace(m.cfg.DKIMSelector),
			acmeChallengeMailSignedHeaders, signer, time.Now())
		return signErr
	})
	return signed, err
}

func (d *issuanceDispatcher) deliverACMEEmailChallenge(ctx context.Context, m orchestrator.Message) error {
	if d.acmeEmail == nil {
		return orchestrator.DefiniteNoEffect(errors.New("server: acme email challenges are not configured"))
	}
	return d.acmeEmail.Deliver(ctx, m)
}
