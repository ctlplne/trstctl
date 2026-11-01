// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
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
	if m.send != nil {
		return m.send(ctx, payload.From, []string{payload.To}, payload.Message)
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
		Send(ctx, payload.From, []string{payload.To}, payload.Message)
}

func (d *issuanceDispatcher) deliverACMEEmailChallenge(ctx context.Context, m orchestrator.Message) error {
	if d.acmeEmail == nil {
		return orchestrator.DefiniteNoEffect(errors.New("server: acme email challenges are not configured"))
	}
	return d.acmeEmail.Deliver(ctx, m)
}
