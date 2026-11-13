// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/branding"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/psa"
	"trstctl.com/trstctl/internal/psa/autotask"
	"trstctl.com/trstctl/internal/psa/connectwise"
	"trstctl.com/trstctl/internal/psa/gradient"
	"trstctl.com/trstctl/internal/psa/halopsa"
	"trstctl.com/trstctl/internal/psa/syncro"
	"trstctl.com/trstctl/internal/store"
)

// observeAttemptsBeforeSkip is how many attempts an alert waits for its
// observers before its channels go ahead without them: a PSA ticket must not
// hold back the alert's own channels for long.
const observeAttemptsBeforeSkip = 3

// observeAlert hands a notification row's alert to the attached observers
// before its channels see it (MSP-3). An observer error retries the row a few
// times; after that the channels go ahead and the error is logged.
func (d *issuanceDispatcher) observeAlert(ctx context.Context, m orchestrator.Message) error {
	if len(d.alertObservers) == 0 {
		return nil
	}
	var alert notify.Alert
	if json.Unmarshal(m.Payload, &alert) != nil {
		return nil
	}
	if alert.TenantID == "" {
		alert.TenantID = m.TenantID
	}
	if alert.TenantID != m.TenantID {
		return nil
	}
	for _, observer := range d.alertObservers {
		err := observer.ObserveAlert(ctx, m.TenantID, m.IdempotencyKey, alert)
		if err == nil {
			continue
		}
		if m.Attempts < observeAttemptsBeforeSkip {
			return fmt.Errorf("server: observe alert: %w", err)
		}
		slog.Default().Warn("an alert observer failed; the alert's channels go ahead without it",
			"destination", m.Destination, "kind", alert.Kind, "attempt", m.Attempts)
	}
	return nil
}

// psaTicketReference is the external reference a subject's ticket carries
// in the PSA: unique per customer, target, subject and generation.
func psaTicketReference(tenantID string, t projections.PSATicketEvent) string {
	return "trstctl-" + crypto.SHA256Hex([]byte(tenantID + "\x00" + t.TargetID + "\x00" + t.AlertKey + "\x00" + strconv.Itoa(t.Generation)))[:24]
}

// handlePSATicket performs one ticket operation (MSP-3). Before anything
// leaves, the target must still open tickets, the customer must still be
// mapped to the company the ticket belongs to, and the operation must be
// the ticket's current generation. The PSA's text carries the tenant's
// "Powered by" line from its brand, never from the payload.
func (d *issuanceDispatcher) handlePSATicket(ctx context.Context, m orchestrator.Message) error {
	var t projections.PSATicketEvent
	if err := json.Unmarshal(m.Payload, &t); err != nil {
		return orchestrator.DefiniteNoEffect(fmt.Errorf("server: decode PSA ticket operation: %w", err))
	}
	if err := projections.ValidatePSATicketEvent(projections.EventPSATicketRequested, t); err != nil {
		return orchestrator.DefiniteNoEffect(fmt.Errorf("server: PSA ticket operation: %w", err))
	}
	if m.IdempotencyKey != orchestrator.PSATicketOpKey(t.TargetID, t.AlertKey, t.Generation, t.Op, t.AlertRef) {
		return orchestrator.DefiniteNoEffect(errors.New("server: PSA ticket key does not name its operation"))
	}
	target, ok := d.billingSync.Target(t.TargetID)
	if !ok || len(target.TicketKinds()) == 0 {
		return orchestrator.DefiniteNoEffect(fmt.Errorf("server: target %q no longer opens tickets", t.TargetID))
	}
	if d.store == nil {
		return errors.New("server: PSA tickets need the store")
	}
	company, mapped, err := d.store.BillingCompanyFor(ctx, m.TenantID, t.TargetID)
	if err != nil {
		return err
	}
	if !mapped || company != t.ExternalCompanyID {
		return orchestrator.DefiniteNoEffect(fmt.Errorf("server: customer is no longer mapped to company %q in target %q", t.ExternalCompanyID, t.TargetID))
	}
	cur, found, err := d.store.PSATicketFor(ctx, m.TenantID, t.TargetID, t.AlertKey)
	if err != nil {
		return err
	}
	if !found || cur.Generation != t.Generation {
		return orchestrator.DefiniteNoEffect(errors.New("server: a newer ticket replaced this one"))
	}
	poweredBy := branding.PoweredByLine(ctx, m.TenantID)
	withLine := func(text string) string {
		if poweredBy == "" {
			return text
		}
		return strings.TrimSpace(text) + "\n\n" + poweredBy
	}
	outcome := projections.PSATicketEvent{TargetID: t.TargetID, AlertKey: t.AlertKey, Generation: t.Generation, Op: t.Op,
		ExternalCompanyID: t.ExternalCompanyID, OK: true}
	switch t.Op {
	case store.PSATicketOpOpen:
		if cur.Status != store.PSATicketOpening {
			return nil
		}
	case store.PSATicketOpUpdate:
		switch {
		case cur.ExternalTicketID == "" && cur.Status == store.PSATicketOpening:
			return orchestrator.DeferDeliveryUntil(errors.New("server: the ticket is still opening"), time.Now().Add(billingSyncOrderWait))
		case cur.ExternalTicketID == "":
			return orchestrator.DefiniteNoEffect(errors.New("server: the ticket never opened"))
		case cur.Status != store.PSATicketOpen:
			return nil
		}
	case store.PSATicketOpClose:
		if cur.ExternalTicketID == "" {
			return orchestrator.DefiniteNoEffect(errors.New("server: the ticket never opened"))
		}
		if cur.Status != store.PSATicketClosing {
			return nil
		}
	}
	err = d.withPSAClient(target, func(cw psa.Client) error {
		switch t.Op {
		case store.PSATicketOpOpen:
			id, err := cw.OpenTicket(ctx, psa.TicketOpen{ExternalCompanyID: t.ExternalCompanyID, Reference: psaTicketReference(m.TenantID, t),
				Summary: t.Summary, Description: withLine(t.Note)})
			outcome.ExternalTicketID = id
			return err
		case store.PSATicketOpUpdate:
			return cw.AddNote(ctx, psa.TicketNote{TicketID: cur.ExternalTicketID,
				Reference: "n-" + crypto.SHA256Hex([]byte(t.AlertRef))[:16], Text: withLine(t.Note)})
		default:
			return cw.CloseTicket(ctx, psa.TicketClose{TicketID: cur.ExternalTicketID,
				Reference:  "c-" + crypto.SHA256Hex([]byte(t.AlertKey + "\x00" + strconv.Itoa(t.Generation)))[:16],
				Resolution: withLine("Resolved: " + t.Reason)})
		}
	})
	if err != nil {
		if errors.Is(err, psa.ErrBeforeWrite) {
			return orchestrator.DefiniteNoEffect(err)
		}
		return err
	}
	return d.orch.RecordPSATicketOutcome(ctx, m.TenantID, outcome)
}

// failPSATicketTerminal records an operation that failed for good, with the
// last cause (never a credential), and raises its alert.
func (d *issuanceDispatcher) failPSATicketTerminal(ctx context.Context, m orchestrator.Message, cause error) error {
	var t projections.PSATicketEvent
	if err := json.Unmarshal(m.Payload, &t); err != nil {
		return nil
	}
	reason := "not done"
	if cause != nil {
		reason = "not done: " + cause.Error()
		if !orchestrator.IsDefiniteNoEffect(cause) {
			reason = "outcome unknown after retries (check the ticket in the PSA): " + cause.Error()
		}
	}
	if len(reason) > 500 {
		reason = reason[:500]
	}
	return d.orch.RecordPSATicketOutcome(ctx, m.TenantID, projections.PSATicketEvent{TargetID: t.TargetID, AlertKey: t.AlertKey,
		Generation: t.Generation, Op: t.Op, ExternalCompanyID: t.ExternalCompanyID, Reason: reason})
}

// withPSAClient resolves a vendor target's credentials for one delivery,
// hands fn its client, and wipes the credentials afterwards.
func (d *issuanceDispatcher) withPSAClient(target config.ProviderBillingTarget, fn func(psa.Client) error) error {
	client, err := d.billingSyncHTTPClient(target)
	if err != nil {
		return orchestrator.DefiniteNoEffect(fmt.Errorf("server: billing target endpoint rejected: %w", err))
	}
	switch {
	case target.Type == "connectwise" && target.ConnectWise != nil:
		cw := target.ConnectWise
		publicKey, err := resolveDeploymentCredentialRef(cw.PublicKeyRef)
		if err != nil {
			return orchestrator.DefiniteNoEffect(errors.New("server: resolve the connectwise target's public_key_ref"))
		}
		defer publicKey.Destroy()
		privateKey, err := resolveDeploymentCredentialRef(cw.PrivateKeyRef)
		if err != nil {
			return orchestrator.DefiniteNoEffect(errors.New("server: resolve the connectwise target's private_key_ref"))
		}
		defer privateKey.Destroy()
		cfg := connectwise.Config{BaseURL: target.Endpoint, CompanyID: cw.CompanyID, ClientID: cw.ClientID,
			AgreementType: cw.AgreementType, Products: cw.Products}
		if cw.Tickets != nil {
			cfg.Tickets = &connectwise.TicketConfig{Board: cw.Tickets.Board, NewStatus: cw.Tickets.NewStatus, ClosedStatus: cw.Tickets.ClosedStatus}
		}
		psaClient, err := connectwise.New(cfg, client, connectwise.Credentials{PublicKey: publicKey.Bytes(), PrivateKey: privateKey.Bytes()})
		if err != nil {
			return orchestrator.DefiniteNoEffect(err)
		}
		return fn(psaClient)
	case target.Type == "autotask" && target.Autotask != nil:
		at := target.Autotask
		secretValue, err := resolveDeploymentCredentialRef(at.SecretRef)
		if err != nil {
			return orchestrator.DefiniteNoEffect(errors.New("server: resolve the autotask target's secret_ref"))
		}
		defer secretValue.Destroy()
		code, err := resolveDeploymentCredentialRef(at.IntegrationCodeRef)
		if err != nil {
			return orchestrator.DefiniteNoEffect(errors.New("server: resolve the autotask target's integration_code_ref"))
		}
		defer code.Destroy()
		cfg := autotask.Config{BaseURL: target.Endpoint, Username: at.Username, ContractName: at.ContractName, Services: at.Services}
		if tk := at.Tickets; tk != nil {
			cfg.Tickets = &autotask.TicketConfig{QueueID: tk.QueueID, StatusNew: tk.StatusNew, StatusComplete: tk.StatusComplete,
				Priority: tk.Priority, NoteType: tk.EffectiveNoteType(), NotePublish: tk.EffectiveNotePublish()}
		}
		psaClient, err := autotask.New(cfg, client, autotask.Credentials{Secret: secretValue.Bytes(), IntegrationCode: code.Bytes()})
		if err != nil {
			return orchestrator.DefiniteNoEffect(err)
		}
		return fn(psaClient)
	case target.Type == "syncro" && target.Syncro != nil:
		sy := target.Syncro
		token, err := resolveDeploymentCredentialRef(sy.APITokenRef)
		if err != nil {
			return orchestrator.DefiniteNoEffect(errors.New("server: resolve the syncro target's api_token_ref"))
		}
		defer token.Destroy()
		cfg := syncro.Config{BaseURL: target.Endpoint, ScheduleName: sy.ScheduleName, Products: sy.Products}
		if tk := sy.Tickets; tk != nil {
			cfg.Tickets = &syncro.TicketConfig{ProblemType: tk.ProblemType, StatusNew: tk.EffectiveStatusNew(), StatusClosed: tk.EffectiveStatusClosed()}
		}
		psaClient, err := syncro.New(cfg, client, syncro.Credentials{APIToken: token.Bytes()})
		if err != nil {
			return orchestrator.DefiniteNoEffect(err)
		}
		return fn(psaClient)
	case target.Type == "halopsa" && target.HaloPSA != nil:
		hp := target.HaloPSA
		secretValue, err := resolveDeploymentCredentialRef(hp.ClientSecretRef)
		if err != nil {
			return orchestrator.DefiniteNoEffect(errors.New("server: resolve the halopsa target's client_secret_ref"))
		}
		defer secretValue.Destroy()
		cfg := halopsa.Config{BaseURL: target.Endpoint, Tenant: hp.Tenant, ClientID: hp.ClientID,
			RecurringInvoiceName: hp.RecurringInvoiceName, Items: hp.Items}
		if tk := hp.Tickets; tk != nil {
			cfg.Tickets = &halopsa.TicketConfig{TicketTypeID: tk.TicketTypeID, StatusNewID: tk.StatusNewID, StatusClosedID: tk.StatusClosedID}
		}
		psaClient, err := halopsa.New(cfg, client, halopsa.Credentials{ClientSecret: secretValue.Bytes()})
		if err != nil {
			return orchestrator.DefiniteNoEffect(err)
		}
		return fn(psaClient)
	case target.Type == "gradient" && target.Gradient != nil:
		g := target.Gradient
		token, err := resolveDeploymentCredentialRef(g.TokenRef)
		if err != nil {
			return orchestrator.DefiniteNoEffect(errors.New("server: resolve the gradient target's token_ref"))
		}
		defer token.Destroy()
		psaClient, err := gradient.New(gradient.Config{BaseURL: target.Endpoint, Services: g.Services}, client, gradient.Credentials{Token: token.Bytes()})
		if err != nil {
			return orchestrator.DefiniteNoEffect(err)
		}
		return fn(psaClient)
	default:
		return orchestrator.DefiniteNoEffect(fmt.Errorf("server: billing target %q has no %s settings", target.ID, target.Type))
	}
}
