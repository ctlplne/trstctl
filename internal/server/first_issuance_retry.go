// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

func (s *Server) RetryFirstIssuance(ctx context.Context, tenantID, identityID, requestKey, retryKey, reason string) (store.FirstIssuanceRetryReceipt, error) {
	d, ok := s.obHandler.(*issuanceDispatcher)
	if !ok || d == nil {
		return store.FirstIssuanceRetryReceipt{}, store.ErrIssuanceRetryUnavailable
	}
	return s.orch.RequestFirstIssuanceRetry(ctx, tenantID, identityID, requestKey, retryKey, reason,
		func(ctx context.Context, command store.FirstIssuanceRetryCommand) (string, error) {
			return d.qualifyFirstIssuanceRetry(ctx, tenantID, command)
		})
}

func (s *Server) FirstIssuanceRetryReadiness(ctx context.Context, tenantID, identityID, requestKey string) (api.FirstIssuanceRetryReadiness, error) {
	result := api.FirstIssuanceRetryReadiness{Reason: "The original issuance must be failed before requesting another attempt."}
	d, ok := s.obHandler.(*issuanceDispatcher)
	if !ok || d == nil {
		return result, nil
	}
	var command store.FirstIssuanceRetryCommand
	err := d.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		command, err = d.store.FirstIssuanceRetryCommandTx(ctx, tx, tenantID, identityID, requestKey, false)
		return err
	})
	if err != nil {
		return result, err
	}
	if command.Status != "failed" {
		return result, nil
	}
	_, err = d.qualifyFirstIssuanceRetry(ctx, tenantID, command)
	if errors.Is(err, store.ErrIssuanceRetryUnavailable) {
		result.Reason = strings.TrimPrefix(err.Error(), store.ErrIssuanceRetryUnavailable.Error()+": ")
		return result, nil
	}
	if err != nil {
		return result, err
	}
	result.Allowed = true
	result.Reason = "The original certificate or a recoverable signing operation is retained. After correcting the failure, request one more attempt."
	return result, nil
}

func (d *issuanceDispatcher) qualifyFirstIssuanceRetry(ctx context.Context, tenantID string, command store.FirstIssuanceRetryCommand) (string, error) {
	refuse := func(reason string) (string, error) {
		return "", fmt.Errorf("%w: %s", store.ErrIssuanceRetryUnavailable, reason)
	}
	if command.Identity.Status != string(orchestrator.StateIssued) && command.Identity.Status != string(orchestrator.StateDeployed) {
		return refuse("This identity has moved past its original issuance; review its current lifecycle state.")
	}
	certs, err := d.store.ListCertificatesByIssuanceIdempotencyKey(ctx, tenantID, "issue:"+command.OutboxKey)
	if err != nil {
		return "", err
	}
	if len(certs) > 1 {
		return refuse("Multiple certificates are recorded for the original request; reconcile them with the issuer first.")
	}
	if len(certs) == 1 {
		cert := certs[0]
		if cert.Status != "active" || cert.RevokedAt != nil || cert.NotAfter == nil || !cert.NotAfter.After(time.Now()) || len(cert.CertificateDER) == 0 || len(cert.CertificatePEM) == 0 {
			return refuse("The recorded certificate is no longer usable; follow replacement or revocation recovery.")
		}
		return "recorded_certificate", nil
	}
	if command.Identity.Status != string(orchestrator.StateIssued) {
		return refuse("No original certificate is recorded for this identity's current lifecycle state.")
	}
	var trigger transitionTrigger
	if json.Unmarshal(command.Payload, &trigger) != nil {
		return "", store.ErrIdempotencyConflict
	}
	selection, err := endpointIssuingAuthority(command.Identity.Attributes)
	if err != nil {
		return refuse("The original issuer selection must be restored before recovery.")
	}
	ctx = withLeafCommand(ctx, d.idem, tenantID, command.OutboxKey)
	if strings.TrimSpace(trigger.SubjectCSRPEM) == "" && subjectCSRFromIdentity(command.Identity) == "" {
		subject, _, err := d.leafSubjectPreparation(ctx, tenantID, command.Identity.OwnerID, command.Identity.Name, []string{command.Identity.Name}, selection, false)
		secret.Wipe(subject.KeyPEM)
		if err != nil {
			return refuse("The original subject key is unavailable or its binding changed. Reconcile the historical request with its issuer; a new key cannot recover that certificate.")
		}
	}
	if selection.Source == "external" {
		key := endpointBindingIssueKey(trigger, orchestrator.Message{IdempotencyKey: command.OutboxKey}) + ":external-ca:" + selection.ID
		result, err := d.store.GetIssuedCertificateRecovery(ctx, tenantID, key)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return "", err
		}
		if err == nil && len(result.CertificatePEM) > 0 && result.RequestBinding != "" && result.NotAfter != nil && result.NotAfter.After(time.Now()) {
			return "external_issuer_result", nil
		}
		return refuse("No exact external-issuer result is retained. Reconcile the original request at the selected CA before requesting new issuance.")
	}
	leaf := leafCommand{tenantID: tenantID, key: command.OutboxKey, idem: d.idem}
	prepared, err := d.store.HasCompletedIdempotencyResult(ctx, tenantID, leaf.preparationKey("leaf-template:v1:"))
	if err != nil {
		return "", err
	}
	if !prepared {
		return refuse("This request has no retained signing operation. Reconcile its outcome with the original issuer before creating another certificate.")
	}
	return "prepared_signing_operation", nil
}
