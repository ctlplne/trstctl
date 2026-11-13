// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/secretfile"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/psa"
	"trstctl.com/trstctl/internal/psa/connectwise"
	"trstctl.com/trstctl/internal/secretsync"
	"trstctl.com/trstctl/internal/secrettext"
)

// billingSyncPushBody is what a billing target receives for one customer's
// closed usage period (MSP-2): the company the Provider mapped the customer
// to, the period, the metered lines, and the signed evidence those lines came
// from, so the receiver can verify the numbers against the Provider's
// published evidence keys.
type billingSyncPushBody struct {
	CustomerID        string                         `json:"customer_id"`
	ExternalCompanyID string                         `json:"external_company_id"`
	TargetID          string                         `json:"target_id"`
	PeriodStart       time.Time                      `json:"period_start"`
	PeriodEnd         time.Time                      `json:"period_end"`
	Lines             []projections.BillingUsageLine `json:"lines"`
	EvidenceDigest    string                         `json:"evidence_digest"`
	EvidenceJWS       string                         `json:"evidence_jws"`
}

// errBillingSyncReceiverRefused is a target's 4xx answer other than 408 or
// 429: the same body would be refused again, so the period fails for good.
var errBillingSyncReceiverRefused = errors.New("server: the billing target refused the period")

// handleBillingSync delivers one queued period. Before anything leaves, the
// target must still be configured and the customer must still be mapped to
// the company the period was queued for: a remapped customer's period is
// never sent to its old company, nor its new one with old evidence. The
// credentials are resolved for this delivery only and wiped.
func (d *issuanceDispatcher) handleBillingSync(ctx context.Context, m orchestrator.Message) error {
	var push projections.BillingSyncPushEvent
	if err := json.Unmarshal(m.Payload, &push); err != nil {
		return orchestrator.DefiniteNoEffect(fmt.Errorf("server: decode billing sync push: %w", err))
	}
	if err := projections.ValidateBillingSyncPushEvent(projections.EventBillingSyncQueued, push); err != nil {
		return orchestrator.DefiniteNoEffect(fmt.Errorf("server: billing sync push: %w", err))
	}
	if m.IdempotencyKey != orchestrator.BillingSyncPushKey(push.TargetID, push.PeriodStart) {
		return orchestrator.DefiniteNoEffect(errors.New("server: billing sync push key does not name its target and period"))
	}
	target, ok := d.billingSync.Target(push.TargetID)
	if !ok {
		return orchestrator.DefiniteNoEffect(fmt.Errorf("server: billing target %q is no longer configured", push.TargetID))
	}
	if d.store == nil {
		return errors.New("server: billing sync needs the store")
	}
	company, mapped, err := d.store.BillingCompanyFor(ctx, m.TenantID, push.TargetID)
	if err != nil {
		return err
	}
	if !mapped || company != push.ExternalCompanyID {
		return orchestrator.DefiniteNoEffect(fmt.Errorf("server: customer is no longer mapped to company %q in billing target %q", push.ExternalCompanyID, push.TargetID))
	}
	if target.Type == "connectwise" {
		return d.pushBillingConnectWise(ctx, m, target, push)
	}
	return d.pushBillingJSON(ctx, m, target, push)
}

// pushBillingJSON is the generic signed JSON push (MSP-2).
func (d *issuanceDispatcher) pushBillingJSON(ctx context.Context, m orchestrator.Message, target config.ProviderBillingTarget, push projections.BillingSyncPushEvent) error {
	endpoint := strings.TrimSpace(target.Endpoint)
	client, err := d.billingSyncHTTPClient(target)
	if err != nil {
		return orchestrator.DefiniteNoEffect(fmt.Errorf("server: billing target endpoint rejected: %w", err))
	}
	signingKey, err := resolveDeploymentCredentialRef(target.SigningKeyRef)
	if err != nil {
		return orchestrator.DefiniteNoEffect(errors.New("server: resolve the billing target's signing_key_ref"))
	}
	defer signingKey.Destroy()
	keyBytes := signingKey.Bytes()
	var tokenBytes []byte
	if strings.TrimSpace(target.TokenRef) != "" {
		token, err := resolveDeploymentCredentialRef(target.TokenRef)
		if err != nil {
			return orchestrator.DefiniteNoEffect(errors.New("server: resolve the billing target's token_ref"))
		}
		defer token.Destroy()
		tokenBytes = token.Bytes()
	}
	body, err := json.Marshal(billingSyncPushBody{
		CustomerID: m.TenantID, ExternalCompanyID: push.ExternalCompanyID, TargetID: push.TargetID,
		PeriodStart: push.PeriodStart.UTC(), PeriodEnd: push.PeriodEnd.UTC(), Lines: push.Lines,
		EvidenceDigest: push.EvidenceDigest, EvidenceJWS: push.EvidenceJWS,
	})
	if err != nil {
		return orchestrator.DefiniteNoEffect(err)
	}
	timestamp := time.Now().Unix()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return orchestrator.DefiniteNoEffect(fmt.Errorf("server: build billing sync request: %w", err))
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Idempotency-Key", m.IdempotencyKey)
	req.Header.Set(secretsync.WebhookDeliveryHeader, m.IdempotencyKey)
	req.Header.Set(secretsync.WebhookTimestampHeader, strconv.FormatInt(timestamp, 10))
	req.Header.Set(secretsync.WebhookSignatureHeader, secretsync.WebhookSignature(keyBytes, timestamp, body))
	if len(tokenBytes) > 0 {
		req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", tokenBytes))
	}
	// From here a transport error cannot prove the receiver did nothing; the
	// receiver dedupes on Idempotency-Key, so a retry is safe.
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("server: deliver billing sync period: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode <= 299:
		push.ResponseStatus = resp.StatusCode
		return d.orch.RecordBillingSyncOutcome(ctx, m.TenantID, push, true)
	case resp.StatusCode >= 400 && resp.StatusCode <= 499 && resp.StatusCode != http.StatusRequestTimeout && resp.StatusCode != http.StatusTooManyRequests:
		return fmt.Errorf("%w (status %d)", errBillingSyncReceiverRefused, resp.StatusCode)
	default:
		return fmt.Errorf("server: billing target answered status %d", resp.StatusCode)
	}
}

// pushBillingConnectWise sets one customer's period as additions of its
// company's agreement (MSP-3). A quantity there is absolute, so one
// customer's periods go to the target oldest first, and an older period
// never overwrites the figures a newer one already set: it is recorded as
// handled with that reason and nothing is written.
func (d *issuanceDispatcher) pushBillingConnectWise(ctx context.Context, m orchestrator.Message, target config.ProviderBillingTarget, push projections.BillingSyncPushEvent) error {
	cw := target.ConnectWise
	if cw == nil {
		return orchestrator.DefiniteNoEffect(fmt.Errorf("server: billing target %q has no connectwise settings", target.ID))
	}
	earlierQueued, laterDelivered, err := d.store.BillingSyncNeighbors(ctx, m.TenantID, push.TargetID, push.PeriodStart)
	if err != nil {
		return err
	}
	if earlierQueued {
		return orchestrator.DeferDeliveryUntil(errors.New("server: an earlier period of this customer is still being delivered to this target"),
			time.Now().Add(billingSyncOrderWait))
	}
	if !laterDelivered.IsZero() {
		push.Reason = "nothing written: the period starting " + laterDelivered.Format("2006-01-02") + " already set this customer's quantities"
		return d.orch.RecordBillingSyncOutcome(ctx, m.TenantID, push, true)
	}
	lines := make([]psa.UsageLine, 0, len(push.Lines))
	for _, line := range push.Lines {
		lines = append(lines, psa.UsageLine{Meter: line.Meter, Value: line.Value})
	}
	var out psa.UsageOutcome
	err = d.withConnectWise(target, func(client *connectwise.Client) error {
		var err error
		out, err = client.PushUsage(ctx, psa.UsagePeriod{CustomerID: m.TenantID, ExternalCompanyID: push.ExternalCompanyID,
			PeriodStart: push.PeriodStart, PeriodEnd: push.PeriodEnd, Lines: lines, EvidenceDigest: push.EvidenceDigest})
		return err
	})
	if err != nil {
		if errors.Is(err, psa.ErrBeforeWrite) {
			return orchestrator.DefiniteNoEffect(err)
		}
		return err
	}
	push.ResponseStatus = out.Status
	return d.orch.RecordBillingSyncOutcome(ctx, m.TenantID, push, true)
}

// billingSyncOrderWait is how long a period waits for an earlier period of
// the same customer and target before it is tried again.
const billingSyncOrderWait = 10 * time.Second

// failBillingSyncTerminal records a period whose delivery failed for good,
// with the last cause (never a credential), and raises its alert.
func (d *issuanceDispatcher) failBillingSyncTerminal(ctx context.Context, m orchestrator.Message, cause error) error {
	var push projections.BillingSyncPushEvent
	if err := json.Unmarshal(m.Payload, &push); err != nil {
		return nil
	}
	// Only a pre-request failure proves nothing reached the receiver; after a
	// request was sent, a lost answer may hide a delivery, so the record says
	// the outcome is unknown and the alert asks the operator to check.
	reason := "not delivered"
	if cause != nil {
		reason = "not delivered: " + cause.Error()
		if !orchestrator.IsDefiniteNoEffect(cause) {
			reason = "delivery outcome unknown after retries (check the target; the Idempotency-Key lets it drop a duplicate): " + cause.Error()
		}
	}
	if len(reason) > 500 {
		reason = reason[:500]
	}
	push.Reason = reason
	return d.orch.RecordBillingSyncOutcome(ctx, m.TenantID, push, false)
}

// billingSyncHTTPClient is the egress client of one target: https through
// the private-egress policy, or plain http only to a loopback test receiver
// the target explicitly allows.
func (d *issuanceDispatcher) billingSyncHTTPClient(target config.ProviderBillingTarget) (*http.Client, error) {
	return secretIntegrationHTTPClient(strings.TrimSpace(target.Endpoint), target.AllowPrivateEndpoint, target.AllowInsecureLoopback,
		target.PrivateEgressCIDRs, d.egress)
}

// resolveDeploymentCredentialRef loads a deployment-level credential into a
// locked buffer the caller destroys: a custody-checked file, or an
// environment variable.
func resolveDeploymentCredentialRef(ref string) (*secret.Buffer, error) {
	ref = strings.TrimSpace(ref)
	var value []byte
	switch {
	case strings.HasPrefix(ref, "file:"):
		loaded, err := secretfile.Load(strings.TrimSpace(strings.TrimPrefix(ref, "file:")))
		if err != nil {
			return nil, fmt.Errorf("load credential file: %w", err)
		}
		value = loaded
	case strings.HasPrefix(ref, "env:"):
		raw, ok := os.LookupEnv(strings.TrimSpace(strings.TrimPrefix(ref, "env:")))
		if !ok || raw == "" {
			return nil, errors.New("environment credential is not set")
		}
		value = []byte(raw)
	default:
		return nil, errors.New("credential ref must use the file or env scheme")
	}
	defer secret.Wipe(value)
	if len(bytes.TrimSpace(value)) == 0 {
		return nil, errors.New("credential is empty")
	}
	return secret.NewFrom(bytes.TrimSpace(value))
}
