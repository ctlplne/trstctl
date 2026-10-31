// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// ADCSRevocationRelay names the enrolled domain-joined network relay that
// revokes an adcs issuer's certificates with certutil, and the certsrv CA it
// revokes at (A162). Zero means trstctl does not revoke at that AD CS.
type ADCSRevocationRelay struct {
	CAConfig string
	Relay    string
}

// adcsRevokeRecheck is how soon a revocation waiting for its relay looks again.
const adcsRevokeRecheck = 15 * time.Second

// revokeThroughADCSRelay hands one external revocation to the adcs issuer's
// relay. It returns nil once that relay's checked report closed the job, and
// the caller records the revocation. Until then the outbox delivery pauses
// without spending its retry budget; a failed relay attempt spends one, and
// the delivery queues a fresh attempt for the relay.
func (d *issuanceDispatcher) revokeThroughADCSRelay(ctx context.Context, tenantID string, route ADCSRevocationRelay,
	cert store.Certificate, reason, revocationID string) error {
	code := crypto.CRLReasonCode(crypto.RevocationReason(reason))
	if !relay.ADCSRevocationReason(code) {
		return fmt.Errorf("server: certutil cannot revoke with reason %s; AD CS takes unspecified through cessationOfOperation", reason)
	}
	intent := relay.ADCSRevokeIntent{
		ID: revocationID, CAConfig: route.CAConfig, Serial: strings.ToLower(strings.ReplaceAll(cert.Serial, ":", "")),
		ReasonCode: code, RequiredAgentID: agentRowID(tenantID, route.Relay),
	}
	if err := relay.ValidateADCSRevokeIntent(intent); err != nil {
		return err
	}
	if d.store == nil || d.outbox == nil {
		return errors.New("server: AD CS relay revocation needs the store and outbox")
	}
	state, err := d.store.ADCSRelayRevocationState(ctx, tenantID, revocationID)
	if err != nil {
		return err
	}
	if state.Delivered {
		return nil
	}
	if state.Pending {
		return orchestrator.DeferDeliveryUntil(fmt.Errorf("server: AD CS revocation is waiting for relay %s to report", route.Relay),
			time.Now().Add(adcsRevokeRecheck))
	}
	payload, err := json.Marshal(intent)
	if err != nil {
		return err
	}
	if err := d.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := d.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{
			TenantID: tenantID, Destination: relay.KindADCSRevoke,
			IdempotencyKey:    "adcs-revoke:" + revocationID + ":" + strconv.Itoa(state.Failed),
			Payload:           payload,
			RequiredAgentRole: mtls.AgentRoleNetwork, RequiredAgentID: intent.RequiredAgentID,
		})
		return err
	}); err != nil {
		return err
	}
	if state.Failed > 0 {
		return fmt.Errorf("server: AD CS relay %s could not revoke the certificate (%s); queued another attempt", route.Relay, state.LastError)
	}
	return orchestrator.DeferDeliveryUntil(fmt.Errorf("server: AD CS revocation queued for relay %s", route.Relay),
		time.Now().Add(adcsRevokeRecheck))
}

// validateADCSRevokeResult checks a relay's AD CS revocation report against the
// queued job before the job closes (A162): the exact issuer relay, the same
// certificate, CA and reason, read back as revoked, with a new CRL published.
// The revocation itself is recorded by the outbox delivery that queued it.
func validateADCSRevokeResult(tenantID, agentName string, payload []byte, detail string) error {
	var intent relay.ADCSRevokeIntent
	if err := decodeStrictJSON(payload, &intent); err != nil {
		return fmt.Errorf("server: decode durable AD CS revocation: %w", err)
	}
	if intent.RequiredAgentID == "" || intent.RequiredAgentID != agentRowID(tenantID, agentName) {
		return errors.New("server: an AD CS revocation result requires the issuer's exact relay")
	}
	if len(detail) > maxStructuredSyncReportBytes {
		return fmt.Errorf("server: AD CS revocation report exceeds the %d-byte bound", maxStructuredSyncReportBytes)
	}
	var report relay.ADCSRevokeReport
	if err := decodeStrictJSON([]byte(detail), &report); err != nil {
		return fmt.Errorf("server: decode AD CS revocation report: %w", err)
	}
	return relay.ValidateADCSRevokeReport(intent, report)
}

// externalRevocationID names one lifecycle revocation of one certificate for
// an issuer that records it later (A162): stable across outbox retries of the
// same command.
func externalRevocationID(tenantID, commandKey, fingerprint string) string {
	return "certificate.external-revoked:" + crypto.SHA256Hex([]byte(tenantID+"\x00"+commandKey+"\x00"+fingerprint))
}
