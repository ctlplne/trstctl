// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// handleRogueCertificateRevocation revokes one CT-found certificate at the
// authority its retained request names (A163). The retained event authorizes
// this exact effect; the authority must still be one the tenant may use and
// that revokes by serial; the finding is recorded revoked at the issuer only
// after the authority confirms. A retry after the confirmation was recorded
// calls the authority no second time.
func (d *issuanceDispatcher) handleRogueCertificateRevocation(ctx context.Context, m orchestrator.Message, cmd store.RogueCertificateRevocationCommand) error {
	if d.log == nil || d.orch == nil {
		return errors.New("server: rogue certificate revocation is not configured")
	}
	event, found, err := d.log.EventByID(ctx, cmd.RogueEventID)
	if err != nil {
		return err
	}
	if !found || event.TenantID != m.TenantID || event.Type != projections.EventRogueCertificateRevocationRequested {
		return errors.New("server: rogue certificate revocation has no retained request for this tenant")
	}
	var requested projections.RogueCertificateRevocationRequested
	if json.Unmarshal(event.Data, &requested) != nil || requested.DiscoveryID != cmd.DiscoveryID || requested.AuthorityID != cmd.AuthorityID ||
		requested.Serial != cmd.Serial || requested.Reason != cmd.Reason {
		return errors.New("server: rogue certificate revocation differs from its retained request")
	}
	resultID := "rogue.revoked-at-issuer:" + crypto.SHA256Hex([]byte(m.TenantID+"\x00"+cmd.RogueEventID))
	result := projections.RogueCertificateRevokedAtIssuer{
		DiscoveryID: requested.DiscoveryID, AuthorityID: requested.AuthorityID,
		RequestEventID: cmd.RogueEventID, Serial: requested.Serial,
	}
	if _, recorded, err := d.log.EventByID(ctx, resultID); err != nil {
		return err
	} else if recorded {
		return d.orch.RecordRogueCertificateRevokedAtIssuer(ctx, m.TenantID, resultID, result)
	}
	if d.externalCAs == nil {
		return errors.New("server: the rogue certificate's authority is unavailable")
	}
	entry, ok := d.externalCAs.byID[requested.AuthorityID]
	if !ok || entry.tenantID != "" && entry.tenantID != m.TenantID || !ca.RevokesBySerial(strings.ToLower(entry.meta.Type)) || !entry.canRevoke() {
		return errors.New("server: the named authority is not one this tenant can revoke a serial at")
	}
	if err := ca.RevokeThrough(ctx, entry.revocationCA, ca.RevokeRequest{
		TenantID: m.TenantID, Serial: requested.Serial, ReasonCode: requested.ReasonCode,
	}); err != nil {
		return fmt.Errorf("server: the authority did not confirm the rogue certificate's revocation: %s", externalCAUpstreamDetail(err))
	}
	return d.orch.RecordRogueCertificateRevokedAtIssuer(ctx, m.TenantID, resultID, result)
}
