// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/ctlog"
	"trstctl.com/trstctl/internal/discovery/ctmonitor"
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
	kind := strings.ToLower(entry.meta.Type)
	if ok && (entry.tenantID == "" || entry.tenantID == m.TenantID) && ca.RevokesByCertificate(kind) && entry.canRevoke() {
		// N10: an ACME authority identifies the certificate by its bytes, which
		// trstctl never held: read them back from the CT log, then prove
		// control of every name before asking.
		revoker, isAuthorized := entry.revocationCA.(ca.AuthorizedRevoker)
		if !isAuthorized {
			return errors.New("server: the named authority cannot revoke a certificate trstctl did not request")
		}
		der, err := d.rogueCertificateFromCT(ctx, m.TenantID, requested)
		if err != nil {
			return err
		}
		if err := revoker.RevokeWithAuthorizations(ctx, m.TenantID, der, requested.ReasonCode); err != nil {
			return fmt.Errorf("server: the authority did not confirm the rogue certificate's revocation: %s", externalCAUpstreamDetail(err))
		}
		return d.orch.RecordRogueCertificateRevokedAtIssuer(ctx, m.TenantID, resultID, result)
	}
	if ok && (entry.tenantID == "" || entry.tenantID == m.TenantID) && entry.adcsRevocation.Relay != "" {
		// A163-L1: an AD CS authority revokes the serial through its
		// revocation relay, as an inventory certificate does (A162): certutil
		// revokes, publishes a CRL and reads the row back, and only that
		// checked report records the revocation. Until it reports, the delivery
		// waits without spending its retry budget.
		if err := d.revokeThroughADCSRelay(ctx, m.TenantID, entry.adcsRevocation, store.Certificate{Serial: requested.Serial},
			requested.Reason, resultID); err != nil {
			return err
		}
		return d.orch.RecordRogueCertificateRevokedAtIssuer(ctx, m.TenantID, resultID, result)
	}
	if !ok || entry.tenantID != "" && entry.tenantID != m.TenantID || !ca.RevokesBySerial(kind) || !entry.canRevoke() {
		return errors.New("server: the named authority is not one this tenant can revoke a serial at")
	}
	if err := ca.RevokeThrough(ctx, entry.revocationCA, ca.RevokeRequest{
		TenantID: m.TenantID, Serial: requested.Serial, ReasonCode: requested.ReasonCode,
	}); err != nil {
		return fmt.Errorf("server: the authority did not confirm the rogue certificate's revocation: %s", externalCAUpstreamDetail(err))
	}
	return d.orch.RecordRogueCertificateRevokedAtIssuer(ctx, m.TenantID, resultID, result)
}

// rogueCertificateFromCT reads a CT finding's certificate back from the log
// that recorded it (N10). The log must still be one of the finding's CT source
// logs, read through that source's own egress policy, and the entry must be the
// certificate the finding names: an issued certificate (a precertificate is not
// what an ACME authority revokes), with the finding's fingerprint and the
// request's serial. N10-L1: when the finding's entry is a precertificate, the
// issued certificate is the one another watched log recorded under the same
// issuer and serial, read back from that finding's own log the same way.
func (d *issuanceDispatcher) rogueCertificateFromCT(ctx context.Context, tenantID string,
	requested projections.RogueCertificateRevocationRequested) ([]byte, error) {
	finding, err := d.store.GetDiscoveryFinding(ctx, tenantID, requested.DiscoveryID)
	if err != nil {
		return nil, fmt.Errorf("server: load the CT finding: %w", err)
	}
	entry, err := d.ctFindingEntry(ctx, tenantID, finding)
	if err != nil {
		return nil, err
	}
	if !sameHex(entry.SerialHex, requested.Serial) {
		return nil, errors.New("server: the CT log entry is not the certificate the finding names")
	}
	if entry.Precert {
		return d.issuedCertificateForPrecert(ctx, tenantID, finding.ID, entry)
	}
	if !sameHex(entry.FingerprintSHA256, finding.Fingerprint) {
		return nil, errors.New("server: the CT log entry is not the certificate the finding names")
	}
	return entry.DER, nil
}

// ctFindingEntry reads the log entry a CT finding names, through its source's
// own logs and egress policy.
func (d *issuanceDispatcher) ctFindingEntry(ctx context.Context, tenantID string, finding store.DiscoveryFinding) (ctlog.Entry, error) {
	var meta struct {
		LogURL string `json:"log_url"`
		Index  *int64 `json:"index"`
	}
	if json.Unmarshal(finding.Metadata, &meta) != nil || meta.LogURL == "" || meta.Index == nil || *meta.Index < 0 {
		return ctlog.Entry{}, errors.New("server: the finding names no CT log position to read its certificate from")
	}
	source, err := d.store.GetDiscoverySource(ctx, tenantID, finding.SourceID)
	if err != nil {
		return ctlog.Entry{}, fmt.Errorf("server: load the finding's CT source: %w", err)
	}
	logs, _, _, client, err := ctLogDiscoverySettings(source.Config)
	if err != nil {
		return ctlog.Entry{}, fmt.Errorf("server: the finding's CT source: %w", err)
	}
	if !slices.Contains(logs, meta.LogURL) {
		return ctlog.Entry{}, errors.New("server: the finding's CT log is no longer one of its source's logs")
	}
	entries, err := ctmonitor.NewHTTPFetcherWithClient(client).Entries(ctx, meta.LogURL, *meta.Index, *meta.Index+1)
	if err != nil {
		return ctlog.Entry{}, fmt.Errorf("server: read the certificate from its CT log: %w", err)
	}
	if len(entries) != 1 || entries[0].Index != *meta.Index {
		return ctlog.Entry{}, errors.New("server: the CT log did not return the finding's entry")
	}
	return entries[0], nil
}

// maxPrecertCandidates bounds the findings a precertificate is matched against.
const maxPrecertCandidates = 20

// issuedCertificateForPrecert finds the issued certificate for a
// precertificate (N10-L1): another CT finding of the tenant's with the same
// serial whose own log entry is an issued certificate from the same issuer,
// with that finding's fingerprint.
func (d *issuanceDispatcher) issuedCertificateForPrecert(ctx context.Context, tenantID, findingID string, precert ctlog.Entry) ([]byte, error) {
	candidates, err := d.store.ListCTFindingsBySerial(ctx, tenantID, precert.SerialHex, findingID, maxPrecertCandidates)
	if err != nil {
		return nil, fmt.Errorf("server: look for the precertificate's issued certificate: %w", err)
	}
	for _, candidate := range candidates {
		entry, err := d.ctFindingEntry(ctx, tenantID, candidate)
		if err != nil || entry.Precert || entry.Issuer != precert.Issuer || !sameHex(entry.SerialHex, precert.SerialHex) ||
			!sameHex(entry.FingerprintSHA256, candidate.Fingerprint) {
			continue
		}
		return entry.DER, nil
	}
	return nil, errors.New("server: the CT log holds a precertificate at the finding's position, and no watched log has shown its issued certificate yet; an ACME authority revokes the issued certificate")
}

// sameHex compares two hex renderings of one number or digest, ignoring case,
// separators and leading zeros.
func sameHex(a, b string) bool {
	norm := func(v string) string {
		v = strings.ToLower(strings.NewReplacer(":", "", " ", "").Replace(strings.TrimSpace(v)))
		return strings.TrimLeft(v, "0")
	}
	return a != "" && b != "" && norm(a) == norm(b)
}
