// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// revokeProtocolLeafAtUpstream revokes a protocol-issued leaf that an upstream
// CA issued (a profile's upstream_external_ca, A159) at that CA (A162-L4). The
// protocol already authorized the request (for ACME, RFC 8555 §7.6 account or
// certificate key), so this queues the same exact external revocation the bulk
// API queues for an operator: one retained batch item for the certificate's
// verified issuer, delivered through the outbox to that CA or its revocation
// relay, recorded revoked only once the CA confirms. It reports false for a
// leaf trstctl's served CA issued, which the caller revokes locally, and an
// error wrapping orchestrator.ErrCertificateRevocationUnsupported for an
// upstream that cannot revoke.
func (s *Server) revokeProtocolLeafAtUpstream(ctx context.Context, tenantID, protocolName, fingerprint, reason string) (bool, error) {
	dispatcher, ok := s.obHandler.(*issuanceDispatcher)
	if !ok || dispatcher.externalCAs == nil || s.store == nil {
		return false, nil
	}
	certificate, err := s.store.GetCertificateByFingerprint(ctx, tenantID, fingerprint)
	if store.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	origins, err := dispatcher.certificateRevocationOrigins(ctx, tenantID, []store.Certificate{certificate})
	if err != nil {
		return false, err
	}
	if origins[certificate.Fingerprint].ExternalID == "" {
		return false, nil
	}
	binding, err := json.Marshal(struct {
		Domain      string `json:"domain"`
		Protocol    string `json:"protocol"`
		TenantID    string `json:"tenant_id"`
		Fingerprint string `json:"fingerprint"`
		Reason      string `json:"reason"`
	}{"trstctl.protocol.upstream-revocation.v1", protocolName, tenantID, fingerprint, reason})
	if err != nil {
		return true, err
	}
	result, err := s.orch.BulkRevokeCertificates(ctx, tenantID, "protocol-upstream-revoke:"+protocolName+":"+fingerprint,
		crypto.SHA256Hex(binding), []string{certificate.ID}, reason, orchestrator.CertificateRevocationChecks{
			Authority: s.certificateRevocationAuthority,
			// The protocol's own wire-level authorization is the authority
			// here, as for a leaf trstctl's CA revokes.
			Authorize: func(context.Context, store.Certificate) error { return nil },
		})
	if err != nil {
		return true, err
	}
	if len(result.Items) != 1 {
		return true, fmt.Errorf("server: upstream revocation answered %d items for one certificate", len(result.Items))
	}
	switch item := result.Items[0]; item.Status {
	case "queued", "revoked":
		return true, nil
	case "failed":
		if item.Error == orchestrator.ErrCertificateRevocationUnsupported.Error() {
			return true, fmt.Errorf("%w: its upstream CA is configured without a way to revoke", orchestrator.ErrCertificateRevocationUnsupported)
		}
		return true, errors.New("server: the upstream revocation failed: " + item.Error)
	default:
		return true, fmt.Errorf("server: the upstream revocation was %s: %s", item.Status, item.Error)
	}
}
