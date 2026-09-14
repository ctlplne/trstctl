// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/custody"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// A certificate.recorded event proves signing finished, not that the requested
// deployment was queued. Resume that remaining phase with the original sealed
// subject and public chain. This path never invokes a CA or generates a key.
func (d *issuanceDispatcher) completeRecordedFirstLeaf(ctx context.Context, m orchestrator.Message, p transitionTrigger, cert store.Certificate) error {
	ident, err := d.store.GetIdentity(ctx, m.TenantID, p.IdentityID)
	if err != nil {
		return fmt.Errorf("server: load identity for recorded issuance recovery: %w", err)
	}
	connName, _ := deploymentRoutingAttrs(ident.Attributes)
	if ident.Status != string(orchestrator.StateIssued) || connName == "" || cert.KeyOrigin == string(custody.OriginRequester) {
		return nil
	}
	if cert.TenantID != m.TenantID || cert.IssuanceIdempotencyKey != "issue:"+m.IdempotencyKey ||
		cert.OwnerID == nil || *cert.OwnerID != ident.OwnerID ||
		cert.Status != "active" || cert.RevokedAt != nil || cert.NotAfter == nil || !cert.NotAfter.After(time.Now()) ||
		cert.KeyOrigin != string(custody.OriginControlPlane) || cert.KeyStorage != string(custody.StorageSealedStore) {
		return errors.New("server: recorded certificate is not eligible for retained-key deployment recovery")
	}
	if err := d.admitIssuance(ctx, m, p, ident, "issue"); err != nil {
		return err
	}
	selection, err := endpointIssuingAuthority(ident.Attributes)
	if err != nil {
		return err
	}
	subject, _, err := d.leafSubjectPreparation(ctx, m.TenantID, ident.OwnerID, ident.Name, []string{ident.Name}, selection, false)
	if err != nil {
		return err
	}
	key, err := secret.NewFrom(subject.KeyPEM)
	secret.Wipe(subject.KeyPEM)
	if err != nil {
		return err
	}
	defer key.Destroy()
	leaf, _ := pem.Decode(cert.CertificatePEM)
	if leaf == nil || leaf.Type != "CERTIFICATE" || !bytes.Equal(leaf.Bytes, cert.CertificateDER) {
		return errors.New("server: retained certificate chain does not match its recorded leaf")
	}
	if err := validateRequesterRenewalCSR(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: subject.CSRDER}), cert); err != nil {
		return fmt.Errorf("server: retained subject does not match recorded certificate: %w", err)
	}
	if err := crypto.VerifyCertKeyMatchPEM(cert.CertificatePEM, key.Bytes()); err != nil {
		return fmt.Errorf("server: retained deployment key does not match recorded certificate: %w", err)
	}
	return d.deployCredential(ctx, m.TenantID, ident, p.Reason, cert.CertificatePEM, key.Bytes(), cert.Fingerprint, false)
}

func recoverCertificatesByIssuanceKey(ctx context.Context, st *store.Store, log *events.Log, tenantID, key string) ([]store.Certificate, error) {
	certs, err := st.ListCertificatesByIssuanceIdempotencyKey(ctx, tenantID, key)
	if err != nil {
		return nil, err
	}
	if len(certs) > 0 || log == nil {
		return certs, nil
	}
	// Recovery asks one small question: did this exact issuance key already append
	// a certificate before its idempotency transaction rolled back? Rebuilding
	// every extension projection answers a much larger boot-time question and made
	// each ordinary issuance slower as retained history grew. Scan immutable event
	// envelopes, select only matching certificate events, and idempotently apply
	// those rows. Full catch-up remains the startup/tailer responsibility.
	var retained []events.Event
	if err := log.Replay(ctx, 0, func(event events.Event) error {
		if event.TenantID != tenantID || event.Type != projections.EventCertificateRecorded {
			return nil
		}
		var payload projections.CertificateRecorded
		if err := json.Unmarshal(event.Data, &payload); err != nil {
			return fmt.Errorf("server: decode retained certificate event %s: %w", event.ID, err)
		}
		if payload.IssuanceIdempotencyKey == key {
			retained = append(retained, event)
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("server: scan issued certificate recovery events: %w", err)
	}
	projector := projections.New(st)
	for _, event := range retained {
		if err := projector.Apply(ctx, event); err != nil {
			return nil, fmt.Errorf("server: recover issued certificate projection: %w", err)
		}
	}
	certs, err = st.ListCertificatesByIssuanceIdempotencyKey(ctx, tenantID, key)
	if err != nil {
		return nil, err
	}
	if len(retained) > 0 && len(certs) == 0 {
		// A completed receipt may intentionally prevent incremental replay from
		// recreating a missing row. Retained signing evidence must never become
		// permission to sign again; restore the read model before retrying.
		return nil, fmt.Errorf("%w: retained issuance has no recoverable certificate row", store.ErrCertificateRecordingRebuildRequired)
	}
	return certs, nil
}
