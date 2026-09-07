// SPDX-License-Identifier: MPL-2.0

// Package lifecycle automates a certificate's lifecycle (F6): renewal at a
// configurable threshold, revocation, rotation, and expiration alerting. It is a
// thin coordinator over the platform's existing rails — it issues replacements
// through ca.IssuanceService (so every mint is idempotent (AN-5) and recorded in
// the outbox (AN-6)), records revocation and alert intents on the outbox in the
// same transaction as the inventory state change (AN-6), and emits a lifecycle
// event for the audit trail (AN-2). CSRs for replacements are built through the
// crypto boundary (AN-3), with the ephemeral subject key held in a locked buffer
// and destroyed immediately (AN-8); this package names no crypto/* itself.
//
// Renewal timing here is a fixed threshold. RFC 9773 ARI (S4.17) will later
// refine it so renewals follow the CA's advertised window; the threshold scan is
// the seam that consumes those windows.
package lifecycle

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/custody"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// Outbox destination for revocation propagation (shared with the lifecycle state
// machine's side-effect map, S3.2).
const destinationRevoke = "revocation.publish"

// Config sets the renewal and alert thresholds and the lifetime of issued
// replacements.
type Config struct {
	RenewBefore time.Duration // renew certificates expiring within this window
	AlertBefore time.Duration // alert on certificates expiring within this window
	TTL         time.Duration // lifetime requested for renewed/rotated certificates
	// LeafValidity is the reference leaf lifetime the CA calendar measures a
	// parent authority's remaining horizon against (H5). It is a yardstick for
	// "can this parent still issue a full-length leaf", not a limit on issuance.
	// Zero means DefaultLeafValidity.
	LeafValidity time.Duration
}

// Manager runs the certificate-lifecycle automation over the inventory and the
// platform rails.
type Manager struct {
	store    *store.Store
	issuance *ca.IssuanceService
	outbox   *orchestrator.Outbox
	idem     *orchestrator.Idempotency
	orch     *orchestrator.Orchestrator
	log      *events.Log
	cfg      Config
	keyAlg   crypto.Algorithm
	now      func() time.Time
}

// NewManager wires a lifecycle Manager over the store, issuance service, outbox,
// idempotency, and event log. It builds an Orchestrator over the same rails so its
// inventory transitions (successor recorded, predecessor superseded, revoked) are
// event-sourced and projected — the read model is written only by the projector
// (AN-2), so a Rebuild() reconstructs them rather than losing a direct write
// (CORRECT-002).
func NewManager(s *store.Store, issuance *ca.IssuanceService, ob *orchestrator.Outbox, idem *orchestrator.Idempotency, log *events.Log, cfg Config) *Manager {
	return &Manager{
		store: s, issuance: issuance, outbox: ob, idem: idem,
		orch: orchestrator.NewOrchestrator(log, s, ob),
		log:  log, cfg: cfg,
		keyAlg: crypto.ECDSAP256,
		now:    time.Now,
	}
}

// RenewExpiring renews every active certificate whose expiry falls within the
// renewal threshold: it scans the inventory, then renews each. Returns how many
// were renewed. Idempotent across runs — a renewed certificate is marked
// superseded and so is not picked up again.
func (m *Manager) RenewExpiring(ctx context.Context, tenantID string) (int, error) {
	cutoff := m.now().Add(m.cfg.RenewBefore)
	certs, err := m.store.ListExpiringActiveCertificates(ctx, tenantID, cutoff)
	if err != nil {
		return 0, err
	}
	renewed := 0
	for _, c := range certs {
		if _, err := m.renew(ctx, tenantID, c, "renew:"+c.ID, "certificate.renewed"); err != nil {
			return renewed, err
		}
		renewed++
	}
	return renewed, nil
}

// Rotate produces a new credential for the certificate identified by certID and
// retires the old one, returning the successor. idempotencyKey makes the
// underlying issuance safe to retry.
func (m *Manager) Rotate(ctx context.Context, tenantID, certID, idempotencyKey string) (store.Certificate, error) {
	old, err := m.store.GetCertificate(ctx, tenantID, certID)
	if err != nil {
		return store.Certificate{}, err
	}
	return m.renew(ctx, tenantID, old, "rotate:"+idempotencyKey, "certificate.rotated")
}

// renew issues a replacement for old (same subject and SANs), links it as the
// successor, retires old, and emits eventType. The mint is idempotent on
// issueKey; the inventory writes commit in one transaction; re-running converges.
func (m *Manager) renew(ctx context.Context, tenantID string, old store.Certificate, issueKey, eventType string) (store.Certificate, error) {
	commonName := old.Subject
	if len(old.SANs) > 0 {
		commonName = old.SANs[0]
	}
	csr, err := m.buildCSR(commonName, old.SANs)
	if err != nil {
		return store.Certificate{}, fmt.Errorf("lifecycle: build successor csr: %w", err)
	}
	issued, err := m.issuance.Issue(ctx, ca.IssueRequest{TenantID: tenantID, CSR: csr, DNSNames: old.SANs, TTL: m.cfg.TTL}, issueKey)
	if err != nil {
		return store.Certificate{}, fmt.Errorf("lifecycle: issue successor: %w", err)
	}
	info, err := certinfo.Inspect(issued.CertificatePEM)
	if err != nil {
		return store.Certificate{}, fmt.Errorf("lifecycle: inspect successor: %w", err)
	}
	nb, na := info.NotBefore, info.NotAfter
	successor := store.Certificate{
		TenantID: tenantID, OwnerID: old.OwnerID, Subject: info.Subject, SANs: info.DNSNames,
		Issuer: info.Issuer, Serial: info.SerialNumber, Fingerprint: info.SHA256Fingerprint,
		KeyAlgorithm: info.KeyAlgorithm, NotBefore: &nb, NotAfter: &na, Source: "lifecycle",
		// B5: automated renewal builds its own CSR here (buildCSR), so the key
		// was made by the control plane, held in locked memory, and destroyed.
		// Recording that on the successor is the point: a fleet whose renewals
		// all read control_plane is a fleet that has not moved to host-executed
		// renewal yet, and that is a question an operator should be able to ask
		// of their inventory rather than of the source.
		KeyOrigin:  string(custody.OriginControlPlane),
		KeyStorage: string(custody.StorageLockedMemory),
	}

	// Record the successor and retire the predecessor through event-sourced
	// projection semantics: the certificate.recorded event carries replaces_id,
	// and the projector inserts the successor plus supersedes the predecessor in
	// one tenant-scoped transaction. The later lifecycle event is audit history,
	// not a second read-model mutation dependency.
	recorded, err := m.orch.RecordSuccessorCertificate(ctx, tenantID, successor, old.ID)
	if err != nil {
		return store.Certificate{}, fmt.Errorf("lifecycle: record successor: %w", err)
	}

	if err := m.emit(ctx, tenantID, eventType, map[string]any{
		"certificate_id": old.ID, "successor_id": recorded.ID,
		"old_serial": old.Serial, "new_serial": info.SerialNumber,
	}); err != nil {
		return store.Certificate{}, err
	}

	return recorded, nil
}

// Revoke marks a certificate revoked and enqueues a revocation.publish intent on
// the outbox (AN-6), so revocation propagates downstream. idempotencyKey makes a
// retried revoke a no-op rather than a second propagation (AN-5).
func (m *Manager) Revoke(ctx context.Context, tenantID, certID, reason, idempotencyKey string) error {
	old, err := m.store.GetCertificate(ctx, tenantID, certID)
	if err != nil {
		return err
	}
	key := "revoke:" + idempotencyKey
	now := m.now()
	_, err = m.idem.Do(ctx, tenantID, key, func(ctx context.Context) ([]byte, error) {
		payload, err := json.Marshal(struct {
			Serial string `json:"serial"`
			Reason string `json:"reason"`
		}{old.Serial, reason})
		if err != nil {
			return nil, err
		}
		// Enqueue the revocation.publish side effect on the outbox (AN-6) so the
		// revocation propagates downstream. The enqueue runs in its own tenant-scoped
		// transaction; exactly-once is guaranteed by the surrounding idempotency
		// wrapper (AN-5).
		if err := m.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			_, err := m.outbox.Enqueue(ctx, tx, orchestrator.Entry{
				TenantID: tenantID, Destination: destinationRevoke, IdempotencyKey: key, Payload: payload,
			})
			return err
		}); err != nil {
			return nil, err
		}
		// Flip the inventory status through a projected certificate.revoked event
		// (CORRECT-002): the read model is written only by the projector (AN-2), so
		// the revoked status survives a Rebuild() rather than being a lost direct
		// UPDATE. Keyed by fingerprint, the projection is idempotent, so a redelivery
		// re-applies the same revoked state harmlessly.
		if err := m.orch.RevokeCertificate(ctx, tenantID, old.Fingerprint, old.Serial, reason, now); err != nil {
			return nil, err
		}
		return []byte("revoked"), nil
	})
	return err
}

// AlertExpiring raises an expiration alert on the notification surface for every
// active certificate expiring within the alert window that has not yet been
// alerted, stamping each so it is alerted at most once. Returns how many alerts
// were raised.
func (m *Manager) AlertExpiring(ctx context.Context, tenantID string) (int, error) {
	now := m.now()
	certs, err := m.store.ListAlertableCertificates(ctx, tenantID, now, now.Add(m.cfg.AlertBefore))
	if err != nil {
		return 0, err
	}
	alerted := 0
	for _, c := range certs {
		var na time.Time
		if c.NotAfter != nil {
			na = *c.NotAfter
		}
		ownerID := certificateOwnerID(c)
		if ownerID == "" {
			// DP2-020: a certificate discovery observed carries no owner of its own; once
			// its finding is claimed into a managed identity, that identity's current
			// owner is the one to alert.
			viaClaim, err := m.store.CertificateOwnerIDViaClaim(ctx, tenantID, c.Fingerprint)
			if err != nil {
				return alerted, err
			}
			ownerID = viaClaim
		}
		alertContext, err := m.store.CertificateAlertContextForOwner(ctx, tenantID, ownerID)
		if err != nil {
			return alerted, err
		}
		thresholdDays := expiryThresholdDays(now, na)
		alert := notify.Alert{
			Kind: notify.KindCertificateExpiry, TenantID: tenantID, CertificateID: c.ID,
			Subject: c.Subject, Serial: c.Serial, NotAfter: na,
			Detail:               "certificate expiring within the alert window",
			Severity:             expirySeverity(thresholdDays),
			ThresholdDays:        &thresholdDays,
			EscalationRecipients: alertRecipients(alertContext),
		}
		if alertContext.Owner != nil {
			alert.OwnerID = alertContext.Owner.ID
			alert.OwnerName = alertContext.Owner.Name
			alert.OwnerEmail = alertContext.Owner.Email
		}
		payload, err := json.Marshal(alert)
		if err != nil {
			return alerted, err
		}
		if err := m.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			if _, err := m.outbox.Enqueue(ctx, tx, orchestrator.Entry{
				TenantID: tenantID, Destination: notify.DestinationExpiry, IdempotencyKey: "expiry:" + c.ID, Payload: payload,
			}); err != nil {
				return err
			}
			return m.store.MarkCertificateAlertedTx(ctx, tx, tenantID, c.ID, now)
		}); err != nil {
			return alerted, err
		}
		if err := m.emit(ctx, tenantID, "certificate.expiring", map[string]any{
			"certificate_id": c.ID, "serial": c.Serial, "not_after": na,
		}); err != nil {
			return alerted, err
		}
		alerted++
	}
	return alerted, nil
}

func certificateOwnerID(c store.Certificate) string {
	if c.OwnerID == nil {
		return ""
	}
	return *c.OwnerID
}

func expiryThresholdDays(now, notAfter time.Time) int {
	if notAfter.IsZero() {
		return 0
	}
	remaining := notAfter.Sub(now)
	if remaining <= 0 {
		return 0
	}
	const day = 24 * time.Hour
	days := int(remaining / day)
	if remaining%day != 0 {
		days++
	}
	return days
}

func expirySeverity(days int) string {
	switch {
	case days <= 7:
		return notify.AlertSeverityCritical
	case days <= 30:
		return notify.AlertSeverityWarning
	default:
		return notify.AlertSeverityLow
	}
}

func alertRecipients(ctx store.CertificateAlertContext) []notify.AlertRecipient {
	recipients := make([]notify.AlertRecipient, 0, 1+len(ctx.Approvers))
	seen := map[string]bool{}
	if ctx.Owner != nil {
		recipient := notify.AlertRecipient{
			Kind:        "owner",
			Subject:     ctx.Owner.ID,
			DisplayName: ctx.Owner.Name,
			Email:       ctx.Owner.Email,
		}
		recipients = append(recipients, recipient)
		seen[recipientKey(recipient)] = true
	}
	for _, approver := range ctx.Approvers {
		recipient := notify.AlertRecipient{
			Kind:        "approver",
			Subject:     approver.Subject,
			DisplayName: approver.DisplayName,
			Email:       approver.Email,
			Roles:       append([]string(nil), approver.Roles...),
		}
		key := recipientKey(recipient)
		if seen[key] {
			continue
		}
		seen[key] = true
		recipients = append(recipients, recipient)
	}
	return recipients
}

func recipientKey(r notify.AlertRecipient) string {
	return r.Kind + "\x00" + r.Subject + "\x00" + r.Email
}

// buildCSR generates an ephemeral subject key in a locked buffer (AN-8), builds a
// PKCS#10 CSR through the crypto boundary (AN-3), and destroys the key. The
// private key is never persisted; only the issued certificate is inventoried.
func (m *Manager) buildCSR(commonName string, sans []string) ([]byte, error) {
	key, err := crypto.GenerateLockedKey(m.keyAlg)
	if err != nil {
		return nil, err
	}
	defer key.Destroy()
	return crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: commonName, DNSNames: sans}, key)
}

// emit appends a lifecycle event to the log for the audit trail (AN-2).
func (m *Manager) emit(ctx context.Context, tenantID, eventType string, data map[string]any) error {
	payload, err := json.Marshal(data)
	if err != nil {
		return err
	}
	_, err = m.log.Append(ctx, events.Event{Type: eventType, TenantID: tenantID, Data: payload})
	return err
}
