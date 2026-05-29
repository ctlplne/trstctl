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

	"certctl.io/certctl/internal/ca"
	"certctl.io/certctl/internal/crypto"
	"certctl.io/certctl/internal/crypto/certinfo"
	"certctl.io/certctl/internal/events"
	"certctl.io/certctl/internal/notify"
	"certctl.io/certctl/internal/orchestrator"
	"certctl.io/certctl/internal/store"
)

// Certificate status values maintained on the inventory by the engine.
const (
	statusActive     = "active"
	statusSuperseded = "superseded"
	statusRevoked    = "revoked"
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
}

// Manager runs the certificate-lifecycle automation over the inventory and the
// platform rails.
type Manager struct {
	store    *store.Store
	issuance *ca.IssuanceService
	outbox   *orchestrator.Outbox
	idem     *orchestrator.Idempotency
	log      *events.Log
	cfg      Config
	keyAlg   crypto.Algorithm
	now      func() time.Time
}

// NewManager wires a lifecycle Manager over the store, issuance service, outbox,
// idempotency, and event log.
func NewManager(s *store.Store, issuance *ca.IssuanceService, ob *orchestrator.Outbox, idem *orchestrator.Idempotency, log *events.Log, cfg Config) *Manager {
	return &Manager{
		store: s, issuance: issuance, outbox: ob, idem: idem, log: log, cfg: cfg,
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
	}

	now := m.now()
	var newID string
	if err := m.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		id, err := m.store.InsertSuccessorCertificateTx(ctx, tx, successor, old.ID)
		if err != nil {
			return err
		}
		newID = id
		return m.store.SupersedeCertificateTx(ctx, tx, tenantID, old.ID, now)
	}); err != nil {
		return store.Certificate{}, err
	}

	if err := m.emit(ctx, tenantID, eventType, map[string]any{
		"certificate_id": old.ID, "successor_id": newID,
		"old_serial": old.Serial, "new_serial": info.SerialNumber,
	}); err != nil {
		return store.Certificate{}, err
	}

	successor.ID = newID
	successor.Status = statusActive
	replaces := old.ID
	successor.ReplacesID = &replaces
	return successor, nil
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
		if err := m.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			if err := m.store.RevokeCertificateTx(ctx, tx, tenantID, certID, reason, now); err != nil {
				return err
			}
			_, err := m.outbox.Enqueue(ctx, tx, orchestrator.Entry{
				TenantID: tenantID, Destination: destinationRevoke, IdempotencyKey: key, Payload: payload,
			})
			return err
		}); err != nil {
			return nil, err
		}
		if err := m.emit(ctx, tenantID, "certificate.revoked", map[string]any{
			"certificate_id": certID, "serial": old.Serial, "reason": reason,
		}); err != nil {
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
		payload, err := json.Marshal(notify.Alert{
			Kind: notify.KindCertificateExpiry, TenantID: tenantID, CertificateID: c.ID,
			Subject: c.Subject, Serial: c.Serial, NotAfter: na,
			Detail: "certificate expiring within the alert window",
		})
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
