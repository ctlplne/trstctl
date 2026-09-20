// SPDX-License-Identifier: BUSL-1.1

package reconcile

import (
	"context"
	"fmt"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/reconcile/canon/reducers"
	corestore "trstctl.com/trstctl/internal/store"
)

// Store-backed authority adapters (epic C4).
//
// Until C4 every reducer in the runtime was registered with a nil source, so a
// scheduled round had no durable external source: observation failed closed,
// the round errored, and "collecting" reported the schedule count while nothing
// was ever read. These two adapters make the first pair of authorities real,
// from state the control plane already keeps durably under RLS (AN-1):
//
//   - "trstctl-self":  the certificate INVENTORY's view (the certificates read
//     model — what the platform believes exists),
//   - "trstctl-ca":    the internal CA issuance LEDGER's view (ca_issued_certs —
//     what the CA recorded issuing, and what it revoked).
//
// The two are written by different paths for different reasons, which is what
// makes reconciling them meaningful: a serial in the ledger but not the
// inventory is a lost or never-projected record; a serial in the inventory
// claiming an internal CA issued it, with no ledger row, is exactly the shape
// of a rogue or out-of-band issuance.
//
// JURISDICTION. Both adapters observe the same universe: certificates issued by
// the tenant's internal CAs (identified by the CA certificates' subject names).
// The inventory also knows external-CA and scanner-discovered certificates; the
// ledger never claimed to know those, so including them would flag every
// DigiCert cert as "presence divergence" — false alarms that bury real drift.
// A comparison is only honest over claims both authorities actually make.
//
// SHARED ASSERTION VOCABULARY. For the same reason, the canonical record each
// adapter emits carries only what BOTH authorities can assert about a
// certificate: its identity (issuer name DER + serial) and its revocation
// standing (active vs revoked). The ledger records neither validity windows nor
// subjects nor key algorithms, so putting the inventory's richer view of those
// into the canonical record would turn every shared certificate into an
// attribute conflict about fields only one side ever claimed. Those fields
// remain served by the inventory read model; they are not cross-authority
// claims here.

const storeSourcePageSize = 500

// storeInventorySource is the "trstctl-self" authority: the certificate
// inventory's claims, scoped to the internal-CA jurisdiction.
type storeInventorySource struct {
	store *corestore.Store
}

func newStoreInventorySource(store *corestore.Store) *storeInventorySource {
	return &storeInventorySource{store: store}
}

func (s *storeInventorySource) SelfSnapshot(ctx context.Context, tenantID string) (reducers.SelfSnapshot, error) {
	if s == nil || s.store == nil {
		return reducers.SelfSnapshot{}, reducers.ErrMissingSource
	}
	issuers, err := internalCAIssuers(ctx, s.store, tenantID)
	if err != nil {
		return reducers.SelfSnapshot{}, err
	}
	now := time.Now().UTC()
	snap := reducers.SelfSnapshot{Watermark: storeWatermark("inventory", now)}
	afterID := corestore.ZeroUUID
	for {
		page, err := s.store.ListCertificatesPage(ctx, tenantID, afterID, nil, storeSourcePageSize, nil)
		if err != nil {
			return reducers.SelfSnapshot{}, fmt.Errorf("xrec inventory source: %w", err)
		}
		for _, row := range page {
			if len(row.CertificateDER) == 0 {
				// A row without captured DER (some scanner and import paths
				// record metadata only) has no issuer NAME bytes to derive the
				// cross-authority identity from. It cannot participate in this
				// comparison; it still exists in the inventory read model.
				continue
			}
			issuerDER, serialHex, err := crypto.CertificateIssuerAndSerial(row.CertificateDER)
			if err != nil {
				// Stored bytes that no longer parse are an inventory data
				// problem, not a reconciliation claim; refusing the whole
				// observation for one bad row would silence the comparison.
				continue
			}
			if _, ok := issuers[string(issuerDER)]; !ok {
				// Outside the internal-CA jurisdiction (external CA, scan of a
				// foreign cert). The ledger makes no claim about it.
				continue
			}
			status := canonStatusActive
			if row.RevokedAt != nil || row.Status == "revoked" {
				status = canonStatusRevoked
			}
			snap.Certificates = append(snap.Certificates, reducers.SelfCertificate{
				IssuerNameDER: issuerDER,
				SerialHex:     serialHex,
				Status:        status,
				NativeID:      row.Fingerprint,
			})
		}
		if len(page) < storeSourcePageSize {
			return snap, nil
		}
		afterID = page[len(page)-1].ID
	}
}

// storeCALedgerSource is the "trstctl-ca" authority: the internal CA issuance
// ledger's claims, one record per issued serial with its revocation standing.
type storeCALedgerSource struct {
	store *corestore.Store
}

func newStoreCALedgerSource(store *corestore.Store) *storeCALedgerSource {
	return &storeCALedgerSource{store: store}
}

func (s *storeCALedgerSource) SelfSnapshot(ctx context.Context, tenantID string) (reducers.SelfSnapshot, error) {
	if s == nil || s.store == nil {
		return reducers.SelfSnapshot{}, reducers.ErrMissingSource
	}
	subjects, err := internalCASubjectsByID(ctx, s.store, tenantID)
	if err != nil {
		return reducers.SelfSnapshot{}, err
	}
	issued, err := s.store.ListIssuedCerts(ctx, tenantID)
	if err != nil {
		return reducers.SelfSnapshot{}, fmt.Errorf("xrec ca ledger source: %w", err)
	}
	now := time.Now().UTC()
	snap := reducers.SelfSnapshot{Watermark: storeWatermark("ca-ledger", now)}
	for _, row := range issued {
		subject, ok := subjects[row.CAID]
		if !ok {
			// A ledger row for a CA the authorities table no longer knows has
			// no issuer name to derive the shared identity from. It cannot be
			// compared; the CA lifecycle surfaces deleted CAs elsewhere.
			continue
		}
		status := canonStatusActive
		if row.RevokedAt != nil {
			status = canonStatusRevoked
		}
		snap.Certificates = append(snap.Certificates, reducers.SelfCertificate{
			IssuerNameDER: append([]byte(nil), subject...),
			SerialHex:     row.Serial,
			Status:        status,
			NativeID:      row.CAID + "/" + row.Serial,
		})
	}
	return snap, nil
}

const (
	canonStatusActive  = "active"
	canonStatusRevoked = "revoked"
)

// internalCASubjectsByID maps each internal CA's id to its certificate's raw
// subject name (DER) — the issuer name every certificate it signs carries.
func internalCASubjectsByID(ctx context.Context, store *corestore.Store, tenantID string) (map[string][]byte, error) {
	cas, err := store.ListCAAuthorities(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("xrec store source: list CAs: %w", err)
	}
	out := make(map[string][]byte, len(cas))
	for _, ca := range cas {
		subject, err := crypto.CertificateSubjectNameDERFromPEM([]byte(ca.CertificatePEM))
		if err != nil {
			// A CA row whose stored PEM does not parse cannot anchor identities.
			// Its issued certs are skipped by the same rule in both adapters,
			// so a broken CA row cannot manufacture one-sided divergence.
			continue
		}
		out[ca.ID] = subject
	}
	return out, nil
}

// internalCAIssuers is the same set keyed by the subject bytes themselves, for
// jurisdiction checks against parsed leaf certificates.
func internalCAIssuers(ctx context.Context, store *corestore.Store, tenantID string) (map[string]struct{}, error) {
	byID, err := internalCASubjectsByID(ctx, store, tenantID)
	if err != nil {
		return nil, err
	}
	out := make(map[string]struct{}, len(byID))
	for _, subject := range byID {
		out[string(subject)] = struct{}{}
	}
	return out, nil
}

// storeWatermark stamps an observation with its read time. Both adapters read
// their full state on every observation (poll mode), so freshness is the read
// itself; a position that advances every read keeps a healthy-but-quiet tenant
// from tripping the staleness class, which exists for FEEDS that stop moving.
func storeWatermark(prefix string, now time.Time) reducers.Watermark {
	return reducers.Watermark{
		Mode:       reducers.ModePoll,
		Position:   prefix + "@" + now.Format(time.RFC3339Nano),
		ObservedAt: now,
	}
}
