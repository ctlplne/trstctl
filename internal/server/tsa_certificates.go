// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/store"
)

// A145: the timestamping authority's certificates are ordinary entries of the
// issuing CA's ledger. Every certificate the TSA signs under is registered as it
// is minted or loaded, so the CA's CRL and OCSP responder answer for it; an
// operator rotates the TSA onto a fresh signer-held key and certificate, revoking
// the outgoing one with a reason when it must no longer be trusted, or revokes a
// certificate rotated out earlier. Audit verification then checks the status of
// every TSA certificate an export's timestamps rely on.

// tsaCertificateState serializes rotation and revocation of the one TSA.
type tsaCertificateState struct {
	mu       sync.Mutex
	certFile string
}

var (
	errTSAActiveRevoke    = errors.New("the TSA still signs under this certificate; rotate it with a revocation reason instead")
	errTSARevocationStore = errors.New("TSA certificate management requires the event log and the store")
)

// activeTSAHandle names the signer handle holding the key of the certificate
// persisted at certFile: the handle it was registered with, or the original
// handle for a certificate registered before rotation existed.
func (s *Server) activeTSAHandle(ctx context.Context, tenantID, certFile string) string {
	if s.store == nil || certFile == "" {
		return tsaSignerHandle
	}
	certDER, found, err := readCertPEM(certFile)
	if err != nil || !found {
		return tsaSignerHandle
	}
	info, err := certinfo.Inspect(certDER)
	if err != nil {
		return tsaSignerHandle
	}
	certs, err := s.store.ListTSACertificates(ctx, tenantID)
	if err != nil {
		return tsaSignerHandle
	}
	for _, c := range certs {
		if c.Serial == info.SerialNumber {
			return c.Handle
		}
	}
	return tsaSignerHandle
}

// registerTSACertificate records certDER in the issuing CA's ledger under the
// TSA's tenant, once.
func (s *Server) registerTSACertificate(ctx context.Context, tenantID, handle string, certDER []byte) error {
	if s.store == nil || s.log == nil {
		return nil
	}
	info, err := certinfo.Inspect(certDER)
	if err != nil {
		return err
	}
	id := "tsa-certificate-" + crypto.SHA256Hex([]byte(tenantID+"\x00"+IssuingCAID()+"\x00"+info.SerialNumber))
	if _, found, err := s.log.EventByID(ctx, id); err != nil {
		return err
	} else if found {
		return nil
	}
	payload, err := json.Marshal(projections.TSACertificateRegistered{
		CAID: IssuingCAID(), Serial: info.SerialNumber, Handle: handle,
		NotBefore: info.NotBefore, NotAfter: info.NotAfter, CertDER: certDER,
	})
	if err != nil {
		return err
	}
	ev, err := s.log.Append(ctx, events.Event{ID: id, Type: projections.EventTSACertificateRegistered, TenantID: tenantID, Data: payload})
	if err != nil {
		return err
	}
	return projections.New(s.store).Apply(ctx, ev)
}

// revokeTSACertificateSerial records a TSA certificate's revocation and
// republishes the tenant's CRL so relying parties see it.
func (s *Server) revokeTSACertificateSerial(ctx context.Context, tenantID, serial string, reason crypto.RevocationReason) error {
	payload, err := json.Marshal(projections.TSACertificateRevoked{
		CAID: IssuingCAID(), Serial: serial, ReasonCode: crypto.CRLReasonCode(reason), RevokedAt: time.Now().UTC(),
	})
	if err != nil {
		return err
	}
	ev, err := s.log.Append(ctx, events.Event{Type: projections.EventTSACertificateRevoked, TenantID: tenantID, Data: payload})
	if err != nil {
		return err
	}
	if err := projections.New(s.store).Apply(ctx, ev); err != nil {
		return err
	}
	if s.revoc == nil {
		return errors.New("the TSA certificate is revoked, but this server publishes no CRL")
	}
	if _, err := s.revoc.generateCRLFromCurrentProjection(ctx, tenantID); err != nil {
		return fmt.Errorf("the TSA certificate is revoked; publish the CRL again: %w", err)
	}
	return nil
}

func (s *Server) tsaManagement(tenantID string) (*servedProtocols, error) {
	sp := s.protocols
	if sp == nil || sp.tsa == nil || sp.tsaTenant != tenantID {
		return nil, api.ErrTSANotServed
	}
	if s.store == nil || s.log == nil || sp.tsaState == nil {
		return nil, errTSARevocationStore
	}
	return sp, nil
}

// TSACertificates lists the TSA's certificates for its tenant, newest first.
func (s *Server) TSACertificates(ctx context.Context, tenantID string) (api.TSACertificateList, error) {
	sp, err := s.tsaManagement(tenantID)
	if err != nil {
		return api.TSACertificateList{}, err
	}
	certs, err := s.store.ListTSACertificates(ctx, tenantID)
	if err != nil {
		return api.TSACertificateList{}, err
	}
	active := sp.tsa.Certificate()
	activeInfo, err := certinfo.Inspect(active)
	if err != nil {
		return api.TSACertificateList{}, err
	}
	list := api.TSACertificateList{
		Items: make([]api.TSACertificate, 0, len(certs)),
		CRL:   "/crl/" + tenantID + ".crl", OCSP: "/ocsp/" + tenantID,
	}
	for _, c := range certs {
		list.Items = append(list.Items, tsaCertificateView(c, activeInfo.SerialNumber))
	}
	return list, nil
}

func tsaCertificateView(c store.TSACertificate, activeSerial string) api.TSACertificate {
	view := api.TSACertificate{
		Serial: c.Serial, NotBefore: c.NotBefore.UTC(), NotAfter: c.NotAfter.UTC(),
		CertSHA256: c.CertSHA256, CertPEM: string(crypto.EncodeCertificatePEM(c.CertDER)), State: "retired",
	}
	if c.Serial == activeSerial {
		view.State = "active"
	}
	if c.RevokedAt != nil {
		view.State = "revoked"
		at := c.RevokedAt.UTC()
		view.RevokedAt = &at
		if c.ReasonCode != nil {
			if reason, ok := crypto.RevocationReasonFromCRLCode(*c.ReasonCode); ok {
				view.Reason = string(reason)
			}
		}
	}
	return view
}

// RotateTSACertificate moves the TSA onto a fresh signer-held key and a new
// certificate from the same CA. With a reason, the outgoing certificate is
// revoked so its timestamps are judged by that reason; without one it is
// retired and stays valid for the timestamps it signed.
func (s *Server) RotateTSACertificate(ctx context.Context, tenantID, revokeReason string) (api.TSARotation, error) {
	sp, err := s.tsaManagement(tenantID)
	if err != nil {
		return api.TSARotation{}, err
	}
	reason := crypto.RevocationReason(strings.TrimSpace(revokeReason))
	if reason != "" && !crypto.IsValidRevocationReason(string(reason)) {
		return api.TSARotation{}, fmt.Errorf("%w: unknown revocation reason %q", api.ErrInvalidTSARequest, reason)
	}
	if s.signer == nil || s.signer.Client() == nil {
		return api.TSARotation{}, errors.New("rotating the TSA requires the signer")
	}
	sp.tsaState.mu.Lock()
	defer sp.tsaState.mu.Unlock()
	previous, err := certinfo.Inspect(sp.tsa.Certificate())
	if err != nil {
		return api.TSARotation{}, err
	}
	handle := fmt.Sprintf("%s-%d", tsaSignerHandle, time.Now().UTC().UnixNano())
	signer, err := s.signer.Client().GenerateConstrainedKeyHandle(ctx, crypto.RSA2048, handle,
		[]signing.KeyPurpose{signing.PurposeGeneric}, signing.PurposeGeneric)
	if err != nil {
		return api.TSARotation{}, fmt.Errorf("provision the new timestamping key in the signer: %w", err)
	}
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: "trstctl TSA", RequestedEKUs: []string{"timeStamping"},
	}, signer)
	if err != nil {
		return api.TSARotation{}, fmt.Errorf("create the TSA certificate request: %w", err)
	}
	certDER, err := crypto.SignTimestampingCertFromCSR(s.caCertDER, s.caSigner, csr, protocolRATTL)
	if err != nil {
		return api.TSARotation{}, fmt.Errorf("sign the TSA certificate: %w", err)
	}
	// Register before persisting: a restart then finds the handle of whichever
	// certificate the file holds.
	if err := s.registerTSACertificate(ctx, tenantID, handle, certDER); err != nil {
		return api.TSARotation{}, fmt.Errorf("register the TSA certificate: %w", err)
	}
	if sp.tsaState.certFile != "" {
		if err := writeCertPEM(sp.tsaState.certFile, certDER); err != nil {
			return api.TSARotation{}, fmt.Errorf("persist the TSA certificate: %w", err)
		}
	}
	if err := sp.tsa.Rotate(certDER, signer); err != nil {
		return api.TSARotation{}, err
	}
	if reason != "" {
		if err := s.revokeTSACertificateSerial(ctx, tenantID, previous.SerialNumber, reason); err != nil {
			return api.TSARotation{}, err
		}
	}
	list, err := s.TSACertificates(ctx, tenantID)
	if err != nil {
		return api.TSARotation{}, err
	}
	var out api.TSARotation
	current, err := certinfo.Inspect(certDER)
	if err != nil {
		return api.TSARotation{}, err
	}
	for _, c := range list.Items {
		switch c.Serial {
		case current.SerialNumber:
			out.Current = c
		case previous.SerialNumber:
			out.Previous = c
		}
	}
	return out, nil
}

// RevokeTSACertificate revokes a TSA certificate the TSA no longer signs under.
func (s *Server) RevokeTSACertificate(ctx context.Context, tenantID, serial, revokeReason string) (api.TSACertificate, error) {
	sp, err := s.tsaManagement(tenantID)
	if err != nil {
		return api.TSACertificate{}, err
	}
	reason := crypto.RevocationReason(strings.TrimSpace(revokeReason))
	if !crypto.IsValidRevocationReason(string(reason)) {
		return api.TSACertificate{}, fmt.Errorf("%w: unknown revocation reason %q", api.ErrInvalidTSARequest, reason)
	}
	serial = strings.ToLower(strings.TrimSpace(serial))
	sp.tsaState.mu.Lock()
	defer sp.tsaState.mu.Unlock()
	active, err := certinfo.Inspect(sp.tsa.Certificate())
	if err != nil {
		return api.TSACertificate{}, err
	}
	if serial == active.SerialNumber {
		return api.TSACertificate{}, fmt.Errorf("%w: %w", api.ErrInvalidTSARequest, errTSAActiveRevoke)
	}
	certs, err := s.store.ListTSACertificates(ctx, tenantID)
	if err != nil {
		return api.TSACertificate{}, err
	}
	for _, c := range certs {
		if c.Serial != serial {
			continue
		}
		if c.RevokedAt == nil {
			if err := s.revokeTSACertificateSerial(ctx, tenantID, serial, reason); err != nil {
				return api.TSACertificate{}, err
			}
		}
		list, err := s.TSACertificates(ctx, tenantID)
		if err != nil {
			return api.TSACertificate{}, err
		}
		for _, item := range list.Items {
			if item.Serial == serial {
				return item, nil
			}
		}
	}
	return api.TSACertificate{}, api.ErrTSACertificateNotFound
}

// TSAStatusEvidence returns, for each TSA certificate in certs that this
// server's CA issued, an OCSP response signed by the TSA tenant's delegated
// responder (A146): the revocation evidence an export carries so it can be
// verified long after, offline.
func (s *Server) TSAStatusEvidence(ctx context.Context, certs [][]byte) ([]api.TSAStatusEvidence, error) {
	sp := s.protocols
	if sp == nil || sp.tsa == nil || s.revoc == nil {
		return nil, nil
	}
	seen := map[string]bool{}
	var out []api.TSAStatusEvidence
	for _, certDER := range certs {
		if err := crypto.VerifyLeafSignedByCA(certDER, s.caCertDER); err != nil {
			continue
		}
		info, err := certinfo.Inspect(certDER)
		if err != nil || seen[info.SerialNumber] {
			continue
		}
		seen[info.SerialNumber] = true
		der, err := s.revoc.statusResponse(ctx, sp.tsaTenant, info.SerialNumber)
		if err != nil {
			return nil, fmt.Errorf("TSA certificate %s status: %w", info.SerialNumber, err)
		}
		out = append(out, api.TSAStatusEvidence{Serial: info.SerialNumber, OCSP: der})
	}
	return out, nil
}
