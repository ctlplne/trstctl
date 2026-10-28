// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// A215: some paths record a certificate without its bytes — a network scan
// without agent_channel.probe_scanned_certificates, a cloud listing, an older
// import — and such a row cannot join cross-authority reconciliation, which
// identifies a certificate by the issuer name bytes and serial inside it. An
// operator asks for the bytes: from a mint of the tenant's own CA that retained
// them, or from the endpoint the row records. Either way they are attached only
// when they hash to the row's fingerprint; nothing is taken from a name or a
// serial alone.

var derRecoveryNamespace = uuid.MustParse("b6a1c9e2-4f3d-5a87-8e0b-2d7c41f5a936")

// Outcomes of a recovery.
const (
	derRecovered   = "recovered"
	derAlreadyHeld = "already_held"
	derNotFound    = "not_found"
	derMismatch    = "mismatch"
	derUnreachable = "unreachable"
)

const derRecoveryProbeTimeout = 15 * time.Second

// RecoverCertificateDER recovers an inventory row's certificate bytes by the
// requested method. A row that already holds them is left as it is.
func (s *Server) RecoverCertificateDER(ctx context.Context, tenantID, certificateID string, req api.CertificateDERRecoveryRequest) (api.CertificateDERRecovery, error) {
	if s.store == nil || s.orch == nil || s.log == nil {
		return api.CertificateDERRecovery{}, errors.New("server: certificate byte recovery requires the store, orchestrator and event log")
	}
	if req.Method != store.DERRecoveredFromCALedger && req.Method != store.DERRecoveredFromEndpoint {
		return api.CertificateDERRecovery{}, fmt.Errorf("%w: method must be ca_ledger or endpoint", api.ErrCertificateDERRecoveryInvalid)
	}
	row, err := s.store.GetCertificate(ctx, tenantID, certificateID)
	if err != nil {
		return api.CertificateDERRecovery{}, err
	}
	out := api.CertificateDERRecovery{CertificateID: row.ID, Fingerprint: row.Fingerprint, Method: req.Method}
	if len(row.CertificateDER) > 0 {
		out.Outcome = derAlreadyHeld
		return out, nil
	}
	var der []byte
	switch req.Method {
	case store.DERRecoveredFromCALedger:
		der, out.Evidence, out.Outcome, out.Detail, err = s.derFromCALedger(ctx, tenantID, row)
	default:
		der, out.Evidence, out.Outcome, out.Detail, err = derFromEndpoint(ctx, row, req)
	}
	if err != nil || der == nil {
		return out, err
	}
	recovered := projections.CertificateDERRecovered{CertificateID: row.ID, Fingerprint: row.Fingerprint,
		Method: req.Method, Evidence: out.Evidence, CertificateDER: der}
	eventID := uuid.NewSHA1(derRecoveryNamespace,
		[]byte(tenantID+"\x00"+row.Fingerprint+"\x00"+req.Method+"\x00"+out.Evidence)).String()
	if err := s.orch.RecordCertificateDERRecoveredWithEventID(ctx, tenantID, eventID, recovered); err != nil {
		return api.CertificateDERRecovery{}, err
	}
	out.Outcome = derRecovered
	return out, nil
}

// derFromCALedger finds a mint of the tenant's own CA that retained the
// certificate the row names, by its serial, and returns those bytes when they
// hash to the row's fingerprint.
func (s *Server) derFromCALedger(ctx context.Context, tenantID string, row store.Certificate) (der []byte, evidence, outcome, detail string, err error) {
	serial := normalizedSerial(row.Serial)
	if serial == "" {
		return nil, "", derNotFound, "the row records no serial to look up in the CA ledger", nil
	}
	err = s.log.WithHistoryRead(ctx, func(readCtx context.Context) error {
		head, err := s.log.LastSequence(readCtx)
		if err != nil || head == 0 {
			return err
		}
		return s.log.ReplayTenantTypesThrough(readCtx, tenantID, 1, head,
			[]string{projections.EventCAIssuedCertificate, projections.EventCAEndEntityIssued}, func(e events.Event) error {
				if der != nil {
					return nil
				}
				var mint struct {
					Serial         string `json:"serial"`
					CertificateDER []byte `json:"certificate_der"`
				}
				if err := json.Unmarshal(e.Data, &mint); err != nil {
					return fmt.Errorf("server: decode CA mint %s: %w", e.ID, err)
				}
				if normalizedSerial(mint.Serial) == serial && len(mint.CertificateDER) > 0 &&
					crypto.SHA256Hex(mint.CertificateDER) == row.Fingerprint {
					der, evidence = mint.CertificateDER, e.ID
				}
				return nil
			})
	})
	if err != nil {
		return nil, "", "", "", err
	}
	if der == nil {
		return nil, "", derNotFound, "no mint of this tenant's CAs retained a certificate with serial " + row.Serial + " and this fingerprint", nil
	}
	return der, evidence, "", "", nil
}

// derFromEndpoint reads the certificate the row's recorded endpoint serves and
// returns it when it hashes to the row's fingerprint. The control plane dials
// the address under the same egress rules as its other outbound calls.
func derFromEndpoint(ctx context.Context, row store.Certificate, req api.CertificateDERRecoveryRequest) (der []byte, evidence, outcome, detail string, err error) {
	address := strings.TrimSpace(row.DeploymentLocation)
	if _, _, err := net.SplitHostPort(address); err != nil {
		return nil, "", derNotFound, "the row records no host:port endpoint", nil
	}
	control := netsec.SafeDialControl
	if req.AllowPrivateEndpoint {
		opts, err := privateEgressSafeClientOptions(req.PrivateEgressCIDRs)
		if err != nil {
			return nil, "", "", "", fmt.Errorf("%w: %v", api.ErrCertificateDERRecoveryInvalid, err)
		}
		control = netsec.SafeDialControlWithOptions(opts)
	}
	res, err := tlsprobe.Probe(ctx, address, tlsprobe.WithDialControl(control), tlsprobe.WithTimeout(derRecoveryProbeTimeout))
	if err != nil {
		return nil, address, derUnreachable, err.Error(), nil
	}
	served := res.PeerCertificates[0]
	if fingerprint := crypto.SHA256Hex(served); fingerprint != row.Fingerprint {
		return nil, address, derMismatch, "the endpoint serves another certificate (" + fingerprint + ")", nil
	}
	return served, address, "", "", nil
}

// normalizedSerial compares serials as lowercase hex without separators or
// leading zeros, the form trstctl records them in.
func normalizedSerial(serial string) string {
	serial = strings.ToLower(strings.NewReplacer(":", "", " ", "").Replace(strings.TrimSpace(serial)))
	trimmed := strings.TrimLeft(serial, "0")
	if trimmed == "" && serial != "" {
		return "0"
	}
	return trimmed
}
