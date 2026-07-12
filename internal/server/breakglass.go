// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/breakglass"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

type breakglassReconciler struct {
	caCertDER []byte
	publicDER []byte
	audit     auditsink.Auditor
}

type breakglassOnlineIssuer struct {
	svc        *breakglass.Service
	reconciler api.BreakglassReconciler
}

func buildBreakglassReconciler(d Deps) (api.BreakglassReconciler, error) {
	if d.BreakglassReconciler != nil {
		return d.BreakglassReconciler, nil
	}
	hasCA := len(d.BreakglassCACertDER) > 0
	hasPublicKey := len(d.BreakglassPublicKeyDER) > 0
	switch {
	case !hasCA && !hasPublicKey:
		return nil, nil
	case hasCA != hasPublicKey:
		return nil, errors.New("server: break-glass reconciliation requires both CA certificate and public key verifier material")
	case d.Log == nil:
		return nil, errors.New("server: break-glass reconciliation requires an event log for audit reconciliation")
	}
	return breakglassReconciler{
		caCertDER: append([]byte(nil), d.BreakglassCACertDER...),
		publicDER: append([]byte(nil), d.BreakglassPublicKeyDER...),
		audit:     audit.NewAuditor(d.Log),
	}, nil
}

func buildBreakglassIssuer(d Deps, reconciler api.BreakglassReconciler) (api.BreakglassIssuer, error) {
	if d.BreakglassIssuer != nil {
		return d.BreakglassIssuer, nil
	}
	if d.BreakglassOfflineIssuer == nil {
		return nil, nil
	}
	if reconciler == nil {
		return nil, errors.New("server: online break-glass issuance requires verifier material and an event log for audit reconciliation")
	}
	return breakglassOnlineIssuer{svc: d.BreakglassOfflineIssuer, reconciler: reconciler}, nil
}

func (r breakglassReconciler) ReconcileBreakglass(ctx context.Context, tenantID string, bundles []breakglass.Bundle) (int, error) {
	if tenantID == "" {
		return 0, errors.New("server: break-glass reconciliation requires tenant scope")
	}
	for _, b := range bundles {
		if err := breakglass.Verify(b, r.caCertDER, r.publicDER); err != nil {
			return 0, fmt.Errorf("%w: bundle %q failed verification: %v", api.ErrBreakglassInvalidBundle, b.RequestID, err)
		}
	}
	return breakglass.Reconcile(ctx, tenantID, bundles, r.caCertDER, r.publicDER, r.audit)
}

func (i breakglassOnlineIssuer) IssueBreakglass(ctx context.Context, tenantID string, req breakglass.EmergencyRequest, ttl time.Duration) (breakglass.Bundle, int, error) {
	if tenantID == "" {
		return breakglass.Bundle{}, 0, errors.New("server: online break-glass issuance requires tenant scope")
	}
	if i.svc == nil || i.reconciler == nil {
		return breakglass.Bundle{}, 0, errors.New("server: online break-glass issuance is not configured")
	}
	bundle, err := i.svc.IssueOffline(req, ttl)
	if err != nil {
		return breakglass.Bundle{}, 0, err
	}
	reconciled, err := i.reconciler.ReconcileBreakglass(ctx, tenantID, []breakglass.Bundle{bundle})
	if err != nil {
		return breakglass.Bundle{}, 0, err
	}
	return bundle, reconciled, nil
}

func breakglassVerifierMaterialFromConfig(cfg config.Breakglass) (caCertDER, publicKeyDER []byte, err error) {
	if !cfg.Enabled {
		return nil, nil, nil
	}
	caCertDER, err = readPEMOrDERFile(cfg.CACertFile, "CERTIFICATE")
	if err != nil {
		return nil, nil, fmt.Errorf("breakglass.ca_cert_file: %w", err)
	}
	publicKeyDER, err = readPEMOrDERFile(cfg.PublicKeyFile, "PUBLIC KEY")
	if err != nil {
		return nil, nil, fmt.Errorf("breakglass.public_key_file: %w", err)
	}
	certificatePublicDER, err := crypto.PublicKeyDERFromCert(caCertDER)
	if err != nil {
		return nil, nil, fmt.Errorf("breakglass.ca_cert_file: %w", err)
	}
	if !bytes.Equal(certificatePublicDER, publicKeyDER) {
		return nil, nil, errors.New("breakglass: CA certificate and public-key verifier name different keys")
	}
	return caCertDER, publicKeyDER, nil
}

func readPEMOrDERFile(path, wantType string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("path is required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	trimmed := bytes.TrimSpace(raw)
	if block, rest := pem.Decode(trimmed); block != nil {
		if block.Type != wantType {
			return nil, fmt.Errorf("PEM block type %q, want %q", block.Type, wantType)
		}
		if len(block.Bytes) == 0 {
			return nil, fmt.Errorf("PEM block %q is empty", wantType)
		}
		if len(bytes.TrimSpace(rest)) != 0 {
			return nil, fmt.Errorf("%s file must contain exactly one public PEM block", wantType)
		}
		return append([]byte(nil), block.Bytes...), nil
	}
	if len(trimmed) == 0 {
		return nil, errors.New("file is empty")
	}
	return append([]byte(nil), trimmed...), nil
}
