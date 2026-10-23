// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"reflect"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/breakglass"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/store"
)

type breakglassReconciler struct {
	caCertDER  []byte
	publicDER  []byte
	offlineKit *signing.OfflineBreakglassKit
	store      *store.Store
	log        *events.Log
}

type breakglassOnlineIssuer struct {
	svc        *breakglass.Service
	reconciler api.BreakglassReconciler
}

// breakglassDependencyPresent rejects both a nil interface and an interface that
// contains a nil pointer. The latter can otherwise look configured at the API
// boundary and panic only when the first incident request calls it.
func breakglassDependencyPresent(dependency any) bool {
	if dependency == nil {
		return false
	}
	value := reflect.ValueOf(dependency)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return !value.IsNil()
	default:
		return true
	}
}

func breakglassRuntimeDependencies(runtime *configuredBreakglassRuntime) (
	api.BreakglassIssuer,
	api.BreakglassCeremonyService,
	api.BreakglassRotationService,
	api.BreakglassReconciler,
) {
	if runtime == nil {
		return nil, nil, nil, nil
	}
	return runtime, runtime, runtime, runtime
}

func buildBreakglassReconciler(d Deps) (api.BreakglassReconciler, error) {
	if breakglassDependencyPresent(d.BreakglassReconciler) {
		return d.BreakglassReconciler, nil
	}
	hasCA := len(d.BreakglassCACertDER) > 0
	hasPublicKey := len(d.BreakglassPublicKeyDER) > 0
	switch {
	case !hasCA && !hasPublicKey:
		return nil, nil
	case hasCA != hasPublicKey:
		return nil, errors.New("server: break-glass reconciliation requires both CA certificate and public key verifier material")
	case d.Log == nil || d.Store == nil:
		return nil, errors.New("server: break-glass reconciliation requires PostgreSQL and an event log for audit reconciliation")
	}
	return breakglassReconciler{
		caCertDER:  append([]byte(nil), d.BreakglassCACertDER...),
		publicDER:  append([]byte(nil), d.BreakglassPublicKeyDER...),
		offlineKit: d.BreakglassOfflineKit,
		store:      d.Store,
		log:        d.Log,
	}, nil
}

func buildBreakglassIssuer(d Deps, reconciler api.BreakglassReconciler) (api.BreakglassIssuer, error) {
	if breakglassDependencyPresent(d.BreakglassIssuer) {
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
	for _, bundle := range bundles {
		var err error
		if bundle.Version == 2 {
			if r.offlineKit == nil || r.offlineKit.Policy.TenantID != tenantID {
				return 0, fmt.Errorf("%w: no pinned offline kit for tenant", api.ErrBreakglassInvalidBundle)
			}
			err = breakglass.VerifyDisconnected(bundle, r.offlineKit.Policy, r.offlineKit.CACertDER, r.offlineKit.PublicKeyDER)
		} else {
			err = breakglass.Verify(bundle, r.caCertDER, r.publicDER)
		}
		if err != nil {
			return 0, fmt.Errorf("%w: %v", api.ErrBreakglassInvalidBundle, err)
		}
	}
	return reconcileVerifiedBreakglassBundles(ctx, tenantID, bundles, r.store, r.log)
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
	if err := checkStartupKeyBinding("breakglass.public_key_file", crypto.PublicKey{DER: publicKeyDER}, nil); err != nil {
		return nil, nil, err
	}
	return caCertDER, publicKeyDER, nil
}

func readPEMOrDERFile(path, wantType string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("path is required")
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-configured local file path from deployment config (CWE-22)
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
	return append([]byte(nil), raw...), nil
}
