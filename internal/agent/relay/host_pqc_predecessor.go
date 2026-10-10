// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
)

// adoptPQCPredecessor makes the rollback claim real before issuance. The
// discovered CBOM fingerprint, local installed bundle, and negotiated public
// leaf must all agree. This only supports host connectors with one certificate
// file and one key file; multi-file stores require a connector-specific
// predecessor reader and cannot silently use this path.
func adoptPQCPredecessor(ctx context.Context, profile connector.LocalOpsConfig, store *HostRollbackStore, intent DeployIntent) error {
	if intent.PQCRunID == "" && intent.PQCAssetID == "" && intent.PQCPredecessorFingerprint == "" {
		return nil
	}
	if intent.PQCRunID == "" || intent.PQCAssetID == "" || intent.PQCPredecessorFingerprint == "" {
		return errors.New("PQC certificate migration requires run, asset, and predecessor fingerprint")
	}
	if store == nil {
		return errors.New("PQC certificate migration requires a host rollback store")
	}
	if strings.TrimSpace(intent.TargetID) == "" || strings.TrimSpace(intent.VerifyAddress) == "" || strings.TrimSpace(intent.VerifyServerName) == "" {
		return errors.New("PQC certificate migration requires target and independent listener verification binding")
	}
	if !SupportsPQCCertificatePredecessor(intent.Connector) {
		return fmt.Errorf("PQC certificate migration has no exact predecessor reader for %s", intent.Connector)
	}
	pinned, err := store.HasPQCPredecessor(intent.Connector, intent.TargetID, intent.PQCRunID, intent.PQCPredecessorFingerprint)
	if err != nil {
		return err
	}
	var pending *hostPQCPending
	if pinned {
		pending, err = store.LoadPQCPending(intent.Connector, intent.TargetID, intent.PQCRunID, intent.PQCAssetID)
		if err != nil {
			return err
		}
		defer wipePQCPending(pending)
	}
	var target HostTargetConfig
	if err := json.Unmarshal(intent.TargetConfig, &target); err != nil {
		return fmt.Errorf("decode PQC host target: %w", err)
	}
	if strings.TrimSpace(target.CertPath) == "" || strings.TrimSpace(target.KeyPath) == "" {
		return errors.New("PQC host target requires cert_path and key_path for exact rollback")
	}
	certPEM, err := connector.ReadLocalFile(profile, target.CertPath)
	if err != nil {
		return fmt.Errorf("read installed predecessor certificate: %w", err)
	}
	rawKey, err := connector.ReadLocalFile(profile, target.KeyPath)
	if err != nil {
		return fmt.Errorf("read installed predecessor private key: %w", err)
	}
	key, err := secret.NewFrom(rawKey)
	secret.Wipe(rawKey)
	if err != nil {
		return fmt.Errorf("lock installed predecessor key: %w", err)
	}
	defer key.Destroy()
	if err := crypto.VerifyCertKeyMatchPEM(certPEM, key.Bytes()); err != nil {
		return fmt.Errorf("installed predecessor certificate/key mismatch: %w", err)
	}
	info, err := certinfo.Inspect(certPEM)
	if err != nil {
		return err
	}
	predecessorServing := sameHostRollbackFingerprint(info.SHA256Fingerprint, intent.PQCPredecessorFingerprint)
	resumingSuccessor := pinned && pending != nil && pending.Fingerprint != "" &&
		sameHostRollbackFingerprint(info.SHA256Fingerprint, pending.Fingerprint)
	if !predecessorServing && !resumingSuccessor {
		return errors.New("installed predecessor does not match selected CBOM certificate fingerprint")
	}
	if err := certinfo.VerifyHostname(certPEM, intent.VerifyServerName); err != nil {
		return fmt.Errorf("installed predecessor does not match listener name: %w", err)
	}
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	observed, err := tlsprobe.ProbeWithNativeFallback(probeCtx, profile.TLSProbeOpenSSL, intent.VerifyAddress,
		tlsprobe.WithTimeout(10*time.Second), tlsprobe.WithServerName(intent.VerifyServerName))
	if err != nil {
		return fmt.Errorf("verify served predecessor: %w", err)
	}
	if len(observed.PeerCertificates) == 0 {
		return errors.New("served predecessor supplied no public leaf")
	}
	served, err := certinfo.Inspect(observed.PeerCertificates[0])
	if err != nil {
		return err
	}
	if !sameHostRollbackFingerprint(served.SHA256Fingerprint, info.SHA256Fingerprint) {
		return errors.New("listener serves a different predecessor than the installed bundle")
	}
	if pinned {
		return nil
	}
	return store.PinPQCPredecessor(intent.Connector, intent.TargetID, intent.PQCRunID, info.SHA256Fingerprint, certPEM, key.Bytes())
}

// SupportsPQCCertificatePredecessor is the closed set of host connectors that
// install one certificate file and one key file through the local sandbox.
// Keeping the preflight and executor on one list prevents a migration preview
// from promising exact rollback for a connector with a different storage shape.
func SupportsPQCCertificatePredecessor(name string) bool {
	switch name {
	case "apache", "nginx", "caddy", "elasticsearch", "mysql", "postgresql", "rabbitmq", "tomcat", "traefik":
		return true
	default:
		return false
	}
}

func sameHostRollbackFingerprint(a, b string) bool {
	a = strings.ToLower(strings.ReplaceAll(strings.TrimPrefix(strings.TrimSpace(a), "sha256:"), ":", ""))
	b = strings.ToLower(strings.ReplaceAll(strings.TrimPrefix(strings.TrimSpace(b), "sha256:"), ":", ""))
	return len(a) == 64 && a == b
}
