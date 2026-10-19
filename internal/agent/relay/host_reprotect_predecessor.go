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

// adoptReprotectPredecessor proves the selected inventory leaf is both installed
// and served, then seals its exact local key before asking for a new signature.
// A retry may see the already installed successor only when its signed result
// was first retained in the same encrypted job slot.
func adoptReprotectPredecessor(ctx context.Context, profile connector.LocalOpsConfig, store *HostRollbackStore, intent DeployIntent) error {
	if intent.ReprotectJobID == "" {
		if intent.ReprotectPredecessorFingerprint != "" || intent.ReprotectPredecessorSPKISHA256 != "" || intent.ReprotectTTLSeconds != 0 {
			return errors.New("CA re-protection requires a complete bound job")
		}
		return nil
	}
	if store == nil || intent.ReprotectPredecessorFingerprint == "" || intent.ReprotectPredecessorSPKISHA256 == "" ||
		intent.ReprotectTTLSeconds < 60 || intent.ReprotectTTLSeconds > 90*24*3600 ||
		intent.TargetID == "" || intent.VerifyAddress == "" || intent.VerifyServerName == "" {
		return errors.New("CA re-protection requires a pinned job, host route, predecessor and TTL")
	}
	if !SupportsPQCCertificatePredecessor(intent.Connector) {
		return fmt.Errorf("CA re-protection has no exact predecessor reader for %s", intent.Connector)
	}
	pinned := false
	err := store.UseReprotectPredecessor(intent.Connector, intent.TargetID, intent.ReprotectJobID, intent.ReprotectPredecessorFingerprint,
		func(oldCert, oldKey []byte) error {
			info, inspectErr := certinfo.Inspect(oldCert)
			if inspectErr != nil || !sameHostRollbackFingerprint(info.SHA256Fingerprint, intent.ReprotectPredecessorFingerprint) ||
				!sameHostRollbackFingerprint(info.SPKISHA256, intent.ReprotectPredecessorSPKISHA256) ||
				crypto.VerifyCertKeyMatchPEM(oldCert, oldKey) != nil {
				return ErrHostRollbackStateMismatch
			}
			pinned = true
			return nil
		})
	if err != nil && !errors.Is(err, ErrHostRollbackPredecessorMissing) {
		return err
	}
	var pending *hostReprotectPending
	if pinned {
		pending, err = store.LoadReprotectPending(intent.Connector, intent.TargetID, intent.ReprotectJobID)
		if err != nil {
			return err
		}
		defer wipeReprotectPending(pending)
	}
	var target HostTargetConfig
	if err := json.Unmarshal(intent.TargetConfig, &target); err != nil || strings.TrimSpace(target.CertPath) == "" || strings.TrimSpace(target.KeyPath) == "" {
		return errors.New("CA re-protection target needs one certificate and one key file")
	}
	certPEM, err := connector.ReadLocalFile(profile, target.CertPath)
	if err != nil {
		return fmt.Errorf("read installed predecessor certificate: %w", err)
	}
	rawKey, err := connector.ReadLocalFile(profile, target.KeyPath)
	if err != nil {
		return fmt.Errorf("read installed predecessor subject key: %w", err)
	}
	key, err := secret.NewFrom(rawKey)
	secret.Wipe(rawKey)
	if err != nil {
		return err
	}
	defer key.Destroy()
	if err := crypto.VerifyCertKeyMatchPEM(certPEM, key.Bytes()); err != nil {
		return err
	}
	info, err := certinfo.Inspect(certPEM)
	if err != nil {
		return err
	}
	predecessorServing := sameHostRollbackFingerprint(info.SHA256Fingerprint, intent.ReprotectPredecessorFingerprint) &&
		sameHostRollbackFingerprint(info.SPKISHA256, intent.ReprotectPredecessorSPKISHA256)
	resumingSuccessor := pinned && pending != nil && pending.Fingerprint != "" && sameHostRollbackFingerprint(info.SHA256Fingerprint, pending.Fingerprint) &&
		sameHostRollbackFingerprint(info.SPKISHA256, intent.ReprotectPredecessorSPKISHA256)
	if !predecessorServing && !resumingSuccessor {
		return errors.New("installed host certificate differs from the reviewed predecessor and retained successor")
	}
	if err := certinfo.VerifyHostname(certPEM, intent.VerifyServerName); err != nil {
		return err
	}
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	observed, err := tlsprobe.ProbeWithNativeFallback(probeCtx, profile.TLSProbeOpenSSL, intent.VerifyAddress,
		tlsprobe.WithTimeout(10*time.Second), tlsprobe.WithServerName(intent.VerifyServerName))
	if err != nil || len(observed.PeerCertificates) == 0 {
		if err == nil {
			return errors.New("listener returned no certificate")
		}
		return fmt.Errorf("verify served predecessor: %w", err)
	}
	served, err := certinfo.Inspect(observed.PeerCertificates[0])
	if err != nil || !sameHostRollbackFingerprint(served.SHA256Fingerprint, info.SHA256Fingerprint) {
		return errors.New("listener serves a different leaf than the installed host bundle")
	}
	if pinned {
		return nil
	}
	return store.PinReprotectPredecessor(intent.Connector, intent.TargetID, intent.ReprotectJobID, info.SHA256Fingerprint, certPEM, key.Bytes())
}
