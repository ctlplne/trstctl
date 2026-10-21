// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"context"
	"encoding/json"
	"encoding/pem"
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
	certPEM, rawKey, err := readInstalledHostPredecessor(profile, intent.Connector, target)
	if err != nil {
		return err
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
	case "apache", "nginx", "caddy", "elasticsearch", "mysql", "postgresql", "rabbitmq", "tomcat", "traefik",
		"haproxy", "postfix":
		return true
	default:
		// java-keystore needs the store password at adoption time, iis keeps
		// the key in the Windows store and envoy holds it behind SDS: none of
		// them has an exact file predecessor this reader can pin.
		return false
	}
}

// HostPredecessorLayoutComplete reports whether a host target's configuration
// names every file the exact-predecessor reader needs for that connector.
func HostPredecessorLayoutComplete(name string, config json.RawMessage) bool {
	var target HostTargetConfig
	if json.Unmarshal(config, &target) != nil {
		return false
	}
	_, err := hostPredecessorLayout(name, target)
	return err == nil
}

type hostPredecessorFiles struct {
	certPath, keyPath string // separate files; empty for a bundle
	bundlePath        string // HAProxy certificate+key bundle
	mirrorCertPath    string // Postfix: the Dovecot pair must serve the same leaf
	mirrorKeyPath     string
}

func hostPredecessorLayout(name string, target HostTargetConfig) (hostPredecessorFiles, error) {
	if !SupportsPQCCertificatePredecessor(name) {
		return hostPredecessorFiles{}, fmt.Errorf("no exact predecessor reader for %s", name)
	}
	switch name {
	case "haproxy":
		if strings.TrimSpace(target.CRTPath) == "" {
			return hostPredecessorFiles{}, errors.New("HAProxy host target requires crt_path for exact rollback")
		}
		return hostPredecessorFiles{bundlePath: target.CRTPath}, nil
	case "postfix":
		if strings.TrimSpace(target.PostfixCertPath) == "" || strings.TrimSpace(target.PostfixKeyPath) == "" ||
			strings.TrimSpace(target.DovecotCertPath) == "" || strings.TrimSpace(target.DovecotKeyPath) == "" {
			return hostPredecessorFiles{}, errors.New("the postfix host target requires the Postfix and Dovecot certificate and key paths for exact rollback")
		}
		return hostPredecessorFiles{certPath: target.PostfixCertPath, keyPath: target.PostfixKeyPath,
			mirrorCertPath: target.DovecotCertPath, mirrorKeyPath: target.DovecotKeyPath}, nil
	default:
		if strings.TrimSpace(target.CertPath) == "" || strings.TrimSpace(target.KeyPath) == "" {
			return hostPredecessorFiles{}, errors.New("PQC host target requires cert_path and key_path for exact rollback")
		}
		return hostPredecessorFiles{certPath: target.CertPath, keyPath: target.KeyPath}, nil
	}
}

// readInstalledHostPredecessor returns the installed certificate (PEM) and
// private key (PEM) for the connector's file layout (A38). The caller wipes
// the key. A bundle is split by PEM block type and must hold exactly one
// private key; a Postfix/Dovecot pair must serve one certificate, since a
// rollback restores one predecessor to both.
func readInstalledHostPredecessor(profile connector.LocalOpsConfig, name string, target HostTargetConfig) ([]byte, []byte, error) {
	layout, err := hostPredecessorLayout(name, target)
	if err != nil {
		return nil, nil, err
	}
	if layout.bundlePath != "" {
		raw, err := connector.ReadLocalFile(profile, layout.bundlePath)
		if err != nil {
			return nil, nil, fmt.Errorf("read installed predecessor bundle: %w", err)
		}
		defer secret.Wipe(raw)
		return splitHostPredecessorBundle(raw)
	}
	certPEM, err := connector.ReadLocalFile(profile, layout.certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read installed predecessor certificate: %w", err)
	}
	keyPEM, err := connector.ReadLocalFile(profile, layout.keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read installed predecessor private key: %w", err)
	}
	if layout.mirrorCertPath != "" {
		mirrorCert, err := connector.ReadLocalFile(profile, layout.mirrorCertPath)
		if err != nil {
			secret.Wipe(keyPEM)
			return nil, nil, fmt.Errorf("read installed Dovecot predecessor certificate: %w", err)
		}
		mirrorKey, err := connector.ReadLocalFile(profile, layout.mirrorKeyPath)
		if err != nil {
			secret.Wipe(keyPEM)
			return nil, nil, fmt.Errorf("read installed Dovecot predecessor private key: %w", err)
		}
		defer secret.Wipe(mirrorKey)
		primary, perr := certinfo.Inspect(certPEM)
		mirror, merr := certinfo.Inspect(mirrorCert)
		if perr != nil || merr != nil || !sameHostRollbackFingerprint(primary.SHA256Fingerprint, mirror.SHA256Fingerprint) ||
			crypto.VerifyCertKeyMatchPEM(mirrorCert, mirrorKey) != nil {
			secret.Wipe(keyPEM)
			return nil, nil, errors.New("the Postfix and Dovecot pairs serve different predecessors; one exact predecessor cannot be pinned")
		}
	}
	return certPEM, keyPEM, nil
}

func splitHostPredecessorBundle(raw []byte) ([]byte, []byte, error) {
	var certPEM, keyPEM []byte
	keys := 0
	rest := raw
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining
		switch {
		case block.Type == "CERTIFICATE":
			certPEM = append(certPEM, pem.EncodeToMemory(block)...)
		case strings.HasSuffix(block.Type, "PRIVATE KEY"):
			keys++
			keyPEM = pem.EncodeToMemory(block)
		}
		secret.Wipe(block.Bytes)
	}
	if len(certPEM) == 0 || keys != 1 {
		secret.Wipe(keyPEM)
		return nil, nil, errors.New("installed bundle must hold the certificate chain and exactly one private key")
	}
	return certPEM, keyPEM, nil
}

func sameHostRollbackFingerprint(a, b string) bool {
	a = strings.ToLower(strings.ReplaceAll(strings.TrimPrefix(strings.TrimSpace(a), "sha256:"), ":", ""))
	b = strings.ToLower(strings.ReplaceAll(strings.TrimPrefix(strings.TrimSpace(b), "sha256:"), ":", ""))
	return len(a) == 64 && a == b
}
