// SPDX-License-Identifier: BUSL-1.1

package secretscan

import (
	"bytes"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	boundarycrypto "trstctl.com/trstctl/internal/crypto"
)

const (
	// ThirdPartySourceKind is the discovery source kind used for CAP-SCAN-04
	// CI/CD-log, container-registry, Slack, and Jira export scanning.
	ThirdPartySourceKind = "secret_third_party"

	ThirdPartyProviderCICDLog           = "cicd_log"
	ThirdPartyProviderContainerRegistry = "container_registry"
	ThirdPartyProviderSlack             = "slack"
	ThirdPartyProviderJira              = "jira"
)

var ErrThirdPartyTargetRequired = errors.New("secretscan: third-party scan requires artifact_path")

// ThirdPartyScanConfig is the metadata-only discovery source config for
// CI/CD-log, registry-export, Slack-export, and Jira-export secret scanning.
// ArtifactPath points at operator-provided local/exported content; raw log/chat
// secret values stay in that artifact and never enter events or outbox JSON.
type ThirdPartyScanConfig struct {
	Provider      string `json:"provider"`
	Source        string `json:"source"`
	ArtifactPath  string `json:"artifact_path"`
	ArtifactKind  string `json:"artifact_kind"`
	Event         string `json:"event,omitempty"`
	CredentialRef string `json:"credential_ref,omitempty"`
	// SignaturePath names the provider's detached signature over the artifact
	// bytes (raw DER/raw bytes, or base64 text). SignerPublicKeyPEM is the
	// provider's public key the signature must verify under. RequireSignature
	// refuses a scan whose artifact is unsigned or whose signature does not
	// verify; without it a supplied signature is still verified and recorded,
	// and a failing one still refuses the scan.
	SignaturePath      string `json:"signature_path,omitempty"`
	SignerPublicKeyPEM string `json:"signer_public_key_pem,omitempty"`
	RequireSignature   bool   `json:"require_signature,omitempty"`
	// DeleteArtifactAfterScan removes the operator's artifact file once the scan
	// is terminal, so an export containing live secrets does not outlive the
	// scan that redacted it. Only a single regular file is removed.
	DeleteArtifactAfterScan bool `json:"delete_artifact_after_scan,omitempty"`
}

// ArtifactSignatureEvidence is what a verified provider signature contributes
// to every finding of the run: no artifact bytes, only the fact and the key.
type ArtifactSignatureEvidence struct {
	Verified        bool   `json:"signature_verified"`
	SignerKeySHA256 string `json:"signer_key_sha256,omitempty"`
}

// ErrArtifactSignatureRequired reports a source that requires a provider
// signature but was queued without one.
var ErrArtifactSignatureRequired = errors.New("secretscan: this source requires a provider signature (signature_path and signer_public_key_pem)")

const maxSignedArtifactBytes = 256 << 20

// VerifyThirdPartyArtifactSignature checks the provider's detached signature
// over the artifact file before anything reads it as scan input. The artifact
// must be one regular file (a signature cannot cover a directory export) of
// at most 256 MiB; the signature file holds raw signature bytes or their
// base64 text; the public key is PEM (PKIX). RSA PKCS#1 v1.5 and ECDSA over
// SHA-256 are accepted, the same primitive the platform's attestation
// verification uses.
func VerifyThirdPartyArtifactSignature(cfg ThirdPartyScanConfig, artifactPath string) (ArtifactSignatureEvidence, error) {
	signaturePath := strings.TrimSpace(cfg.SignaturePath)
	keyPEM := strings.TrimSpace(cfg.SignerPublicKeyPEM)
	if signaturePath == "" || keyPEM == "" {
		if cfg.RequireSignature {
			return ArtifactSignatureEvidence{}, ErrArtifactSignatureRequired
		}
		return ArtifactSignatureEvidence{}, nil
	}
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil || block.Type != "PUBLIC KEY" {
		return ArtifactSignatureEvidence{}, errors.New("secretscan: signer_public_key_pem must be a PEM PUBLIC KEY")
	}
	info, err := os.Lstat(artifactPath)
	if err != nil {
		return ArtifactSignatureEvidence{}, fmt.Errorf("secretscan: artifact: %w", err)
	}
	if !info.Mode().IsRegular() {
		return ArtifactSignatureEvidence{}, errors.New("secretscan: a provider signature can only cover a single regular artifact file")
	}
	if info.Size() > maxSignedArtifactBytes {
		return ArtifactSignatureEvidence{}, errors.New("secretscan: signed artifact exceeds 256 MiB")
	}
	content, err := os.ReadFile(artifactPath) // #nosec G304 -- operator-owned artifact path from the reviewed source config, bounded by size above (CWE-22)
	if err != nil {
		return ArtifactSignatureEvidence{}, fmt.Errorf("secretscan: read artifact: %w", err)
	}
	sigRaw, err := os.ReadFile(signaturePath) // #nosec G304 -- operator-owned signature path from the reviewed source config (CWE-22)
	if err != nil {
		return ArtifactSignatureEvidence{}, fmt.Errorf("secretscan: read signature: %w", err)
	}
	sig := bytes.TrimSpace(sigRaw)
	if decoded, decodeErr := base64.StdEncoding.DecodeString(string(sig)); decodeErr == nil && len(decoded) > 0 {
		sig = decoded
	}
	if err := boundarycrypto.VerifyMessage(block.Bytes, content, sig); err != nil {
		return ArtifactSignatureEvidence{}, fmt.Errorf("secretscan: artifact signature verification failed: %w", err)
	}
	return ArtifactSignatureEvidence{Verified: true, SignerKeySHA256: boundarycrypto.SHA256Hex(block.Bytes)}, nil
}

type ThirdPartyTarget struct {
	Path    string
	Cleanup func()
	Mode    string
}

func NormalizeThirdPartyProvider(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "cicd", "ci_cd", "ci-cd", "ci_cd_log", "ci-cd-log", "cicd_log", "cicd-log":
		return ThirdPartyProviderCICDLog
	case "registry", "container_registry", "container-registry":
		return ThirdPartyProviderContainerRegistry
	case ThirdPartyProviderSlack:
		return ThirdPartyProviderSlack
	case ThirdPartyProviderJira:
		return ThirdPartyProviderJira
	default:
		return ""
	}
}

func ThirdPartyArtifactKind(provider string) string {
	switch NormalizeThirdPartyProvider(provider) {
	case ThirdPartyProviderCICDLog:
		return "ci_cd_log"
	case ThirdPartyProviderContainerRegistry:
		return "container_registry_export"
	case ThirdPartyProviderSlack:
		return "slack_export"
	case ThirdPartyProviderJira:
		return "jira_export"
	default:
		return "third_party_export"
	}
}

func ThirdPartyProviders() []string {
	return []string{ThirdPartyProviderCICDLog, ThirdPartyProviderContainerRegistry, ThirdPartyProviderSlack, ThirdPartyProviderJira}
}

func PrepareThirdPartyTarget(cfg ThirdPartyScanConfig) (ThirdPartyTarget, error) {
	path := strings.TrimSpace(cfg.ArtifactPath)
	if path == "" {
		return ThirdPartyTarget{}, ErrThirdPartyTargetRequired
	}
	return ThirdPartyTarget{Path: filepath.Clean(path), Cleanup: func() {}, Mode: "artifact_path"}, nil
}

// RemoveThirdPartyArtifactAfterScan deletes the operator's artifact once a scan
// is terminal when the source asked for it. It removes exactly one regular
// file (the artifact itself; a directory export or archive tree is left in
// place) and reports what happened as a note for the run record. Removal
// failures are reported, never fatal: the scan result stands on its own.
func RemoveThirdPartyArtifactAfterScan(cfg ThirdPartyScanConfig) string {
	if !cfg.DeleteArtifactAfterScan {
		return ""
	}
	path := filepath.Clean(strings.TrimSpace(cfg.ArtifactPath))
	info, err := os.Lstat(path)
	if err != nil {
		return "artifact not removed after scan: " + err.Error()
	}
	if !info.Mode().IsRegular() {
		return "artifact not removed after scan: only a single regular file is removed"
	}
	if err := os.Remove(path); err != nil {
		return "artifact not removed after scan: " + err.Error()
	}
	return "artifact removed after scan"
}
