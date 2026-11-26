// SPDX-License-Identifier: BUSL-1.1

package secretscan

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	boundarycrypto "trstctl.com/trstctl/internal/crypto"
)

const (
	// ThirdPartySourceKind is the discovery source kind used for CAP-SCAN-04
	// CI/CD-log, container-registry, Slack, Jira, Teams and Confluence
	// export scanning.
	ThirdPartySourceKind = "secret_third_party"

	ThirdPartyProviderCICDLog           = "cicd_log"
	ThirdPartyProviderContainerRegistry = "container_registry"
	ThirdPartyProviderSlack             = "slack"
	ThirdPartyProviderJira              = "jira"
	// Microsoft Teams channel messages and Confluence content (OD-4).
	ThirdPartyProviderTeams      = "teams"
	ThirdPartyProviderConfluence = "confluence"
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
	// Annotation writes findings back at the provider (A174); see
	// AnnotationConfig.
	Annotation *AnnotationConfig `json:"annotation,omitempty"`
	// Collect (N6) reads the content from the provider instead of
	// ArtifactPath; see CollectConfig.
	Collect *CollectConfig `json:"collect,omitempty"`
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
const maxThirdPartySignatureBytes = 64 << 10

// ThirdPartyArtifactAccess is the root-confined file authority supplied by
// the served scanner. A tenant's path cannot grant filesystem authority.
type ThirdPartyArtifactAccess interface {
	ValidateLocalTarget(path string) error
	ReadLocalRegular(ctx context.Context, path string, maxBytes int64) ([]byte, error)
	HashLocalRegular(ctx context.Context, path string, maxBytes int64) ([]byte, error)
	RemoveLocalRegular(path string) error
}

// VerifyThirdPartyArtifactSignature checks the provider's detached signature
// over the artifact file before anything reads it as scan input. The artifact
// must be one regular file (a signature cannot cover a directory export) of
// at most 256 MiB; the signature file holds raw signature bytes or their
// base64 text; the public key is PEM (PKIX). RSA PKCS#1 v1.5 and ECDSA over
// SHA-256 are accepted, the same primitive the platform's attestation
// verification uses.
func VerifyThirdPartyArtifactSignature(ctx context.Context, cfg ThirdPartyScanConfig, artifactPath string, files ThirdPartyArtifactAccess) (ArtifactSignatureEvidence, error) {
	signaturePath := strings.TrimSpace(cfg.SignaturePath)
	keyPEM := strings.TrimSpace(cfg.SignerPublicKeyPEM)
	if (signaturePath == "") != (keyPEM == "") {
		return ArtifactSignatureEvidence{}, ErrArtifactSignatureRequired
	}
	if signaturePath == "" || keyPEM == "" {
		if cfg.RequireSignature {
			return ArtifactSignatureEvidence{}, ErrArtifactSignatureRequired
		}
		return ArtifactSignatureEvidence{}, nil
	}
	if files == nil {
		return ArtifactSignatureEvidence{}, errors.New("secretscan: root-confined artifact file access is unavailable")
	}
	pub, err := boundarycrypto.ParsePublicKeyPEM([]byte(keyPEM))
	if err != nil {
		return ArtifactSignatureEvidence{}, fmt.Errorf("secretscan: signer_public_key_pem must be a PEM PUBLIC KEY: %w", err)
	}
	digest, err := files.HashLocalRegular(ctx, artifactPath, maxSignedArtifactBytes)
	if err != nil {
		return ArtifactSignatureEvidence{}, fmt.Errorf("secretscan: read regular artifact: %w", err)
	}
	sigRaw, err := files.ReadLocalRegular(ctx, signaturePath, maxThirdPartySignatureBytes)
	if err != nil {
		return ArtifactSignatureEvidence{}, fmt.Errorf("secretscan: read bounded regular signature: %w", err)
	}
	if err := verifyDetachedArtifactDigest(pub, digest, sigRaw); err != nil {
		return ArtifactSignatureEvidence{}, fmt.Errorf("secretscan: artifact signature verification failed: %w", err)
	}
	return ArtifactSignatureEvidence{Verified: true, SignerKeySHA256: boundarycrypto.SHA256Hex(pub.DER)}, nil
}

// verifyDetachedArtifactSignature accepts base64 text or the exact binary
// signature. Only the text candidate may have surrounding whitespace removed:
// an RSA or ECDSA signature can itself begin or end with a whitespace byte.
func verifyDetachedArtifactSignature(publicDER, content, signature []byte) error {
	return verifyDetachedArtifactDigest(boundarycrypto.PublicKey{DER: publicDER}, boundarycrypto.SHA256Sum(content), signature)
}

func verifyDetachedArtifactDigest(pub boundarycrypto.PublicKey, digest, signature []byte) error {
	opts := boundarycrypto.SignOptions{Hash: boundarycrypto.SHA256, RSAPadding: boundarycrypto.RSAPKCS1v15}
	if decoded, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(signature))); err == nil && len(decoded) > 0 {
		if err := boundarycrypto.VerifyDigest(pub, digest, decoded, opts); err == nil {
			return nil
		}
	}
	return boundarycrypto.VerifyDigest(pub, digest, signature, opts)
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
	case ThirdPartyProviderTeams, "microsoft_teams", "microsoft-teams", "ms_teams":
		return ThirdPartyProviderTeams
	case ThirdPartyProviderConfluence:
		return ThirdPartyProviderConfluence
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
	case ThirdPartyProviderTeams:
		return "teams_export"
	case ThirdPartyProviderConfluence:
		return "confluence_export"
	default:
		return "third_party_export"
	}
}

func ThirdPartyProviders() []string {
	return []string{ThirdPartyProviderCICDLog, ThirdPartyProviderContainerRegistry, ThirdPartyProviderSlack, ThirdPartyProviderJira,
		ThirdPartyProviderTeams, ThirdPartyProviderConfluence}
}

func PrepareThirdPartyTarget(cfg ThirdPartyScanConfig) (ThirdPartyTarget, error) {
	if cfg.Collect != nil {
		return ThirdPartyTarget{}, errors.New("secretscan: a collected scan's content is fetched by the worker, not prepared from a path")
	}
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
func RemoveThirdPartyArtifactAfterScan(cfg ThirdPartyScanConfig, files ThirdPartyArtifactAccess) string {
	if !cfg.DeleteArtifactAfterScan {
		return ""
	}
	if files == nil {
		return "artifact not removed after scan: root-confined file access is unavailable"
	}
	if err := files.RemoveLocalRegular(filepath.Clean(strings.TrimSpace(cfg.ArtifactPath))); err != nil {
		return "artifact not removed after scan: " + err.Error()
	}
	return "artifact removed after scan"
}
