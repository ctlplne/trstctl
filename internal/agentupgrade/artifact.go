// SPDX-License-Identifier: BUSL-1.1

package agentupgrade

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
)

// Artifact is one downloadable build of the agent for one platform.
//
// The digest is the trust anchor: the agent verifies the downloaded bytes
// against it before touching its own binary, so a compromised or misconfigured
// artifact host can deny an upgrade but cannot substitute a build. The digest
// is operator-supplied at campaign start — the platform does not vouch for what
// the operator published, it guarantees the fleet installs exactly that and
// nothing else.
type Artifact struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
	URL  string `json:"url"`
	// SHA256 is the lowercase hex digest of the artifact bytes.
	SHA256 string `json:"sha256"`
	// Signature is the publisher's base64 Ed25519 signature over the raw sha256
	// digest (A68). Optional unless the control plane or the agent pins a
	// publisher key, in which case an artifact without a verifying signature
	// is refused: the digest pins the bytes, the signature says who published
	// them.
	Signature string `json:"signature,omitempty"`
}

// UpgradeIntent is the payload of one agent.upgrade job. It is decoded by the
// agent, so the shape lives here where both sides import it — a drift between
// what the campaign enqueues and what the agent expects would fail every
// upgrade while both halves passed their own tests.
type UpgradeIntent struct {
	CampaignID    string     `json:"campaign_id"`
	Ring          string     `json:"ring"`
	Round         int        `json:"round"`
	TargetVersion string     `json:"target_version"`
	Artifacts     []Artifact `json:"artifacts"`
}

// ValidateArtifacts refuses an artifact list a campaign could not act on.
//
// Every refusal here is one an operator hits at campaign start, with the field
// named — the alternative is a canary halt ten minutes later with "silent",
// which is true and useless.
func ValidateArtifacts(artifacts []Artifact) error {
	seen := map[string]bool{}
	for i, a := range artifacts {
		if strings.TrimSpace(a.OS) == "" || strings.TrimSpace(a.Arch) == "" {
			return fmt.Errorf("artifact %d: os and arch are required; the agent picks its build by platform and an unlabeled artifact matches nothing", i)
		}
		key := strings.ToLower(strings.TrimSpace(a.OS)) + "/" + strings.ToLower(strings.TrimSpace(a.Arch))
		if seen[key] {
			return fmt.Errorf("artifact %d: %s is listed twice; the agent would install whichever came first and the operator would not know which", i, key)
		}
		seen[key] = true
		u, err := url.Parse(strings.TrimSpace(a.URL))
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return fmt.Errorf("artifact %d (%s): url must be an absolute http(s) URL the agent can fetch", i, key)
		}
		if !isHexSHA256(a.SHA256) {
			return fmt.Errorf("artifact %d (%s): sha256 must be 64 hex characters; the digest is what stops a substituted build, so it cannot be optional or approximate", i, key)
		}
	}
	return nil
}

func isHexSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// ArtifactFor picks the build for one platform, matching case-insensitively.
// The second return is false when the campaign published nothing for it —
// which the agent reports as its own platform's gap, not as a generic failure.
func ArtifactFor(artifacts []Artifact, goos, goarch string) (Artifact, bool) {
	for _, a := range artifacts {
		if strings.EqualFold(strings.TrimSpace(a.OS), goos) && strings.EqualFold(strings.TrimSpace(a.Arch), goarch) {
			return a, true
		}
	}
	return Artifact{}, false
}

// EncodeArtifacts round-trips the list for the campaign row's jsonb column.
// nil in, nil out: an observe-only campaign stores NULL, never "[]", so the
// column cannot show an empty publication where there was no publication.
func EncodeArtifacts(artifacts []Artifact) ([]byte, error) {
	if len(artifacts) == 0 {
		return nil, nil
	}
	return json.Marshal(artifacts)
}

// DecodeArtifacts is EncodeArtifacts' inverse; NULL/empty decodes to nil.
func DecodeArtifacts(raw []byte) ([]Artifact, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var out []Artifact
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ArtifactSignedMessage is the exact bytes a publisher signs for one artifact:
// the raw SHA-256 digest the campaign pins. Signing the digest rather than the
// file keeps the signature bound to the same bytes the agent verifies and lets
// a publisher sign a release manifest without re-reading every binary.
func ArtifactSignedMessage(sha256Hex string) ([]byte, error) {
	if !isHexSHA256(sha256Hex) {
		return nil, fmt.Errorf("agentupgrade: sha256 must be 64 hex characters")
	}
	return hex.DecodeString(strings.ToLower(sha256Hex))
}

// VerifyArtifactSignature checks the artifact's publisher signature (A68): a
// base64 Ed25519 signature over ArtifactSignedMessage, against the pinned
// publisher public key (PKIX DER). It fails closed on a missing, malformed or
// mismatched signature; the digest pin alone is not enough once a key is pinned.
func VerifyArtifactSignature(a Artifact, publisherKeyDER []byte) error {
	if len(publisherKeyDER) == 0 {
		return fmt.Errorf("agentupgrade: no publisher key pinned")
	}
	if strings.TrimSpace(a.Signature) == "" {
		return fmt.Errorf("agentupgrade: artifact %s/%s carries no publisher signature", a.OS, a.Arch)
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(a.Signature))
	if err != nil {
		return fmt.Errorf("agentupgrade: artifact %s/%s signature is not base64: %w", a.OS, a.Arch, err)
	}
	msg, err := ArtifactSignedMessage(a.SHA256)
	if err != nil {
		return err
	}
	if err := crypto.VerifyEd25519(publisherKeyDER, msg, sig); err != nil {
		return fmt.Errorf("agentupgrade: artifact %s/%s publisher signature does not verify against the pinned key", a.OS, a.Arch)
	}
	return nil
}

// ValidateArtifactSignatures refuses a campaign whose artifacts are not all
// signed by the pinned publisher key. A control plane with no key pinned
// accepts the digest pin alone and says so in its limitations.
func ValidateArtifactSignatures(artifacts []Artifact, publisherKeyDER []byte) error {
	if len(publisherKeyDER) == 0 {
		return nil
	}
	for i, a := range artifacts {
		if err := VerifyArtifactSignature(a, publisherKeyDER); err != nil {
			return fmt.Errorf("artifact %d: %w; this control plane pins an upgrade publisher key, so every artifact must carry that publisher's Ed25519 signature over its sha256", i, err)
		}
	}
	return nil
}

// SignArtifact produces the publisher signature VerifyArtifactSignature
// checks, from a PEM-encoded Ed25519 private key. Release tooling and tests
// use it; the control plane and the agent only ever verify.
func SignArtifact(a Artifact, publisherPrivatePEM []byte) (string, error) {
	msg, err := ArtifactSignedMessage(a.SHA256)
	if err != nil {
		return "", err
	}
	sig, err := crypto.SignEd25519(publisherPrivatePEM, msg)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}
