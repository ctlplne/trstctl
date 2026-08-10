// SPDX-License-Identifier: MPL-2.0

package agentupgrade

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
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
			return fmt.Errorf("artifact %d: os and arch are required; the agent picks its build by platform and an unlabelled artifact matches nothing", i)
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
