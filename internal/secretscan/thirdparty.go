// SPDX-License-Identifier: BUSL-1.1

package secretscan

import (
	"errors"
	"path/filepath"
	"strings"
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
