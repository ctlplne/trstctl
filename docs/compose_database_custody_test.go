// SPDX-License-Identifier: BUSL-1.1

package docs

import (
	"slices"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestComposeKeepsSigningSecretsReadOnlyOutsideSigner(t *testing.T) {
	type service struct {
		Volumes     []string          `yaml:"volumes"`
		Environment map[string]string `yaml:"environment"`
	}
	var primary, backup struct {
		Services map[string]service `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(read(t, "../deploy/docker/docker-compose.yml")), &primary); err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal([]byte(read(t, "../deploy/docker/docker-compose.backup.yml")), &backup); err != nil {
		t.Fatal(err)
	}
	controlPlane := primary.Services["trstctl"]
	if !slices.Contains(controlPlane.Volumes, "secrets:/data/secrets:ro") || slices.Contains(controlPlane.Volumes, "secrets:/data/secrets") {
		t.Error("control plane must mount signing secrets read-only")
	}
	if !slices.Contains(primary.Services["signer"].Volumes, "secrets:/data/secrets") {
		t.Error("signer must create and retain the shared signing secrets")
	}
	if !slices.Contains(backup.Services["dr-backup"].Volumes, "secrets:/data/secrets:ro") {
		t.Error("backup must mount signing secrets read-only")
	}
	if controlPlane.Environment["TRSTCTL_AUTH_OIDC_SESSION_SECRET_FILE"] != "/data/oidc-session.secret" {
		t.Error("the eval OIDC cookie key needs a writable application data location")
	}
}
