// SPDX-License-Identifier: BUSL-1.1

package docker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A replace directive is resolved while Go reads the module graph. Every image
// stage that copies the root go.mod must provide the pinned local SAML module's
// metadata before its first Go command, including stages that build only a
// trust helper or an upstream executable.
func TestImageModuleStagesCopyPinnedSAMLMetadataBeforeGo(t *testing.T) {
	for _, name := range []string{
		"Dockerfile", "Dockerfile.agent-pkcs11", "Dockerfile.nats", "Dockerfile.node",
		"Dockerfile.postgres", "Dockerfile.signer-hsm", "../demo/Dockerfile.seed",
		"../../tools/dodcensus/Dockerfile.runtime-runner",
	} {
		t.Run(filepath.Base(name), func(t *testing.T) {
			body, err := os.ReadFile(name) // #nosec G304 -- fixed repository Dockerfile list (CWE-22)
			if err != nil {
				t.Fatal(err)
			}
			lines := strings.Split(string(body), "\n")
			found := 0
			for i, line := range lines {
				if !strings.HasPrefix(line, "COPY go.mod go.sum ") {
					continue
				}
				found++
				if i+1 == len(lines) || !strings.HasPrefix(lines[i+1],
					"COPY internal/crypto/crewjamsaml/go.mod internal/crypto/crewjamsaml/go.sum ") {
					t.Errorf("%s:%d: local SAML module metadata is missing before the Go command", name, i+1)
				}
			}
			if found == 0 {
				t.Fatal("image no longer copies the root module; review this gate against its new build path")
			}
		})
	}
}
