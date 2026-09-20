// SPDX-License-Identifier: BUSL-1.1

package licenseboundary

import (
	"testing"
)

func TestRepoSourcePathIgnoresCheckoutParentNames(t *testing.T) {
	filename := "/Users/example/Desktop/ctlplne-trstctl/qa-worktrees/dev/docs/aud65_test.go"
	if got, want := repoSourcePath(filename, modulePath+"/docs"), "docs/aud65_test.go"; got != want {
		t.Fatalf("repoSourcePath() = %q, want %q", got, want)
	}
	if got, want := repoSourcePath(filename, modulePath+"/docs_test"), "docs/aud65_test.go"; got != want {
		t.Fatalf("repoSourcePath() for external test package = %q, want %q", got, want)
	}
	attach := "/workspace/qa-worktrees/dev/cmd/trstctl/ee_attach.go"
	if got, want := repoSourcePath(attach, modulePath+"/cmd/trstctl.test"), "cmd/trstctl/ee_attach.go"; got != want {
		t.Fatalf("repoSourcePath() for synthetic test package = %q, want %q", got, want)
	}

	eeFilename := "/tmp/a-path-containing-pqc-and-core/internal/pqc/service.go"
	if got, want := repoSourcePath(eeFilename, modulePath+"/internal/pqc"), "internal/pqc/service.go"; got != want {
		t.Fatalf("repoSourcePath() for EE = %q, want %q", got, want)
	}
}

func TestClientTreeIsClassifiedByRepositoryRelativePath(t *testing.T) {
	for _, path := range []string{"clients/embedded/embedded.go", "clients/sdk/go/trstctl/client.go"} {
		if !isClientPath(path) {
			t.Fatalf("client tree path %q was not classified as clients/", path)
		}
	}
	for _, path := range []string{
		"internal/server/clients.go",
		"cmd/trstctl/clients_cmd.go",
		"ee/provider/clients.go",
		"/workspace/clients/embedded/embedded.go",
	} {
		if isClientPath(path) {
			t.Fatalf("non-client path %q was classified as clients/", path)
		}
	}
}

func TestTaggedAttachSeamsAcceptRepositoryRelativePaths(t *testing.T) {
	for _, filename := range []string{
		"cmd/trstctl/ee_attach.go",
		"cmd/trstctl-signer/ee_attach.go",
	} {
		if !isTaggedAttachSeam(filename) {
			t.Fatalf("repository-relative attach seam %q was rejected", filename)
		}
	}
	if isTaggedAttachSeam("internal/api/ee_attach.go") {
		t.Fatal("unapproved repository-relative attach seam was accepted")
	}
	if isTaggedAttachSeam("cmd/trstctl-agent/cosign_attach.go") {
		t.Fatal("the agent co-sign seam imports nothing from ee/ since PCAS moved into the core and must not be fenced")
	}
}

func TestVendoredEmbeddedPostgresLicenseBoundaryIsExact(t *testing.T) {
	for _, path := range []string{
		"third_party/embedded-postgres/embedded_postgres.go",
		"third_party/embedded-postgres/remote_fetch_test.go",
	} {
		if !isEmbeddedPostgresSource(path) {
			t.Fatalf("fixture escaped exact vendored source prefix: %s", path)
		}
	}
	for _, path := range []string{
		"third_party/other/library.go",
		"internal/embedded-postgres/library.go",
	} {
		if isEmbeddedPostgresSource(path) {
			t.Fatalf("unrelated source acquired the MIT boundary: %s", path)
		}
	}
}
