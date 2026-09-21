// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRepoWideMulticheckerRunsAndFailsPlantedViolations(t *testing.T) {
	root := repoRoot(t)
	bin := filepath.Join(t.TempDir(), "trstctllint")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	runCmd(t, root, "go", "build", "-o", bin, "./tools/trstctllint")

	clean := exec.Command(bin, "./...") // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
	clean.Dir = root
	clean.Env = linterCommandEnv(t)
	if out, err := clean.CombinedOutput(); err != nil {
		t.Fatalf("repo-wide trstctllint ./... failed on clean tree: %v\n%s", err, out)
	}

	fixture := t.TempDir()
	writeFile(t, filepath.Join(fixture, "go.mod"), "module trstctl.com/trstctl\n\ngo 1.22\n")
	writeFile(t, filepath.Join(fixture, "badcrypto", "bad.go"), `// SPDX-License-Identifier: BUSL-1.1

package badcrypto

import _ "crypto/x509"
`)
	writeFile(t, filepath.Join(fixture, "internal", "api", "secrets.go"), `// SPDX-License-Identifier: BUSL-1.1

package api

type issueRequest struct {
	Credential string
}

func leak(credential []byte) string {
	return string(credential)
}
`)
	writeFile(t, filepath.Join(fixture, "internal", "crypto", "agility.go"), `// SPDX-License-Identifier: BUSL-1.1

package crypto

import _ "trstctl.com/trstctl/internal/policy"

var providerRegistry = map[string]any{}
`)
	writeFile(t, filepath.Join(fixture, "internal", "policy", "policy.go"), `// SPDX-License-Identifier: BUSL-1.1

package policy
`)
	writeFile(t, filepath.Join(fixture, "internal", "badnetexec", "bad.go"), `// SPDX-License-Identifier: BUSL-1.1

package badnetexec

import (
	"net/http"
	"os/exec"
	"time"
)

var client = http.DefaultClient

func reload() error {
	return exec.Command("sh", "-c", "reload").Run()
}

func ambient(url string) error {
	c := &http.Client{Timeout: time.Second}
	if _, err := c.Get(url); err != nil {
		return err
	}
	_, err := http.Get(url)
	return err
}
`)
	writeFile(t, filepath.Join(fixture, "internal", "badlicense", "missing_spdx.go"), `package badlicense
`)
	writeFile(t, filepath.Join(fixture, "internal", "badimport", "bad.go"), `// SPDX-License-Identifier: BUSL-1.1

package badimport

import _ "trstctl.com/trstctl/ee/billing"
`)
	writeFile(t, filepath.Join(fixture, "ee", "billing", "billing.go"), `// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing
`)
	writeFile(t, filepath.Join(fixture, "ee", "badspdx", "bad.go"), `// SPDX-License-Identifier: MPL-2.0

package badspdx
`)
	writeFile(t, filepath.Join(fixture, "clients", "okclient", "ok.go"), `// SPDX-License-Identifier: MPL-2.0

package okclient
`)
	writeFile(t, filepath.Join(fixture, "clients", "badclient", "bad.go"), `// SPDX-License-Identifier: BUSL-1.1

package badclient
`)

	planted := exec.Command(bin, "./...") // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
	planted.Dir = fixture
	planted.Env = linterCommandEnv(t)
	out, err := planted.CombinedOutput()
	if err == nil {
		t.Fatalf("trstctllint accepted planted violations; output:\n%s", out)
	}
	got := string(out)
	for _, want := range []string{
		`import "crypto/x509" is not allowed outside internal/crypto`,
		"secret-bearing API/auth field must not use string",
		"secret-bearing API/auth code must not convert secret bytes to string",
		`import "trstctl.com/trstctl/internal/policy" is not allowed in the crypto/signer boundary`,
		`runtime-mutable crypto provider/engine registry "providerRegistry" is not allowed`,
		"http.DefaultClient is not allowed in new outbound surfaces",
		"ambient http.Client construction is not allowed in new outbound surfaces",
		"http.Get/http.Head/http.Post/http.PostForm are not allowed",
		"direct shell interpreter execution is not allowed",
		"core file must carry SPDX-License-Identifier: BUSL-1.1",
		"core file imports \"trstctl.com/trstctl/ee/billing\"",
		"ee/ file must not carry SPDX-License-Identifier: MPL-2.0",
		"clients/ file must not carry SPDX-License-Identifier: BUSL-1.1",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("planted violation output missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "okclient") {
		t.Fatalf("trstctllint reported the MPL-2.0 clients/ fixture, which is the license that tree must carry:\n%s", got)
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func commandEnv(t *testing.T) []string {
	t.Helper()
	env := os.Environ()
	if os.Getenv("GOCACHE") == "" {
		env = append(env, "GOCACHE="+filepath.Join(t.TempDir(), "gocache"))
	}
	return env
}

func linterCommandEnv(t *testing.T) []string {
	t.Helper()
	env := commandEnv(t)
	// Whole-repository type loading creates substantial temporary garbage.
	// Bound the analyzer's soft memory target so it collects that garbage
	// before exhausting a local test host. This applies only to these linter
	// children, never to product or performance-test processes. An explicit
	// operator setting remains authoritative.
	if os.Getenv("GOMEMLIMIT") == "" {
		env = append(env, "GOMEMLIMIT=1536MiB")
	}
	return env
}

func runCmd(t *testing.T, dir, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...) // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
	cmd.Dir = dir
	cmd.Env = commandEnv(t)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %s failed: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
