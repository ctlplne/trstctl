// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

func TestSignerFIPSRequiredFailsClosedBeforeListening(t *testing.T) {
	if os.Getenv("TRSTCTL_TEST_SIGNER_FIPS_HELPER") == "1" {
		for i, arg := range os.Args {
			if arg == "--" {
				os.Args = append(os.Args[:1], os.Args[i+1:]...)
				break
			}
		}
		flag.CommandLine = flag.NewFlagSet("trstctl-signer", flag.ExitOnError)
		main()
		return
	}
	if crypto.FIPSEnabled() {
		t.Skip("inactive refusal is covered by the default non-FIPS test build")
	}
	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		args []string
		env  string
	}{
		{name: "flag", args: []string{"--fips"}},
		{name: "environment", env: "TRSTCTL_FIPS=1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			args := []string{"-test.run=^TestSignerFIPSRequiredFailsClosedBeforeListening$", "--",
				"--socket=" + filepath.Join(t.TempDir(), "signer.sock"), "--allow-insecure-dev-nonlinux"}
			args = append(args, test.args...)
			cmd := exec.CommandContext(ctx, testExecutable, args...) // #nosec G204 -- current local test executable and bounded QA flags
			cmd.Env = append(os.Environ(), "TRSTCTL_TEST_SIGNER_FIPS_HELPER=1")
			if test.env != "" {
				cmd.Env = append(cmd.Env, test.env)
			}
			var output bytes.Buffer
			cmd.Stderr = &output
			err := cmd.Run()
			if ctx.Err() != nil {
				t.Fatal("signer failed to refuse inactive FIPS before listening")
			}
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 1 {
				t.Fatalf("signer exit = %v, want fail-closed status 1; stderr=%s", err, output.String())
			}
			if !strings.Contains(output.String(), "crypto power-on self-test") || !strings.Contains(output.String(), "FIPS cryptographic module is not active") {
				t.Fatalf("signer did not report the FIPS refusal: %s", output.String())
			}
		})
	}
}
