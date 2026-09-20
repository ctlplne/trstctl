// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Run the actual entry point in a subprocess, with a fresh FlagSet, so its exit
// status and early refusal are tested without starting a configured service.
func TestAgentCLIArgumentBoundary(t *testing.T) {
	if os.Getenv("TRSTCTL_TEST_Agent_ARGS_HELPER") == "1" {
		for i, arg := range os.Args {
			if arg == "--" {
				os.Args = append(os.Args[:1], os.Args[i+1:]...)
				break
			}
		}
		flag.CommandLine = flag.NewFlagSet("trstctl-agent", flag.ExitOnError)
		main()
		os.Exit(0)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// Keep the subprocess command fixed and constrain both file operations to
	// opened directories. The helper is this exact race/tag-instrumented test
	// executable, copied once into an owned directory; no PATH search is used.
	workingDir := t.TempDir()
	sourceRoot, err := os.OpenRoot(filepath.Dir(executable))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := sourceRoot.Close(); err != nil {
			t.Error(err)
		}
	})
	source, err := sourceRoot.Open(filepath.Base(executable))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := source.Close(); err != nil {
			t.Error(err)
		}
	})
	root, err := os.OpenRoot(workingDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	})
	helper, err := root.OpenFile("daemon-test.exe", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	_, copyErr := io.Copy(helper, source)
	closeErr := helper.Close()
	if copyErr != nil || closeErr != nil {
		t.Fatalf("copy test executable: %v; close: %v", copyErr, closeErr)
	}
	for _, tc := range []struct {
		name    string
		invalid bool
		command func(context.Context) *exec.Cmd
	}{
		{"version", false, func(ctx context.Context) *exec.Cmd {
			return exec.CommandContext(ctx, "./daemon-test.exe", "-test.run=^TestAgentCLIArgumentBoundary$", "--", "--version")
		}},
		{"help", false, func(ctx context.Context) *exec.Cmd {
			return exec.CommandContext(ctx, "./daemon-test.exe", "-test.run=^TestAgentCLIArgumentBoundary$", "--", "--help")
		}},
		{"unexpected", true, func(ctx context.Context) *exec.Cmd {
			return exec.CommandContext(ctx, "./daemon-test.exe", "-test.run=^TestAgentCLIArgumentBoundary$", "--", "--version", "qa-private-operand")
		}},
		{"after-separator", true, func(ctx context.Context) *exec.Cmd {
			return exec.CommandContext(ctx, "./daemon-test.exe", "-test.run=^TestAgentCLIArgumentBoundary$", "--", "--version", "--", "qa-private-operand")
		}},
		{"ignored-tail-flags", true, func(ctx context.Context) *exec.Cmd {
			return exec.CommandContext(ctx, "./daemon-test.exe", "-test.run=^TestAgentCLIArgumentBoundary$", "--", "--version", "qa-private-operand", "--version")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			cmd := tc.command(ctx)
			cmd.Env = append(os.Environ(), "TRSTCTL_TEST_Agent_ARGS_HELPER=1")
			cmd.Dir = workingDir
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()
			if ctx.Err() != nil {
				t.Fatal("CLI did not exit within the command bound")
			}
			if tc.invalid {
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 2 {
					t.Fatalf("unexpected argument returned %v; stdout=%q stderr=%q", err, stdout.String(), stderr.String())
				}
				if stdout.Len() != 0 || !strings.Contains(stderr.String(), "unexpected") || !strings.Contains(stderr.String(), "--help") {
					t.Fatalf("missing early refusal guidance: stdout=%q stderr=%q", stdout.String(), stderr.String())
				}
				if strings.Contains(stderr.String(), "qa-private-operand") {
					t.Fatal("refusal repeated a potentially sensitive operand")
				}
			} else if err != nil {
				t.Fatalf("supported command refused: %v %s", err, stderr.String())
			}
			entries, err := os.ReadDir(cmd.Dir)
			if err != nil || len(entries) != 1 || entries[0].Name() != "daemon-test.exe" {
				t.Fatalf("read-only command wrote files: entries=%v err=%v", entries, err)
			}
		})
	}
}
