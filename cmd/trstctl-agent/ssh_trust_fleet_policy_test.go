// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFleetPolicyRequiresLocalOptInConfirmationAndExistingConfig(t *testing.T) {
	disabled, err := newSSHFleetPolicyLoader(sshTrustOptions{}).load(true)
	if err != nil || disabled.Readiness.Enabled || disabled.Readiness.Ready() {
		t.Fatalf("default trust mode is not off: %+v %v", disabled, err)
	}
	missing, err := newSSHFleetPolicyLoader(sshTrustOptions{fleet: true}).load(true)
	if err != nil || missing.Readiness.Confirmed || missing.Readiness.Ready() {
		t.Fatalf("implicit confirmation: %+v %v", missing, err)
	}
	_, err = newSSHFleetPolicyLoader(sshTrustOptions{fleet: true, confirm: true}).load(true)
	if err == nil {
		t.Fatal("fleet mode accepted no staged public CA")
	}
}

func TestFleetPolicyFreshHashRefusesMetadataPreservingExecutableReplacement(t *testing.T) {
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pub")
	config := filepath.Join(dir, "sshd_config")
	action := filepath.Join(dir, "owned-action")
	for path, data := range map[string][]byte{ca: []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPexCbv5HmN6JhIN7b1GaDxkyWFY3uSrHBvKdlQYHONt local-public-pin\n"), config: []byte("Port 2222\n"), action: []byte("#!/bin/sh\nexit 0\n")} {
		if err := os.WriteFile(path, data, 0o700); err != nil { // #nosec G306 -- executable fixture owned by this test; its executable bit is the behavior under test (CWE-276).
			t.Fatal(err)
		}
	}
	options := sshTrustOptions{fleet: true, confirm: true, caKeyPath: ca, sshdConfig: config, trustedKeys: filepath.Join(dir, "trusted_keys"), validateCmd: action, reloadCmd: action, healthCmd: action}
	loader := newSSHFleetPolicyLoader(options)
	first, err := loader.load(true)
	if err != nil || !first.Readiness.Ready() {
		t.Fatalf("configured policy=%+v %v", first, err)
	}
	info, err := os.Stat(action)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(action, []byte("#!/bin/sh\nexit 1\n"), 0o700); err != nil { // #nosec G306 -- replace the owned executable fixture while retaining its mode (CWE-276).
		t.Fatal(err)
	}
	if err := os.Chtimes(action, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	refreshed, err := loader.load(true)
	if err != nil || !refreshed.Readiness.Ready() || refreshed.Readiness.PolicyDigest == first.Readiness.PolicyDigest {
		t.Fatalf("changed action inherited reviewed authority: %+v %v", refreshed, err)
	}
	if err := os.Remove(config); err != nil {
		t.Fatal(err)
	}
	bad, err := loader.load(true)
	if err == nil || bad.Readiness.Ready() || bad.Readiness.IssueCode != "local_configuration_invalid" {
		t.Fatalf("missing configuration reported ready: %+v %v", bad, err)
	}
}

func TestSSHHostMutationSlotSerializesKRLAndFleetAndHonorsCancellation(t *testing.T) {
	release, err := acquireSSHHostMutation(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if _, err := acquireSSHHostMutation(ctx); !errors.Is(err, context.DeadlineExceeded) {
		release()
		t.Fatalf("a concurrent mutation entered the occupied slot: %v", err)
	}
	release()
	next, err := acquireSSHHostMutation(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	next()
}

func TestPinnedSSHActionUsesValidatedPrimitiveWithoutOutputInErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "health-action")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nprintf 'untrusted-health-output' >&2\nexit 1\n"), 0o700); err != nil { // #nosec G306 -- owned executable fixture needed to check error-output suppression (CWE-276).
		t.Fatal(err)
	}
	err := runPinnedSSHCommand(t.Context(), pinnedSSHCommand{Argv: []string{path}})
	if err == nil || strings.Contains(err.Error(), "untrusted-health-output") || strings.Contains(err.Error(), path) {
		t.Fatalf("fleet command leaked local command/output detail: %v", err)
	}
}
