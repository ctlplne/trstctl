// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/agent/sshkrl"
	"trstctl.com/trstctl/internal/crypto"
	sshprotocol "trstctl.com/trstctl/internal/protocols/ssh"
)

type krlTestChecks struct{ target string }

func (k krlTestChecks) ActiveKRLPath(context.Context, string) (string, error) { return k.target, nil }
func (k krlTestChecks) ValidateKRL(_ context.Context, path string) error {
	b, err := os.ReadFile(path) // #nosec G304 -- test fixture path created under t.TempDir
	if err != nil {
		return err
	}
	_, err = sshkrl.Version(b)
	return err
}
func (k krlTestChecks) ValidateSSHD(context.Context, string) error { return nil }
func (k krlTestChecks) Reload(context.Context) error               { return nil }
func (k krlTestChecks) Health(context.Context) error               { return nil }

func TestAgentKRLApplyRequiresConfirmation(t *testing.T) {
	var o sshKRLOptions
	o.apply = true
	handled, err := runSSHKRLApply(context.Background(), o, krlTestChecks{})
	if !handled || err == nil || !strings.Contains(err.Error(), "--ssh-krl-confirm") {
		t.Fatalf("handled=%v err=%v", handled, err)
	}
	o.apply = false
	handled, err = runSSHKRLApply(context.Background(), o, krlTestChecks{})
	if handled || err != nil {
		t.Fatalf("disabled one-shot handled=%v err=%v", handled, err)
	}
}

func TestAgentKRLApplyUsesPinnedFileAndDurableRollback(t *testing.T) {
	dir := t.TempDir()
	current := sshprotocol.NewKRL().DistributeKRL(1)
	k := sshprotocol.NewKRL()
	k.RevokeSerial(77)
	next := k.DistributeKRL(2)
	target := filepath.Join(dir, "revoked_keys")
	input := filepath.Join(dir, "downloaded.krl")
	for path, data := range map[string][]byte{target: current, input: next} {
		if err := os.WriteFile(path, data, 0o644); err != nil { // #nosec G306 -- public KRL fixture checks the operator's existing mode
			t.Fatal(err)
		}
	}
	o := sshKRLOptions{apply: true, confirm: true, file: input, sha256: crypto.SHA256Hex(next), target: target, sshdConfig: filepath.Join(dir, "sshd_config"), rollbackDir: filepath.Join(dir, "rollbacks"), reloadCmd: "true", healthCmd: "true"}
	handled, err := runSSHKRLApply(context.Background(), o, krlTestChecks{target: target})
	if !handled || err != nil {
		t.Fatalf("handled=%v err=%v", handled, err)
	}
	installed, err := os.ReadFile(target) // #nosec G304 -- test fixture target under t.TempDir
	if err != nil || !bytes.Equal(installed, next) {
		t.Fatalf("installed KRL mismatch: %v", err)
	}
	entries, err := os.ReadDir(o.rollbackDir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("durable predecessor entries=%d err=%v", len(entries), err)
	}
}

func TestProductionOpenSSHValidatesCompleteKRL(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("stock OpenSSH client is unavailable on this test host")
	}
	valid := sshprotocol.NewKRL().DistributeKRL(2)
	path := filepath.Join(t.TempDir(), "candidate.krl")
	if err := os.WriteFile(path, valid, 0o600); err != nil {
		t.Fatal(err)
	}
	checks := sshdKRLChecks{}
	if err := checks.ValidateKRL(context.Background(), path); err != nil {
		t.Fatalf("valid OpenSSH KRL rejected: %v", err)
	}
	if err := os.WriteFile(path, valid[:len(valid)-1], 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checks.ValidateKRL(context.Background(), path); err == nil {
		t.Fatal("truncated KRL passed stock OpenSSH validation")
	}
}

func TestKRLHealthRetriesATransientReloadRefusal(t *testing.T) {
	attempts := 0
	err := retryKRLHealth(context.Background(), func(context.Context) error {
		attempts++
		if attempts == 1 {
			return errors.New("connection refused during sshd SIGHUP")
		}
		return nil
	})
	if err != nil || attempts != 2 {
		t.Fatalf("transient health refusal: attempts=%d err=%v", attempts, err)
	}
}

func TestKRLHealthStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := retryKRLHealth(ctx, func(context.Context) error { return errors.New("unhealthy") }); err == nil {
		t.Fatal("canceled health probe was treated as healthy")
	}
}
