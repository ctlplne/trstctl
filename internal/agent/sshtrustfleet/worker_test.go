// SPDX-License-Identifier: BUSL-1.1

package sshtrustfleet

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/sshtrust"
	"trstctl.com/trstctl/internal/sshtrustrollout"
)

type fleetFS struct {
	files  map[string][]byte
	writes int
}

func (f *fleetFS) ReadFile(path string) ([]byte, error) {
	value, ok := f.files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return append([]byte(nil), value...), nil
}
func (f *fleetFS) Exists(path string) bool  { _, ok := f.files[path]; return ok }
func (f *fleetFS) Remove(path string) error { delete(f.files, path); return nil }
func (f *fleetFS) WriteFileAtomic(path string, value []byte, _ os.FileMode) error {
	f.writes++
	f.files[path] = append([]byte(nil), value...)
	return nil
}

type fleetChecks struct {
	reloads, health int
	failHealth      bool
}

func (*fleetChecks) Validate(context.Context) error { return nil }
func (c *fleetChecks) Reload(context.Context) error { c.reloads++; return nil }
func (c *fleetChecks) HealthCheck(context.Context) error {
	c.health++
	if c.failHealth && c.health == 1 {
		return errors.New("first daemon health check failed")
	}
	return nil
}

func fleetFixture(t *testing.T) (*fleetFS, *fleetChecks, sshtrust.Config, sshtrustrollout.Command, sshtrustrollout.LocalAuthority) {
	t.Helper()
	key, fingerprint, err := sshtrustrollout.CanonicalPublicCAKey([]byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPexCbv5HmN6JhIN7b1GaDxkyWFY3uSrHBvKdlQYHONt"))
	if err != nil {
		t.Fatal(err)
	}
	f := &fleetFS{files: map[string][]byte{"/owned/sshd_config": []byte("Port 2222\n")}}
	c := &fleetChecks{}
	config := sshtrust.Config{FS: f, Reloader: c, SSHDConfigPath: "/owned/sshd_config", TrustedUserCAKeysPath: "/owned/ca_keys"}
	command := sshtrustrollout.Command{RolloutID: "a2260000-0000-4000-8000-000000000001", AgentID: "a2260000-0000-4000-8000-000000000002", PublicCAKey: key, CAFingerprint: fingerprint, PlanDigest: "sha256:" + strings.Repeat("a", 64), ReadinessDigest: "sha256:" + strings.Repeat("b", 64), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	local := sshtrustrollout.LocalAuthority{Enabled: true, Confirmed: true, AllowedCAFingerprint: fingerprint, AgentID: command.AgentID, ReadinessDigest: command.ReadinessDigest}
	return f, c, config, command, local
}

func TestFleetWorkerLocalRefusalsNeverTouchSSHD(t *testing.T) {
	for name, change := range map[string]func(*sshtrustrollout.LocalAuthority){
		"local_not_enabled": func(a *sshtrustrollout.LocalAuthority) { a.Enabled = false },
		"local_unconfirmed": func(a *sshtrustrollout.LocalAuthority) { a.Confirmed = false },
		"ca_pin_changed":    func(a *sshtrustrollout.LocalAuthority) { a.AllowedCAFingerprint = "another-ca" },
		"policy_changed":    func(a *sshtrustrollout.LocalAuthority) { a.ReadinessDigest = "another-policy" },
		"other_agent":       func(a *sshtrustrollout.LocalAuthority) { a.AgentID = "another-agent" },
	} {
		t.Run(name, func(t *testing.T) {
			fs, checks, config, command, local := fleetFixture(t)
			change(&local)
			report, err := Execute(context.Background(), "owned-tenant", config, local, command)
			if err == nil || report.State != "refused" || report.ReasonCode != name || fs.writes != 0 || checks.reloads != 0 {
				t.Fatalf("unsafe refusal: %+v err=%v writes=%d reloads=%d", report, err, fs.writes, checks.reloads)
			}
			_, digest, err := report.Encode()
			if err != nil {
				t.Fatal(err)
			}
			if err := report.Validate(command, digest); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFleetWorkerReportsIndependentEffectAndVerifiedRollback(t *testing.T) {
	fs, checks, config, command, local := fleetFixture(t)
	report, err := Execute(context.Background(), "owned-tenant", config, local, command)
	if err != nil || report.State != "verified" || !report.CAReadBack || !report.EffectiveConfigReadBack || !report.Healthy {
		t.Fatalf("missing effect: %+v %v", report, err)
	}
	before := fs.writes
	retry, err := Execute(context.Background(), "owned-tenant", config, local, command)
	if err != nil || retry.Changed || fs.writes != before || checks.reloads != 2 {
		t.Fatalf("unsafe retry: %+v %v", retry, err)
	}
	fs, checks, config, command, local = fleetFixture(t)
	checks.failHealth = true
	report, err = Execute(context.Background(), "owned-tenant", config, local, command)
	if err == nil || report.State != "failed" || report.ReasonCode != "apply_failed" || report.Rollback != "verified" || report.Phase != "health" {
		t.Fatalf("false apply/rollback: %+v %v", report, err)
	}
	if string(fs.files["/owned/sshd_config"]) != "Port 2222\n" || fs.Exists("/owned/ca_keys") {
		t.Fatal("rollback did not restore the exact predecessor")
	}
	_, digest, err := report.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := report.Validate(command, digest); err != nil {
		t.Fatal(err)
	}
}

func TestFleetWorkerExpiredServerWindowAndCancellationDoNotWrite(t *testing.T) {
	fs, _, config, command, local := fleetFixture(t)
	report, err := ExecuteAt(context.Background(), "owned-tenant", config, local, command, command.ExpiresAt)
	if err == nil || report.ReasonCode != "execution_window_ended" || fs.writes != 0 {
		t.Fatalf("expired write: %+v %v", report, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	report, err = ExecuteAt(ctx, "owned-tenant", config, local, command, time.Now().UTC())
	if err == nil || report.ReasonCode != "canceled" || fs.writes != 0 {
		t.Fatalf("canceled write: %+v %v", report, err)
	}
}
