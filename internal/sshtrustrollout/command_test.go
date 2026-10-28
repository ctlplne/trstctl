// SPDX-License-Identifier: BUSL-1.1

package sshtrustrollout

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func reviewedCommand(t testing.TB) Command {
	t.Helper()
	key := []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPexCbv5HmN6JhIN7b1GaDxkyWFY3uSrHBvKdlQYHONt fleet-public-fixture")
	canonical, fingerprint, err := CanonicalPublicCAKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return Command{RolloutID: "a2260000-0000-4000-8000-000000000001", AgentID: "a2260000-0000-4000-8000-000000000002", PublicCAKey: canonical, CAFingerprint: fingerprint, PlanDigest: "sha256:" + strings.Repeat("a", 64), ReadinessDigest: "sha256:" + strings.Repeat("b", 64), ExpiresAt: time.Now().UTC().Add(time.Hour)}
}

func TestRemoteTrustJobCannotChooseCommandsPathsOrConfirmation(t *testing.T) {
	command := reviewedCommand(t)
	data, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeCommand(strings.NewReader(string(data))); err != nil {
		t.Fatal(err)
	}
	for _, extra := range []string{`"reload_command":"arbitrary-executable"`, `"trusted_keys_path":"/other/trust"`, `"mode":"remove"`, `"confirmed":true`} {
		bad := strings.TrimSuffix(string(data), "}") + "," + extra + "}"
		if _, err = DecodeCommand(strings.NewReader(bad)); err == nil {
			t.Fatalf("accepted remote authority %s", extra)
		}
	}
	command.PublicCAKey = append(command.PublicCAKey, []byte("\nssh-ed25519 another-authority")...)
	if err = command.Validate(); err == nil {
		t.Fatal("accepted multiple trust lines")
	}
}

func TestHostOptInConfirmationBindingAndDeadlineRemainLocal(t *testing.T) {
	command := reviewedCommand(t)
	local := LocalAuthority{Enabled: true, Confirmed: true, AllowedCAFingerprint: command.CAFingerprint, AgentID: command.AgentID, ReadinessDigest: command.ReadinessDigest}
	if err := command.PermitLocal(local, time.Now()); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*LocalAuthority){"unstaged-ca": func(a *LocalAuthority) { a.AllowedCAFingerprint = "another-ca" },
		"opt-out": func(a *LocalAuthority) { a.Enabled = false }, "unconfirmed": func(a *LocalAuthority) { a.Confirmed = false }, "other-agent": func(a *LocalAuthority) { a.AgentID = "a2260000-0000-4000-8000-000000000003" }, "changed-settings": func(a *LocalAuthority) { a.ReadinessDigest = "sha256:" + strings.Repeat("c", 64) }} {
		t.Run(name, func(t *testing.T) {
			bad := local
			change(&bad)
			if err := command.PermitLocal(bad, time.Now()); err == nil {
				t.Fatal("accepted unreviewed local authority")
			}
		})
	}
	if err := command.PermitLocal(local, command.ExpiresAt); err == nil {
		t.Fatal("accepted expired execution")
	}
}
