// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"trstctl.com/trstctl/internal/agent"
	"trstctl.com/trstctl/internal/agent/sshdiscovery"
	"trstctl.com/trstctl/internal/agent/sshkrl"
	"trstctl.com/trstctl/internal/crypto"
)

// agentAuthorizedKey's OpenSSH fingerprint (internal/crypto/sshkeys tests).
const agentAuthorizedKeyFP = "SHA256:eg0upccGdZXXLvQU+nKO1PwItOw1TX8CCe3NwH6DnLE"

func sshTrustFinding(t *testing.T, findings []agent.InventoryFinding) agent.InventoryFinding {
	t.Helper()
	var out []agent.InventoryFinding
	for _, f := range findings {
		if f.Kind == sshdiscovery.TrustFindingKind {
			out = append(out, f)
		}
	}
	if len(out) != 1 {
		t.Fatalf("ssh_trust findings = %d in %+v, want 1", len(out), findings)
	}
	return out[0]
}

// A115: an agent given an sshd_config reports that configuration's trust
// posture beside its keys — the trusted CA fingerprint, the RevokedKeys KRL's
// version and digest, and AuthorizedKeysFile — as one ssh_trust finding whose
// fingerprint is the digest of what it reports, so a changed configuration is
// a new finding and an unchanged one reports the same identity again.
func TestShippedAgentReportsSSHDTrustPosture(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "trusted_user_ca_keys")
	if err := os.WriteFile(caPath, []byte(agentAuthorizedKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	krlBytes, err := os.ReadFile(filepath.Join("..", "..", "internal", "agent", "sshkrl", "testdata", "ssh-keygen-sha256.krl"))
	if err != nil {
		t.Fatal(err)
	}
	krlVersion, err := sshkrl.Version(krlBytes)
	if err != nil {
		t.Fatal(err)
	}
	krlPath := filepath.Join(dir, "revoked_keys")
	if err := os.WriteFile(krlPath, krlBytes, 0o600); err != nil { // #nosec G703 -- committed stock KRL fixture bytes written under t.TempDir (CWE-22)
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "sshd_config")
	config := "TrustedUserCAKeys " + caPath + "\nRevokedKeys " + krlPath + "\nAuthorizedKeysFile none\n"
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	report := func() agent.InventoryFinding {
		t.Helper()
		reporter := &inventoryReporterStub{}
		if err := reportSSHInventory(context.Background(), reporter, nil, sshdiscovery.Config{SSHDConfigPaths: []string{configPath}}); err != nil {
			t.Fatal(err)
		}
		return sshTrustFinding(t, reporter.findings)
	}

	first := report()
	m := first.Metadata
	if first.Ref != configPath || m["config_state"] != "read" || m["trusted_ca_state"] != "read" ||
		m["trusted_ca_fingerprints"] != agentAuthorizedKeyFP || m["revocation_state"] != "krl" ||
		m["krl_version"] != strconv.FormatUint(krlVersion, 10) || m["revoked_keys_sha256"] != crypto.SHA256Hex(krlBytes) ||
		m["authorized_keys_file"] != "none" || m["host_certificates"] != "[]" || m["key_bytes"] != "not_collected" {
		t.Fatalf("trust posture metadata = %+v", m)
	}
	if again := report(); again.Fingerprint != first.Fingerprint || len(first.Fingerprint) != 64 {
		t.Fatalf("unchanged posture fingerprint %q then %q", first.Fingerprint, again.Fingerprint)
	}

	// Presenting a host certificate that is not there is a different posture.
	missing := filepath.Join(dir, "ssh_host_ed25519_key-cert.pub")
	if err := os.WriteFile(configPath, []byte(config+"HostCertificate "+missing+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	changed := report()
	var certificates []sshTrustCertificateReport
	if err := json.Unmarshal([]byte(changed.Metadata["host_certificates"]), &certificates); err != nil {
		t.Fatal(err)
	}
	if changed.Fingerprint == first.Fingerprint || len(certificates) != 1 || certificates[0].Path != missing || certificates[0].State != "missing" {
		t.Fatalf("changed posture = %s %+v", changed.Fingerprint, certificates)
	}
}
