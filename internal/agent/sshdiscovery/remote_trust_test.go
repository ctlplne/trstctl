// SPDX-License-Identifier: BUSL-1.1
package sshdiscovery

import (
	"testing"
	"trstctl.com/trstctl/internal/sshcollection"
)

func TestTrustFromSnapshotNeverReadsTheRelaysLocalFiles(t *testing.T) {
	snapshot := sshcollection.Snapshot{Version: 1, Profile: sshcollection.Profile, ConfigPath: "/etc/ssh/sshd_config", Settings: map[string][]string{"trustedusercakeys": {"/etc/ssh/remote_ca"}, "revokedkeys": {"/etc/ssh/remote.krl"}, "hostcertificate": {"none"}, "authorizedkeysfile": {"none"}, "authorizedprincipalsfile": {"none"}}, Files: []sshcollection.PublicFile{{Path: "/etc/ssh/remote_ca", Kind: "ca", State: "missing"}, {Path: "/etc/ssh/remote.krl", Kind: "revocations", State: "not_allowed"}}}
	posture, err := TrustFromSnapshot(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if posture.TrustedCAState != StateMissing || posture.RevocationState != StateUnreadable || len(posture.AuthorizedKeysFile) != 1 || posture.AuthorizedKeysFile[0] != "none" {
		t.Fatalf("remote failures were hidden: %+v", posture)
	}
	findings, err := InventoryFindings([]SSHDTrust{posture})
	if err != nil || len(findings) != 1 {
		t.Fatalf("findings: %v %v", findings, err)
	}
	if findings[0].Metadata["key_bytes"] != "not_collected" || findings[0].Metadata["revocation_state"] != "unreadable" {
		t.Fatal("remote coverage or key custody was lost")
	}
	delete(snapshot.Settings, "authorizedkeysfile")
	if _, err := TrustFromSnapshot(snapshot); err == nil {
		t.Fatal("omitted standing-key coverage became a posture")
	}
}
