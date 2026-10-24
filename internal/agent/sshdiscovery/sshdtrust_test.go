// SPDX-License-Identifier: BUSL-1.1

package sshdiscovery

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/sshkeys"
	sshprotocol "trstctl.com/trstctl/internal/protocols/ssh"
)

// testdata holds stock ssh-keygen output: host-ca.pub signed host-cert.pub
// (serial 42); tampered-cert.pub is host-cert.pub with its last signature byte
// flipped; host.pub is the plain host key.
func trustFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name)) // #nosec G304 -- committed test fixture
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func writeTrustFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// A115: the posture is the global section as sshd resolves it. An Include read
// in place sets RevokedKeys before the main file's later line (sshd keeps the
// first value), HostCertificate accumulates across both files, Keyword=value
// and quoted arguments parse, and a Match block's settings are counted, not
// applied.
func TestTrustPostureReadsTheGlobalSectionLikeSSHD(t *testing.T) {
	dir := t.TempDir()
	caPath := writeTrustFile(t, dir, "trusted_user_ca_keys", trustFixture(t, "host-ca.pub"))
	krl := sshprotocol.NewKRL()
	krl.RevokeSerial(7)
	krlBytes := krl.DistributeKRL(3)
	krlPath := writeTrustFile(t, dir, "revoked_keys", krlBytes)
	certPath := writeTrustFile(t, dir, "ssh_host_ed25519_key-cert.pub", trustFixture(t, "host-cert.pub"))
	tamperedPath := writeTrustFile(t, dir, "tampered-cert.pub", trustFixture(t, "tampered-cert.pub"))
	writeTrustFile(t, dir, "sshd_config.d/10-trstctl.conf", []byte("RevokedKeys "+krlPath+"\nHostCertificate "+certPath+"\n"))
	config := writeTrustFile(t, dir, "sshd_config", []byte(fmt.Sprintf(`# global section
Include %s/sshd_config.d/*.conf
TrustedUserCAKeys=%s
RevokedKeys /etc/ssh/a-later-value-sshd-ignores
HostCertificate "%s"
AuthorizedKeysFile none
Match User deploy
    TrustedUserCAKeys /etc/ssh/match-only-ca.pub
    AuthorizedKeysFile .ssh/authorized_keys
`, dir, caPath, tamperedPath)))

	postures := New(Config{SSHDConfigPaths: []string{config}}).TrustPosture()
	if len(postures) != 1 {
		t.Fatalf("postures = %d, want 1", len(postures))
	}
	p := postures[0]
	ca, err := sshkeys.ParsePublicKey(trustFixture(t, "host-ca.pub"))
	if err != nil {
		t.Fatal(err)
	}
	if p.ConfigState != StateRead || p.IncludedFiles != 1 || p.MatchBlocks != 1 {
		t.Fatalf("config = %s, included %d, match blocks %d", p.ConfigState, p.IncludedFiles, p.MatchBlocks)
	}
	if p.TrustedUserCAKeys != caPath || p.TrustedCAState != StateRead || len(p.TrustedCAs) != 1 || p.TrustedCAs[0].FingerprintSHA256 != ca.FingerprintSHA256 {
		t.Fatalf("trusted CAs = %s %s %+v", p.TrustedUserCAKeys, p.TrustedCAState, p.TrustedCAs)
	}
	if p.RevokedKeys != krlPath || p.RevocationState != StateKRL || p.KRLVersion != 3 || p.RevokedKeysSHA256 != crypto.SHA256Hex(krlBytes) {
		t.Fatalf("revocation = %s %s v%d %s", p.RevokedKeys, p.RevocationState, p.KRLVersion, p.RevokedKeysSHA256)
	}
	if len(p.HostCertificates) != 2 || p.HostCertificates[0].Path != certPath || p.HostCertificates[1].Path != tamperedPath {
		t.Fatalf("host certificates = %+v", p.HostCertificates)
	}
	good, bad := p.HostCertificates[0], p.HostCertificates[1]
	if good.State != StateCertificate || !good.Certificate.SignatureVerified || good.Certificate.CAFingerprintSHA256 != ca.FingerprintSHA256 ||
		good.Certificate.Serial != 42 || good.ValidBeforeText() != "2036-01-01T00:00:00Z" {
		t.Fatalf("host certificate = %+v", good)
	}
	if bad.State != StateCertificate || bad.Certificate.SignatureVerified {
		t.Fatalf("tampered certificate verified: %+v", bad)
	}
	if len(p.AuthorizedKeysFile) != 1 || p.AuthorizedKeysFile[0] != "none" || p.AuthorizedPrincipalsFile != StateNone {
		t.Fatalf("authorized keys = %v, principals = %s", p.AuthorizedKeysFile, p.AuthorizedPrincipalsFile)
	}
}

// What the posture could not use is reported, not dropped: a host whose CA
// file is missing is not the same as a host with no CA configured.
func TestTrustPostureReportsWhatItCouldNotRead(t *testing.T) {
	dir := t.TempDir()
	keyList := writeTrustFile(t, dir, "revoked.pub", trustFixture(t, "host.pub"))
	plainKey := writeTrustFile(t, dir, "plain-key.pub", trustFixture(t, "host.pub"))
	unset := writeTrustFile(t, dir, "unset_config", []byte("Port 22\n"))
	partial := writeTrustFile(t, dir, "partial_config", []byte("TrustedUserCAKeys "+filepath.Join(dir, "absent-ca.pub")+
		"\nRevokedKeys "+keyList+"\nHostCertificate "+plainKey+"\nHostCertificate relative/cert.pub\n"))
	missingKRL := writeTrustFile(t, dir, "missing_krl_config", []byte("TrustedUserCAKeys relative/ca.pub\nRevokedKeys "+filepath.Join(dir, "absent.krl")+"\n"))

	byPath := map[string]SSHDTrust{}
	for _, p := range New(Config{SSHDConfigPaths: []string{unset, partial, missingKRL, filepath.Join(dir, "absent_config")}}).TrustPosture() {
		byPath[p.ConfigPath] = p
	}
	if p := byPath[unset]; p.TrustedUserCAKeys != StateNone || p.TrustedCAState != StateNone || p.RevocationState != StateNone ||
		len(p.AuthorizedKeysFile) != 2 || p.AuthorizedKeysFile[0] != ".ssh/authorized_keys" || len(p.HostCertificates) != 0 {
		t.Fatalf("unset posture = %+v", p)
	}
	if p := byPath[partial]; p.TrustedCAState != StateMissing || p.RevocationState != StateKeyList || p.RevokedKeyCount != 1 ||
		len(p.HostCertificates) != 2 || p.HostCertificates[0].State != StateInvalid || p.HostCertificates[1].State != StateRelative {
		t.Fatalf("partial posture = %+v", p)
	}
	if p := byPath[missingKRL]; p.TrustedCAState != StateRelative || p.RevocationState != StateMissing {
		t.Fatalf("missing KRL posture = %+v", p)
	}
	// An absent configuration file matches no glob and is not reported.
	if _, ok := byPath[filepath.Join(dir, "absent_config")]; ok || len(byPath) != 3 {
		t.Fatalf("postures = %v", byPath)
	}
}
