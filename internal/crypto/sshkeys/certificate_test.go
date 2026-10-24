// SPDX-License-Identifier: BUSL-1.1

package sshkeys_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/sshkeys"
)

// The fixtures are stock OpenSSH output: ssh-keygen -s host-ca -h (host-cert,
// serial 42, 2026-01-01Z to 2036-01-01Z), -V always:forever (forever-cert),
// a user certificate for alice (user-cert), and host-cert with its last
// signature byte flipped (tampered-cert, which ssh-keygen -L refuses).
func certFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name)) // #nosec G304 -- committed test fixture
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func fingerprintOf(t *testing.T, name string) string {
	t.Helper()
	info, err := sshkeys.ParsePublicKey(certFixture(t, name))
	if err != nil {
		t.Fatal(err)
	}
	return info.FingerprintSHA256
}

// A115: a host certificate reports what it certifies, which CA signed it, and
// its validity, with the CA signature verified.
func TestParseCertificateReadsAStockHostCertificate(t *testing.T) {
	info, err := sshkeys.ParseCertificate(certFixture(t, "host-cert.pub"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Kind != "host" || !info.SignatureVerified || info.CAType != "ssh-ed25519" ||
		info.CAFingerprintSHA256 != fingerprintOf(t, "host-ca.pub") ||
		info.KeyType != "ssh-ed25519" || info.KeyFingerprintSHA256 != fingerprintOf(t, "host.pub") ||
		info.KeyID != "web-1 host" || info.Serial != 42 ||
		len(info.Principals) != 2 || info.Principals[0] != "web-1.example.test" || info.Principals[1] != "10.0.0.5" ||
		!info.ValidAfter.Equal(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) ||
		!info.ValidBefore.Equal(time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC)) || info.Forever {
		t.Fatalf("host certificate = %+v", info)
	}
}

func TestParseCertificateReportsForeverAndUserCertificates(t *testing.T) {
	forever, err := sshkeys.ParseCertificate(certFixture(t, "forever-cert.pub"))
	if err != nil {
		t.Fatal(err)
	}
	if !forever.Forever || !forever.ValidBefore.IsZero() || !forever.ValidAfter.Equal(time.Unix(0, 0).UTC()) ||
		forever.Serial != 7 || !forever.SignatureVerified {
		t.Fatalf("forever certificate = %+v", forever)
	}
	user, err := sshkeys.ParseCertificate(certFixture(t, "user-cert.pub"))
	if err != nil {
		t.Fatal(err)
	}
	if user.Kind != "user" || user.KeyType != "ecdsa-sha2-nistp256" || len(user.Principals) != 1 ||
		user.Principals[0] != "alice" || user.Serial != 9 || !user.SignatureVerified {
		t.Fatalf("user certificate = %+v", user)
	}
}

// A certificate that names a CA but whose signature does not verify vouches for
// nothing: it still parses, so a report can say which CA it claims, and it is
// marked unverified.
func TestParseCertificateMarksATamperedSignatureUnverified(t *testing.T) {
	info, err := sshkeys.ParseCertificate(certFixture(t, "tampered-cert.pub"))
	if err != nil {
		t.Fatal(err)
	}
	if info.SignatureVerified || info.CAFingerprintSHA256 != fingerprintOf(t, "host-ca.pub") {
		t.Fatalf("tampered certificate = %+v", info)
	}
}

func TestParseCertificateRefusesAPlainKeyAndOversizedInput(t *testing.T) {
	if _, err := sshkeys.ParseCertificate(certFixture(t, "host.pub")); err == nil {
		t.Fatal("a plain public key parsed as a certificate")
	}
	if _, err := sshkeys.ParseCertificate(make([]byte, 65<<10)); err == nil {
		t.Fatal("an oversized certificate file parsed")
	}
}
