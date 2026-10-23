// SPDX-License-Identifier: BUSL-1.1

package keyposture

import (
	"encoding/base64"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/weakkey"
	"trstctl.com/trstctl/internal/crypto/weakkey/weakkeytest"
)

// eMudhra, Part 4: a reporter attaches an RSA certificate's public key; the
// control plane uses it only when it is an RSA key that hashes to the reported
// spki_sha256, and rates it with its own checks, which include the operator's
// blocklists no reporter holds.
func TestReportedRSAKeysAreCheckedAndRatedByTheControlPlane(t *testing.T) {
	rsaCert := fixtureDER(t, "rsa-1024.pem")
	value := RSASPKIMetadata(rsaCert)
	info, err := certinfo.Inspect(rsaCert)
	if err != nil || value == "" {
		t.Fatalf("RSA certificate key = %q, %v", value, err)
	}
	if RSASPKIMetadata(fixtureDER(t, "ecdsa-p256-ordinary.pem")) != "" {
		t.Fatal("an ECDSA certificate reported an RSA key")
	}
	if _, ok := ReportedRSAKey(value, info.SPKISHA256); !ok {
		t.Fatal("the certificate's own key was refused")
	}
	a, b, err := weakkeytest.SharedPrimeRSASPKIs(1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ReportedRSAKey(base64.StdEncoding.EncodeToString(a), crypto.SHA256Hex(b)); ok {
		t.Fatal("a key that does not hash to the reported spki_sha256 was accepted")
	}
	for _, bad := range []string{"not base64!", base64.StdEncoding.EncodeToString([]byte("not a key")), strings.Repeat("A", 4000)} {
		if _, ok := ReportedRSAKey(bad, ""); ok {
			t.Fatalf("accepted %q", bad[:min(len(bad), 20)])
		}
	}

	// The operator's blocklist lives only on the control plane.
	line, err := weakkeytest.DebianBlocklistLine(a)
	if err != nil {
		t.Fatal(err)
	}
	list, err := weakkey.LoadOpenSSLBlocklist("blacklist.RSA-1024", []byte("# test\n"+line+"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if v := RateReportedRSAKey(a); v.Weak() {
		t.Fatalf("rated weak before the blocklist was installed: %+v", v)
	}
	previous := weakkey.Default()
	weakkey.SetDefault(weakkey.NewChecker(list))
	t.Cleanup(func() { weakkey.SetDefault(previous) })
	if v := RateReportedRSAKey(a); !v.Weak() || !strings.Contains(strings.Join(v.WeakReasons, "|"), "blacklist.RSA-1024") {
		t.Fatalf("blocklisted key = %+v", v)
	}
	if v := RateReportedRSAKey(b); v.Weak() {
		t.Fatalf("an unlisted key was rated weak: %+v", v)
	}
}
