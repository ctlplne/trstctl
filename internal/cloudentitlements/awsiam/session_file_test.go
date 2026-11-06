// SPDX-License-Identifier: BUSL-1.1
package awsiam

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/awssignin"
	"trstctl.com/trstctl/internal/crypto/secretfile"
)

func TestAWSIAMSessionFileCustodyExpiryAndBytesA264(t *testing.T) {
	now := time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)
	raw := []byte(`{"Credentials":{"AccessKeyId":"ASIAEXAMPLE","SecretAccessKey":"fixture-signing-material","SessionToken":"fixture-temporary-token","Expiration":"2026-11-05T01:00:00Z"}}`)
	path := filepath.Join(t.TempDir(), "session.json")
	if err := secretfile.Create(path, raw); err != nil {
		t.Fatal(err)
	}
	calls := 0
	use := func(c awssignin.Credentials) error {
		calls++
		if !bytes.Equal(c.AccessKeyID, []byte("ASIAEXAMPLE")) || !bytes.Equal(c.SecretAccessKey, []byte("fixture-signing-material")) || !bytes.Equal(c.SessionToken, []byte("fixture-temporary-token")) {
			t.Fatal("byte-backed session changed")
		}
		return nil
	}
	if err := SessionFile(path, func() time.Time { return now })(context.Background(), use); err != nil {
		t.Fatal(err)
	}
	if err := SessionFile(path, func() time.Time { return now.Add(2 * time.Hour) })(context.Background(), use); err == nil {
		t.Fatal("expired session accepted")
	}
	if err := SessionFile(filepath.Dir(path), func() time.Time { return now })(context.Background(), use); err == nil {
		t.Fatal("non-regular session path accepted")
	}
	if calls != 1 {
		t.Fatalf("refused session reached signing callback %d times", calls)
	}
	for _, bad := range [][]byte{[]byte(`{"Credentials":{"AccessKeyId":"ASIAEXAMPLE","SecretAccessKey":"fixture","Expiration":"2026-11-05T01:00:00Z"}}`), append(append([]byte(nil), raw...), []byte(` {}`)...), bytes.ReplaceAll(raw, []byte("2026-11-05T01"), []byte("2027-11-05T01")), bytes.ReplaceAll(raw, []byte("ASIAEXAMPLE"), []byte(`ASIA\nEXAMPLE`))} {
		if err := useSessionJSON(bad, now, use); err == nil {
			t.Fatal("malformed STS material accepted")
		}
	}
}
func FuzzAWSIAMSessionDocument(f *testing.F) {
	f.Add([]byte(`{"Credentials":{"AccessKeyId":"ASIAEXAMPLE","SecretAccessKey":"fixture","SessionToken":"fixture","Expiration":"2026-11-05T01:00:00Z"}}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 64<<10 {
			return
		}
		_ = useSessionJSON(raw, time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC), func(c awssignin.Credentials) error {
			if len(c.AccessKeyID) > 256 || len(c.SecretAccessKey) > 1024 || len(c.SessionToken) > 32<<10 {
				t.Fatal("unbounded borrowed material")
			}
			return nil
		})
	})
}
