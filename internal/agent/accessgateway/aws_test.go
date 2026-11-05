// SPDX-License-Identifier: BUSL-1.1
package accessgateway

import (
	"bytes"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/awssignin"
	"trstctl.com/trstctl/internal/crypto/secret"
)

func TestAWSRecordingMasksFullAndTruncatedCredentialBeforeText(t *testing.T) {
	credential := awssignin.Credentials{AccessKeyID: []byte("ASIAOWNEDTESTIDENTITY"), SecretAccessKey: []byte("owned-signing-material"), SessionToken: []byte("owned-opaque-session-material")}
	complete := bytes.Join([][]byte{[]byte("public:"), credential.AccessKeyID, credential.SecretAccessKey, credential.SessionToken, []byte(":result")}, []byte("/"))
	before := bytes.Clone(complete)
	masked := maskAWSHead(credential, complete, len(complete))
	defer secret.Wipe(masked)
	for _, value := range [][]byte{credential.AccessKeyID, credential.SecretAccessKey, credential.SessionToken} {
		if bytes.Contains(masked, value) {
			t.Fatal("recording kept injected credential")
		}
	}
	if !bytes.Equal(complete, before) || !bytes.Contains(masked, []byte(":result")) {
		t.Fatal("mask changed caller input or discarded unrelated result")
	}
	partial := append([]byte("public:"), credential.SessionToken[:12]...)
	short := maskAWSHead(credential, partial, len(partial)+100)
	defer secret.Wipe(short)
	if bytes.Contains(short, credential.SessionToken[:12]) || !bytes.Contains(short, []byte("[masked:credential]")) {
		t.Fatal("truncated recording head leaked a completing token")
	}
}

func TestAWSGatewayEnvelopeIsBoundedAndLockedUntilDestroy(t *testing.T) {
	raw := []byte(`{"access_key_id":"ASIAOWNEDTESTIDENTITY","secret_access_key":"owned-signing-material","session_token":"owned-session-material","expiration":"2026-11-05T20:00:00Z"}`)
	before := bytes.Clone(raw)
	material, err := parseAWSGatewayMaterial(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, before) || !material.expiration.Equal(time.Date(2026, 11, 5, 20, 0, 0, 0, time.UTC)) {
		t.Fatal("credential parse changed input or native expiry")
	}
	if err := material.use(func(c awssignin.Credentials) error {
		if !bytes.Equal(c.SecretAccessKey, []byte("owned-signing-material")) {
			t.Fatal("locked key differs")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	material.destroy()
	if err := material.use(func(awssignin.Credentials) error { return nil }); err == nil {
		t.Fatal("destroyed credential remained usable")
	}
	for _, bad := range [][]byte{nil, []byte(`null`), []byte(`{}`), bytes.Repeat([]byte("x"), (64<<10)+1)} {
		if material, err := parseAWSGatewayMaterial(bad); err == nil {
			material.destroy()
			t.Fatal("invalid credential envelope accepted")
		}
	}
}

func FuzzAWSGatewayCredentialEnvelope(f *testing.F) {
	for _, raw := range []string{`{"access_key_id":"ASIAOWNEDTESTIDENTITY","secret_access_key":"owned-signing-material","session_token":"owned-session-material","expiration":"2026-11-05T20:00:00Z"}`, `null`, `{"session_token":"owned"}`} {
		f.Add([]byte(raw))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		before := bytes.Clone(raw)
		material, err := parseAWSGatewayMaterial(raw)
		if !bytes.Equal(raw, before) {
			t.Fatal("parser changed caller bytes")
		}
		if err == nil {
			defer material.destroy()
			if len(raw) > 64<<10 {
				t.Fatal("unbounded envelope accepted")
			}
			if err := material.use(func(c awssignin.Credentials) error {
				if len(c.AccessKeyID) == 0 || len(c.SecretAccessKey) == 0 || len(c.SessionToken) == 0 {
					t.Fatal("incomplete envelope accepted")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		}
	})
}
