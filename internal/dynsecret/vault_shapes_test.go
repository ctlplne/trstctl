// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import "testing"

func TestSplitCredentialUserinfoReadsEveryDatabaseFormat(t *testing.T) {
	for _, c := range []struct {
		providerType, credential, user, password string
	}{
		{"postgresql", "postgres://v_ro%40app:p%3Aw@db.internal:5432/app?sslmode=verify-full", "v_ro@app", "p:w"},
		{"postgresql", `host=db.internal dbname=app user='v_ro' password='se\'cret' sslmode=verify-full`, "v_ro", "se'cret"},
		{"mysql", "v_mysql_ro:9f0e1d@tcp(db.internal:3306)/app", "v_mysql_ro", "9f0e1d"},
		{"mongodb", "mongodb://v_mongo:pw%2Fx@mongo.internal:27017/app?authSource=app", "v_mongo", "pw/x"},
		{"redis", "rediss://v_redis:0a1b2c@cache.internal:6380/0", "v_redis", "0a1b2c"},
	} {
		user, password, err := SplitCredentialUserinfo(c.providerType, []byte(c.credential))
		if err != nil || user != c.user || string(password) != c.password {
			t.Errorf("%s %q = %q %q %v, want %q %q", c.providerType, c.credential, user, password, err, c.user, c.password)
		}
	}
	for _, c := range []struct{ providerType, credential string }{
		{"postgresql", "postgres://db.internal/app"},
		{"postgresql", "host=db.internal user=v_ro"},
		{"mysql", "v_mysql_ro@tcp(db.internal:3306)/app"},
		{"mysql", "v_mysql_ro:@tcp(db.internal:3306)/app"},
		{"mongodb", "mongodb://mongo.internal/app"},
		{"redis", "redis://cache.internal:6379/0"},
		{"kubernetes", "eyJhbGciOi"},
	} {
		if user, password, err := SplitCredentialUserinfo(c.providerType, []byte(c.credential)); err == nil {
			t.Errorf("%s %q = %q %q, want an error", c.providerType, c.credential, user, password)
		}
	}
}

func TestKubernetesServiceAccountNameReadsTheProviderReference(t *testing.T) {
	if name, ok := KubernetesServiceAccountName(`{"version":1,"name":"trstctl-reader-7f3a","service_account_uid":"u1","bound_secret_uid":"u2"}`); !ok || name != "trstctl-reader-7f3a" {
		t.Fatalf("JSON reference = %q %v", name, ok)
	}
	if name, ok := KubernetesServiceAccountName("trstctl-legacy-1"); !ok || name != "trstctl-legacy-1" {
		t.Fatalf("legacy name-only reference = %q %v", name, ok)
	}
	for _, ref := range []string{"", "{broken", `{"version":1}`} {
		if name, ok := KubernetesServiceAccountName(ref); ok {
			t.Fatalf("%q named %q", ref, name)
		}
	}
}

func TestAWSSTSSessionARNIsTheAssumedRoleARN(t *testing.T) {
	ref := `{"role_arn":"arn:aws:iam::123456789012:role/apps/deployer","session_name":"trstctl-deployer-1","assumed_role_id":"AROAEXAMPLE:trstctl-deployer-1","access_key_id":"ASIAEXAMPLE","expiration":"2026-10-27T12:00:00Z"}`
	if arn, ok := AWSSTSSessionARN(ref); !ok || arn != "arn:aws:sts::123456789012:assumed-role/deployer/trstctl-deployer-1" {
		t.Fatalf("session ARN = %q %v", arn, ok)
	}
	for _, ref := range []string{"", "{}", `{"role_arn":"arn:aws:iam::1:user/u","session_name":"s"}`} {
		if arn, ok := AWSSTSSessionARN(ref); ok {
			t.Fatalf("%q produced %q", ref, arn)
		}
	}
}
