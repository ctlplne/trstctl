// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// A239: a credential that can't be revoked early keeps its revocation pending
// until the native expiry its provider reference carries; AWS STS sessions are
// one such credential, and its error is a native-expiry error.
func TestNativeExpiryPendsUntilTheReferenceExpiryA239(t *testing.T) {
	expiry := time.Date(2026, 11, 2, 13, 0, 0, 0, time.UTC)
	raw, err := json.Marshal(awsSTSRef{
		RoleARN: "arn:aws:iam::123456789012:role/reader", SessionName: "trstctl-lease-1",
		AssumedRoleID: "AROAEXAMPLE:trstctl-lease-1", AccessKeyID: "ASIAEXAMPLE", Expiration: expiry,
	})
	if err != nil {
		t.Fatal(err)
	}
	ref := string(raw)
	if got, ok := NativeExpiration(ref); !ok || !got.Equal(expiry) {
		t.Fatalf("NativeExpiration = %s, %v", got, ok)
	}
	if err := CheckNativeExpiration(ref, expiry.Add(-time.Second)); !errors.Is(err, ErrNativeExpiryPending) {
		t.Fatalf("before expiry = %v", err)
	}
	if err := CheckNativeExpiration(ref, expiry); err != nil {
		t.Fatalf("at expiry = %v", err)
	}
	if _, ok := NativeExpiration("pg-user-trstctl-1"); ok {
		t.Fatal("a reference without a native expiry reported one")
	}
	if err := CheckNativeExpiration("pg-user-trstctl-1", expiry); err == nil || errors.Is(err, ErrNativeExpiryPending) {
		t.Fatalf("a reference without a native expiry = %v", err)
	}
	if !errors.Is(ErrAWSSTSSessionActive, ErrNativeExpiryPending) {
		t.Fatal("the AWS STS session error is not a native-expiry error")
	}
}

// OD-5: a provider reference names whose native expiry it carries, so a lease
// can say whether it waits for an AWS session or a token.
func TestNativeExpiryKindNamesTheCredentialOD5(t *testing.T) {
	raw, err := json.Marshal(awsSTSRef{
		RoleARN: "arn:aws:iam::123456789012:role/reader", SessionName: "trstctl-lease-1",
		AssumedRoleID: "AROAEXAMPLE:trstctl-lease-1", AccessKeyID: "ASIAEXAMPLE", Expiration: time.Date(2026, 11, 2, 13, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := "0123456789abcdef0123456789abcdef"
	for ref, want := range map[string]string{
		string(raw):                            NativeExpiryAWSSession,
		"oauth:" + digest + ":1794500000":      NativeExpiryOAuthToken,
		"github-app:" + digest + ":1794500000": NativeExpiryGitHubAppToken,
		"pg-user-trstctl-1":                    "",
		"oauth:short:1794500000":               "",
	} {
		if got := NativeExpiryKind(ref); got != want {
			t.Fatalf("NativeExpiryKind(%q) = %q, want %q", ref, got, want)
		}
	}
	if RevocationMethodTokenRevoked != "token_revoked" {
		t.Fatal("the token revocation method is not the stored value")
	}
}
