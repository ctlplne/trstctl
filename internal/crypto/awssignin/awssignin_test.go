// SPDX-License-Identifier: BUSL-1.1
package awssignin

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// These are published non-secret example inputs, used only to compare the
// byte-backed implementation with the already pinned upstream AWS signer.
func TestSignMatchesPinnedAWSReference(t *testing.T) {
	exampleSigningBytes := []byte("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")
	exampleTokenBytes := []byte("example-session-token")
	credential := Credentials{AccessKeyID: []byte("AKIDEXAMPLE"), SecretAccessKey: exampleSigningBytes, SessionToken: exampleTokenBytes}
	now := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	for _, tc := range []struct{ service, method, path, body string }{{"sts", "GET", "/?Action=GetCallerIdentity&Version=2011-06-15", ""}, {"sts", "POST", "/", "Action=GetCallerIdentity&Version=2011-06-15"}, {"s3", "GET", "/owned-bucket/a%20b//object?prefix=a+b&tag=z&tag=a", ""}, {"s3", "PUT", "/owned-bucket/object", "owned-data"}} {
		t.Run(tc.service+tc.method, func(t *testing.T) {
			request, err := http.NewRequest(tc.method, "https://service.example"+tc.path, strings.NewReader(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Content-Type", "application/octet-stream")
			request.Header["X-Amz-Meta-Owned"] = []string{" first  value ", "second"}
			reference := request.Clone(context.Background())
			reference.Header.Set("X-Amz-Content-Sha256", crypto.SHA256Hex([]byte(tc.body)))
			sdkCredentials := aws.Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: string(exampleSigningBytes), SessionToken: string(exampleTokenBytes)}
			err = v4.NewSigner().SignHTTP(context.Background(), sdkCredentials, reference, crypto.SHA256Hex([]byte(tc.body)), tc.service, "us-east-1", now, func(options *v4.SignerOptions) { options.DisableURIPathEscaping = tc.service == "s3" })
			if err != nil {
				t.Fatal(err)
			}
			header, err := Sign(request, []byte(tc.body), credential, "us-east-1", tc.service, now)
			if err != nil {
				t.Fatal(err)
			}
			defer secret.Wipe(header)
			want := []byte("Authorization: " + reference.Header.Get("Authorization") + "\r\nX-Amz-Security-Token: " + reference.Header.Get("X-Amz-Security-Token"))
			if !bytes.Equal(header, want) {
				t.Fatalf("signature differs from pinned reference:\n%s\n%s", header, want)
			}
			if request.Header.Get("Authorization") != "" || request.Header.Get("X-Amz-Security-Token") != "" {
				t.Fatal("secret entered immutable HTTP headers")
			}
		})
	}
}

func TestSignDiscardsIncomingAuthAndBindsOperation(t *testing.T) {
	credential := Credentials{AccessKeyID: []byte("ASIAEXAMPLE"), SecretAccessKey: []byte("example-signing-material"), SessionToken: []byte("example-session-material")}
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	makeRequest := func() *http.Request {
		request, _ := http.NewRequest(http.MethodGet, "https://service.example/owned?x=1", nil)
		return request
	}
	clean := makeRequest()
	expected, err := Sign(clean, nil, credential, "us-east-1", "s3", now)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(expected)
	incoming := makeRequest()
	incoming.Header.Set("Authorization", "client-auth-canary")
	incoming.Header.Set("X-Amz-Security-Token", "client-auth-canary")
	incoming.URL.RawQuery += "&X-Amz-Credential=client-auth-canary&X-Amz-Signature=client-auth-canary"
	replaced, err := Sign(incoming, nil, credential, "us-east-1", "s3", now)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(replaced)
	if !bytes.Equal(replaced, expected) || strings.Contains(incoming.URL.RawQuery, "canary") {
		t.Fatal("incoming authentication changed session authority")
	}
	for _, change := range []func(*http.Request){func(r *http.Request) { r.Method = http.MethodDelete }, func(r *http.Request) { r.URL.Path = "/other" }, func(r *http.Request) { r.URL.RawQuery = "x=2" }, func(r *http.Request) { r.Header.Set("X-Amz-Target", "different-operation") }} {
		request := makeRequest()
		change(request)
		signed, err := Sign(request, nil, credential, "us-east-1", "s3", now)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(signed, expected) {
			t.Fatal("signature omitted method/path/query/operation binding")
		}
		secret.Wipe(signed)
	}
}

func FuzzSignCanonicalRequest(f *testing.F) {
	f.Add("a/b", "x=one+two&tag=z&tag=a", []byte("owned"))
	f.Add("a%20b", "x=%E2%82%AC", []byte{})
	f.Add("/", "malformed=%", []byte{})
	f.Fuzz(func(t *testing.T, path, query string, body []byte) {
		if len(path) > 4096 || len(query) > 4096 || len(body) > 4096 {
			return
		}
		request, err := http.NewRequest(http.MethodPost, "https://service.example/"+strings.TrimPrefix(path, "/"), bytes.NewReader(body))
		if err != nil {
			return
		}
		request.URL.RawQuery = query
		credential := Credentials{AccessKeyID: []byte("ASIAEXAMPLE"), SecretAccessKey: []byte("example-signing-material"), SessionToken: []byte("example-session-material")}
		before := bytes.Clone(credential.SecretAccessKey)
		signed, err := Sign(request, body, credential, "us-east-1", "s3", time.Unix(1793880000, 0))
		defer secret.Wipe(signed)
		if !bytes.Equal(before, credential.SecretAccessKey) {
			t.Fatal("signer changed caller key")
		}
		if err == nil && (request.Header.Get("Authorization") != "" || request.Header.Get("X-Amz-Security-Token") != "" || bytes.Contains(signed, credential.SecretAccessKey)) {
			t.Fatal("key material escaped byte-backed signing")
		}
	})
}
