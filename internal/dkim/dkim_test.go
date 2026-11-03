// SPDX-License-Identifier: BUSL-1.1

package dkim

import (
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// dkimpyVectors are messages signed by an independent implementation
// (Debian's python3-dkim 1.1.4, dkimpy) with fresh keys, generated in a lab
// container: rsa-sha256 and ed25519-sha256, relaxed and simple, and one
// signature over part of the body (l=).
// dkimpyVectorsJSON is the committed dkimpy vector set, compiled in: fuzz
// targets seed from it, and the ClusterFuzzLite runner has no source tree.
//
//go:embed testdata/dkimpy-vectors.json
var dkimpyVectorsJSON []byte

func dkimpyVectors(t fuzzFixtureTB) (map[string]string, map[string][]byte) {
	t.Helper()
	raw := dkimpyVectorsJSON
	var v struct {
		Records  map[string]string `json:"records"`
		Messages map[string]string `json:"messages"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	messages := map[string][]byte{}
	for name, b64 := range v.Messages {
		msg, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			t.Fatal(err)
		}
		messages[name] = msg
	}
	return v.Records, messages
}

func TestVerifyDomainAgreesWithAnIndependentSignerP15(t *testing.T) {
	records, messages := dkimpyVectors(t)
	verifier := Verifier{Pinned: records}
	ctx := context.Background()
	for _, name := range []string{"rsa-relaxed", "rsa-simple", "ed25519-relaxed", "ed25519-relaxed-simple"} {
		msg := messages[name]
		if err := verifier.VerifyDomain(ctx, msg, "p15.test"); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := verifier.VerifyDomain(ctx, msg, "other.test"); !errors.Is(err, ErrNoValidSignature) {
			t.Fatalf("%s for another domain: %v", name, err)
		}
		for what, tampered := range map[string]string{
			"From": strings.Replace(string(msg), "From: alice@p15.test", "From: mallory@p15.test", 1),
			"body": strings.Replace(string(msg), "jxAjEuX0", "jxAjEuX1", 1),
		} {
			if err := verifier.VerifyDomain(ctx, []byte(tampered), "p15.test"); err == nil {
				t.Fatalf("%s with a changed %s verified", name, what)
			}
		}
	}
	if err := verifier.VerifyDomain(ctx, messages["rsa-length-tag"], "p15.test"); err == nil {
		t.Fatal("a signature over part of the body (l=) verified")
	}
	if err := (Verifier{}).VerifyDomain(ctx, messages["rsa-relaxed"], "p15.test"); err == nil {
		t.Fatal("verified with no key source")
	}
	lookups := 0
	viaDNS := Verifier{Lookup: func(_ context.Context, name string) ([]string, error) {
		lookups++
		return []string{records[name]}, nil
	}}
	if err := viaDNS.VerifyDomain(ctx, messages["ed25519-relaxed"], "p15.test"); err != nil || lookups != 1 {
		t.Fatalf("DNS key lookup: %v (lookups %d)", err, lookups)
	}
	revoked := Verifier{Pinned: map[string]string{"rsa1._domainkey.p15.test": "v=DKIM1; k=rsa; p="}}
	if err := revoked.VerifyDomain(ctx, messages["rsa-relaxed"], "p15.test"); err == nil {
		t.Fatal("a revoked key (empty p=) verified")
	}
}

// Sign produces signatures the verifier accepts; an expired one is refused.
func TestSignRoundTripP15(t *testing.T) {
	key, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	msg := []byte("From: alice@p15.test\r\nTo: acme@ca.p15.test\r\nSubject: Re: ACME:   abc\r\nDate: Sun, 01 Nov 2026 12:00:00 +0000\r\n" +
		"Content-Type: text/plain\r\n\r\nhello  world \r\n\r\n")
	signed, err := Sign(msg, "p15.test", "lab", []string{"From", "To", "Subject", "Date", "Content-Type"}, key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	verifier := Verifier{Pinned: map[string]string{"lab._domainkey.p15.test": "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(key.Public().DER)}}
	if err := verifier.VerifyDomain(context.Background(), signed, "p15.test"); err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyDomain(context.Background(), []byte(strings.Replace(string(signed), "abc", "abd", 1)), "p15.test"); err == nil {
		t.Fatal("a changed Subject verified")
	}
	later := Verifier{Pinned: verifier.Pinned, Now: func() time.Time { return time.Now().Add(time.Hour) }}
	expiring := []byte(strings.Replace(string(signed), "; t=", "; x=1; t=", 1))
	if err := later.VerifyDomain(context.Background(), expiring, "p15.test"); err == nil {
		t.Fatal("an expired signature verified")
	}
	ecKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ecKey.Destroy)
	if _, err := Sign(msg, "p15.test", "lab", []string{"From"}, ecKey, time.Now()); err == nil {
		t.Fatal("signed with a non-RSA key")
	}
}

// FuzzVerifyDomain: a received message is untrusted input; verifying it never
// panics, whatever its bytes.
func FuzzVerifyDomain(f *testing.F) {
	records, messages := dkimpyVectors(f)
	for _, msg := range messages {
		f.Add(msg)
	}
	f.Add([]byte("DKIM-Signature: v=1; a=rsa-sha256; d=p15.test; s=rsa1; h=from; bh=; b=\r\nFrom: a@p15.test\r\n\r\n"))
	verifier := Verifier{Pinned: records}
	f.Fuzz(func(t *testing.T, msg []byte) {
		_ = verifier.VerifyDomain(context.Background(), msg, "p15.test")
	})
}

// fuzzFixtureTB is the part of testing.TB the fixture helpers use. Fuzz
// targets hand them their *testing.F, and ClusterFuzzLite's testing shim
// implements these methods but not all of Go 1.26's testing.TB (it has no
// ArtifactDir), so a testing.TB parameter does not compile there.
type fuzzFixtureTB interface {
	Helper()
	Fatal(args ...any)
	Fatalf(format string, args ...any)
}
