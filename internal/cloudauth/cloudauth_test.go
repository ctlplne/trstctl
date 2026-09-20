// SPDX-License-Identifier: BUSL-1.1

package cloudauth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(req *http.Request) (*http.Response, error) { return f(req) }

func TestAWSFederatedExchangeUsesFormBytesAndRedactsProviderFailure(t *testing.T) {
	const proof = "header.payload.signature+with/slash"
	doer := doerFunc(func(req *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatal(err)
		}
		got := string(body)
		for _, want := range []string{
			"Action=AssumeRoleWithWebIdentity",
			"RoleArn=arn%3Aaws%3Aiam%3A%3A123456789012%3Arole%2Fsync",
			"RoleSessionName=trstctl-job",
			"WebIdentityToken=header.payload.signature%2Bwith%2Fslash",
		} {
			if !strings.Contains(got, want) {
				t.Fatalf("AWS STS form %q does not contain %q", got, want)
			}
		}
		return &http.Response{
			StatusCode: http.StatusBadRequest,
			Body:       io.NopCloser(strings.NewReader(`token ` + proof + ` was rejected`)),
		}, nil
	})
	_, err := ExchangeAWSWebIdentity(context.Background(), doer, AWSExchangeRequest{
		Endpoint: "https://sts.amazonaws.com", RoleARN: "arn:aws:iam::123456789012:role/sync",
		RoleSessionName: "trstctl-job", WebIdentityToken: []byte(proof),
	})
	if err == nil {
		t.Fatal("AWS STS failure unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), proof) || !strings.Contains(err.Error(), "status 400") {
		t.Fatalf("AWS STS error = %q, want status-only redacted failure", err)
	}
}

func TestAWSFederatedMinterCachesAndRefreshesLockedCredentials(t *testing.T) {
	now := time.Date(2026, 7, 28, 0, 0, 0, 0, time.UTC)
	minter := NewMinter(2 * time.Minute)
	minter.now = func() time.Time { return now }
	t.Cleanup(minter.Close)
	var calls atomic.Int32
	exchange := func(context.Context) (Material, error) {
		n := calls.Add(1)
		return Material{
			Identifier: "AKID" + string(rune('0'+n)),
			Primary:    []byte("short-secret"),
			Secondary:  []byte("short-session-token"),
			ExpiresAt:  now.Add(15 * time.Minute),
		}, nil
	}
	first, hit, err := minter.Mint(context.Background(), "tenant/source", exchange)
	if err != nil || hit {
		t.Fatalf("first Mint() hit=%v err=%v", hit, err)
	}
	if string(first.Primary.Bytes()) != "short-secret" || string(first.Secondary.Bytes()) != "short-session-token" {
		t.Fatal("first Mint() lost credential bytes")
	}
	first.Destroy()
	second, hit, err := minter.Mint(context.Background(), "tenant/source", exchange)
	if err != nil || !hit || calls.Load() != 1 {
		t.Fatalf("cached Mint() hit=%v calls=%d err=%v", hit, calls.Load(), err)
	}
	second.Destroy()
	now = now.Add(14 * time.Minute)
	refreshed, hit, err := minter.Mint(context.Background(), "tenant/source", exchange)
	if err != nil || hit || calls.Load() != 2 {
		t.Fatalf("refresh Mint() hit=%v calls=%d err=%v", hit, calls.Load(), err)
	}
	refreshed.Destroy()
}

func TestAWSFederatedMinterDoesNotCrossBlockSources(t *testing.T) {
	minter := NewMinter(time.Minute)
	t.Cleanup(minter.Close)
	blocked := make(chan struct{})
	release := make(chan struct{})
	go func() {
		_, _, _ = minter.Mint(context.Background(), "tenant/slow", func(context.Context) (Material, error) {
			close(blocked)
			<-release
			return Material{}, errors.New("slow failed")
		})
	}()
	<-blocked
	fastDone := make(chan error, 1)
	go func() {
		credential, _, err := minter.Mint(context.Background(), "tenant/fast", func(context.Context) (Material, error) {
			return Material{
				Identifier: "AKID", Primary: []byte("secret"), Secondary: []byte("token"),
				ExpiresAt: time.Now().Add(15 * time.Minute),
			}, nil
		})
		if credential != nil {
			credential.Destroy()
		}
		fastDone <- err
	}()
	select {
	case err := <-fastDone:
		if err != nil {
			t.Fatalf("independent source failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("slow source blocked an independent source cache lane")
	}
	close(release)
}

func TestAWSFederatedMinterDestroysUnusedCredentialAtExpiry(t *testing.T) {
	minter := NewMinter(time.Millisecond)
	defer minter.Close()
	credential, _, err := minter.Mint(context.Background(), "tenant/expiring", func(context.Context) (Material, error) {
		return Material{
			Identifier: "AKID", Primary: []byte("short-secret"), Secondary: []byte("short-token"),
			ExpiresAt: time.Now().Add(40 * time.Millisecond),
		}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	credential.Destroy()
	entry := minter.entries["tenant/expiring"]
	deadline := time.After(time.Second)
	for {
		entry.mu.Lock()
		destroyed := entry.credential == nil
		entry.mu.Unlock()
		if destroyed {
			break
		}
		select {
		case <-deadline:
			t.Fatal("cached credential survived provider expiry")
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func TestAWSFederatedResponseParsesTemporaryCredentials(t *testing.T) {
	raw := []byte(`<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials>` +
		`<AccessKeyId>ASIATEMP</AccessKeyId><SecretAccessKey>temporary-secret</SecretAccessKey>` +
		`<SessionToken>temporary-token</SessionToken><Expiration>2026-07-28T01:00:00Z</Expiration>` +
		`</Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`)
	got, err := parseAWSAssumeRoleResponse(raw)
	if err != nil {
		t.Fatalf("parseAWSAssumeRoleResponse: %v", err)
	}
	defer func() {
		for i := range got.Primary {
			got.Primary[i] = 0
		}
		for i := range got.Secondary {
			got.Secondary[i] = 0
		}
	}()
	if got.Identifier != "ASIATEMP" || string(got.Primary) != "temporary-secret" || string(got.Secondary) != "temporary-token" {
		t.Fatalf("parsed AWS credentials = %#v", got)
	}
}

func FuzzAWSFederatedSTSResponse(f *testing.F) {
	f.Add([]byte(`<AssumeRoleWithWebIdentityResponse/>`))
	f.Add([]byte(`<Credentials><SecretAccessKey>secret</SecretAccessKey>`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		got, _ := parseAWSAssumeRoleResponse(raw)
		for i := range got.Primary {
			got.Primary[i] = 0
		}
		for i := range got.Secondary {
			got.Secondary[i] = 0
		}
		if len(got.Primary) > len(raw) || len(got.Secondary) > len(raw) {
			t.Fatal("parser produced more secret bytes than bounded input")
		}
	})
}
