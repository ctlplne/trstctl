// SPDX-License-Identifier: BUSL-1.1
package accessgateway

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/crypto/secret"
)

func consoleTestMaterial(t *testing.T) *awsGatewayMaterial {
	t.Helper()
	raw, err := json.Marshal(struct {
		ID      secret.JSONBytes `json:"access_key_id"`
		Key     secret.JSONBytes `json:"secret_access_key"`
		Token   secret.JSONBytes `json:"session_token"`
		Expires time.Time        `json:"expiration"`
	}{[]byte("owned-id"), []byte("owned-key-material"), []byte("owned-session-material"), time.Now().Add(time.Hour)}) // #nosec G117 -- owned STS-envelope fixture; parsed into locked bytes and scratch wiped (CWE-200)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(raw)
	m, err := parseAWSGatewayMaterial(raw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.destroy)
	return m
}
func TestConsoleProofBindsSessionHostAndDeadline(t *testing.T) {
	m := consoleTestMaterial(t)
	now := time.Now().Truncate(time.Second)
	intent := SessionIntent{SessionID: "owned-session", ExpiresAt: now.Add(2 * time.Minute)}
	proof, err := consoleProof(m, intent, "127.0.0.1:8000", now)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(proof)
	if !validConsoleProof(m, intent, "127.0.0.1:8000", proof, now) {
		t.Fatal("own review proof failed")
	}
	other := intent
	other.SessionID = "other"
	if validConsoleProof(m, other, "127.0.0.1:8000", proof, now) || validConsoleProof(m, intent, "127.0.0.1:8001", proof, now) || validConsoleProof(m, intent, "127.0.0.1:8000", proof, now.Add(61*time.Second)) {
		t.Fatal("foreign or expired review proof accepted")
	}
	changed := bytes.Clone(proof)
	defer secret.Wipe(changed)
	changed[len(changed)-1] ^= 1
	if validConsoleProof(m, intent, "127.0.0.1:8000", changed, now) {
		t.Fatal("forged review proof accepted")
	}
	m.destroy()
	if validConsoleProof(m, intent, "127.0.0.1:8000", proof, now) {
		t.Fatal("destroyed material authenticated a console proof")
	}
}
func TestConsoleStateReplaysOneMintAndNeverRetriesAmbiguousOutcome(t *testing.T) {
	for _, fail := range []bool{false, true} {
		state := &consoleState{}
		var calls atomic.Int32
		var wg sync.WaitGroup
		for range 16 {
			wg.Go(func() {
				page, _, err := state.page(context.Background(), time.Now().Add(time.Minute), func(context.Context) (*secret.Buffer, error) {
					calls.Add(1)
					if fail {
						return nil, errors.New("owned ambiguous outcome")
					}
					return secret.NewFrom([]byte("owned-token"))
				}, func(raw []byte) (*secret.Buffer, error) { return secret.NewFrom(raw) })
				if fail {
					if err == nil {
						page.Destroy()
						t.Error("ambiguous mint outcome reported success")
					}
					return
				}
				if err != nil {
					t.Error(err)
					return
				}
				defer page.Destroy()
				_ = page.Use(func(raw []byte) error {
					if !bytes.Equal(raw, []byte("owned-token")) {
						t.Error("idempotent handoff returned a different result")
					}
					return nil
				})
			})
		}
		wg.Wait()
		if calls.Load() != 1 {
			t.Fatal("console mint repeated for one session")
		}
		state.destroy()
		if page, _, err := state.page(context.Background(), time.Now().Add(time.Minute), func(context.Context) (*secret.Buffer, error) {
			t.Fatal("destroyed state retried mint")
			return nil, nil
		}, func(raw []byte) (*secret.Buffer, error) { return secret.NewFrom(raw) }); err == nil {
			page.Destroy()
			t.Fatal("destroyed state served a token")
		}
	}
}
func TestConsoleHTMLLocksAndEscapesPrivateValues(t *testing.T) {
	value := []byte("<&\"'owned&>")
	defer secret.Wipe(value)
	page, err := lockedConsoleHTML([]string{"prefix:", ":middle:", ":suffix"}, value)
	if err != nil {
		t.Fatal(err)
	}
	err = page.Use(func(raw []byte) error {
		if bytes.Contains(raw, value) || !bytes.Equal(raw, []byte("prefix:&lt;&amp;&#34;&#39;owned&amp;&gt;:middle:&lt;&amp;&#34;&#39;owned&amp;&gt;:suffix")) {
			t.Fatal("private HTML attribute was not escaped exactly")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	page.Destroy()
	if page.Len() != 0 {
		t.Fatal("private form page remained live after destruction")
	}
}
func TestConsoleFormRejectsDuplicateOrExtraFields(t *testing.T) {
	good := []byte("proof=owned%2Bvalue&idempotency_key=owned%2Bvalue")
	fields, err := consoleForm(good)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range fields {
		secret.Wipe(value)
	}
	for _, raw := range [][]byte{[]byte("proof=x&proof=y&idempotency_key=x"), []byte("proof=x"), []byte("proof=x&idempotency_key=x&Destination=https://foreign.example"), []byte("proof=%&idempotency_key=x"), []byte("proof=%ZZ&idempotency_key=x")} {
		fields, err := consoleForm(raw)
		for _, value := range fields {
			secret.Wipe(value)
		}
		if err == nil {
			t.Fatal("invalid console form accepted")
		}
	}
	for _, host := range []string{"evil.example:8000", "127.0.0.1.evil.example:8000", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1"} {
		if consoleLocalHost(host) {
			t.Fatal("foreign/rebinding console host accepted")
		}
	}
	if !consoleLocalHost("127.0.0.1:8000") || !consoleLocalHost("[::1]:8000") {
		t.Fatal("own loopback host refused")
	}
}
func FuzzConsoleForm(f *testing.F) {
	f.Add([]byte("proof=owned&idempotency_key=owned"))
	f.Add([]byte("proof=%ZZ"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 4096 {
			return
		}
		fields, err := consoleForm(raw)
		defer func() {
			for _, value := range fields {
				secret.Wipe(value)
			}
		}()
		if err == nil && len(fields) != 2 {
			t.Fatal("console form escaped its finite schema")
		}
	})
}
func FuzzConsoleProof(f *testing.F) {
	key, err := secret.NewFrom([]byte("owned-fuzz-proof-authority"))
	if err != nil {
		f.Fatal(err)
	}
	defer key.Destroy()
	material := &awsGatewayMaterial{key: key}
	intent := SessionIntent{SessionID: "owned", ExpiresAt: time.Unix(400, 0)}
	now := time.Unix(200, 0)
	proof, err := consoleProof(material, intent, "127.0.0.1:8000", now)
	if err != nil {
		f.Fatal(err)
	}
	defer secret.Wipe(proof)
	f.Add(proof)
	f.Add([]byte("invalid"))
	f.Add(base64.RawURLEncoding.AppendEncode(nil, make([]byte, 56)))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 128 {
			return
		}
		valid := validConsoleProof(material, intent, "127.0.0.1:8000", raw, now)
		if valid && validConsoleProof(material, intent, "127.0.0.1:8001", raw, now) {
			t.Fatal("accepted proof was not bound to its reviewed local origin")
		}
	})
}

func TestConsoleReclaimedJobDoesNotRemintAfterLosingNativeTokenState(t *testing.T) {
	state := consoleStateForAttempt(2)
	defer state.destroy()
	minted := false
	page, _, err := state.page(context.Background(), time.Now().Add(time.Minute), func(context.Context) (*secret.Buffer, error) {
		minted = true
		return secret.NewFrom([]byte("owned-reclaimed-token"))
	}, func(raw []byte) (*secret.Buffer, error) { return secret.NewFrom(raw) })
	if page != nil {
		page.Destroy()
	}
	if err == nil || minted {
		t.Fatal("reclaimed gateway job minted another console credential after losing the original result")
	}
}

func FuzzConsoleSigninTokenEnvelope(f *testing.F) {
	f.Add([]byte(`{"SigninToken":"owned-console-result"}`))
	f.Add([]byte(`{"SigninToken":"bad\r\nvalue"}`))
	f.Add([]byte("null"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		held, err := parseConsoleToken(raw)
		if err == nil {
			defer held.Destroy()
			if held.Len() == 0 || held.Len() > 32<<10 {
				t.Fatal("unbounded native sign-in token accepted")
			}
			if err := held.Use(func(value []byte) error {
				if !validOAuthBearer(value) {
					t.Fatal("unsafe native sign-in token accepted")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		}
	})
}
