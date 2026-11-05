// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/awssignin"
	"trstctl.com/trstctl/internal/crypto/secret"
)

type a263ConsoleToken struct {
	value   *secret.Buffer
	leaseID string
	expires time.Time
}
type a263ConsoleStandIn struct {
	mu            sync.Mutex
	aws           *a263AWSStandIn
	url           string
	tokens        map[string]a263ConsoleToken
	mints, logins int
}

func newA263ConsoleStandIn(t *testing.T, aws *a263AWSStandIn) *a263ConsoleStandIn {
	t.Helper()
	s := &a263ConsoleStandIn{aws: aws, tokens: map[string]a263ConsoleToken{}}
	server := httptest.NewServer(http.HandlerFunc(s.serve))
	s.url = server.URL
	t.Cleanup(func() {
		server.Close()
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, token := range s.tokens {
			token.value.Destroy()
		}
	})
	return s
}
func (s *a263ConsoleStandIn) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/federation" || r.URL.RawQuery != "" {
		http.Error(w, "native federation requires POST", http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 256<<10+1))
	defer secret.Wipe(body)
	if err != nil || len(body) > 256<<10 {
		http.Error(w, "bad federation form", http.StatusBadRequest)
		return
	}
	fields, valid := a263AzureForm(body)
	defer func() {
		for _, value := range fields {
			secret.Wipe(value)
		}
	}()
	if !valid {
		http.Error(w, "bad federation encoding", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case bytes.Equal(fields["Action"], []byte("getSigninToken")):
		if len(fields) != 2 || len(fields["Session"]) == 0 {
			http.Error(w, "unexpected federation authority", http.StatusBadRequest)
			return
		}
		var session struct {
			ID    secret.JSONBytes `json:"sessionId"`
			Key   secret.JSONBytes `json:"sessionKey"`
			Token secret.JSONBytes `json:"sessionToken"`
		}
		defer func() { secret.Wipe(session.ID); secret.Wipe(session.Key); secret.Wipe(session.Token) }()
		if json.Unmarshal(fields["Session"], &session) != nil {
			http.Error(w, "bad Session", http.StatusBadRequest)
			return
		}
		matched := ""
		s.aws.mu.Lock()
		for id, issued := range s.aws.issued {
			if issued.denied || !time.Now().Before(issued.expiration) {
				continue
			}
			_ = issued.use(func(c awssignin.Credentials) error {
				if crypto.ConstantTimeEqual(c.AccessKeyID, session.ID) && crypto.ConstantTimeEqual(c.SecretAccessKey, session.Key) && crypto.ConstantTimeEqual(c.SessionToken, session.Token) {
					matched = id
				}
				return nil
			})
		}
		s.aws.mu.Unlock()
		if matched == "" {
			http.Error(w, "native session rejected", http.StatusForbidden)
			return
		}
		nonce, err := crypto.RandomBytes(32)
		if err != nil {
			http.Error(w, "entropy unavailable", http.StatusServiceUnavailable)
			return
		}
		value := base64.RawURLEncoding.AppendEncode([]byte("owned-console-"), nonce)
		secret.Wipe(nonce)
		defer secret.Wipe(value)
		held, err := secret.NewFrom(value)
		if err != nil {
			http.Error(w, "token unavailable", http.StatusServiceUnavailable)
			return
		}
		s.mints++
		s.tokens[crypto.SHA256Hex(value)] = a263ConsoleToken{held, matched, time.Now().Add(15 * time.Minute)}
		_ = json.NewEncoder(w).Encode(struct {
			Value secret.JSONBytes `json:"SigninToken"`
		}{value}) // #nosec G117 -- native federation protocol returns its owned issued sign-in token (CWE-200)
	case bytes.Equal(fields["Action"], []byte("login")):
		if len(fields) != 4 || !bytes.Equal(fields["Destination"], []byte(s.url+"/console")) {
			http.Error(w, "wrong console destination", http.StatusBadRequest)
			return
		}
		issuer, err := url.Parse(string(fields["Issuer"]))
		if err != nil || issuer.Scheme != "http" || issuer.Hostname() != "127.0.0.1" {
			http.Error(w, "wrong issuer", http.StatusBadRequest)
			return
		}
		token, ok := s.tokens[crypto.SHA256Hex(fields["SigninToken"])]
		if !ok || !time.Now().Before(token.expires) {
			http.Error(w, "expired sign-in token", http.StatusForbidden)
			return
		}
		s.aws.mu.Lock()
		issued := s.aws.issued[token.leaseID]
		admitted := issued != nil && !issued.denied && time.Now().Before(issued.expiration)
		s.aws.mu.Unlock()
		if !admitted {
			http.Error(w, "issued role access denied", http.StatusForbidden)
			return
		}
		s.logins++
		_, _ = io.WriteString(w, "Native console stand-in accepted the issued role")
	default:
		http.Error(w, "unknown federation action", http.StatusBadRequest)
	}
}
func (s *a263ConsoleStandIn) counts() (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mints, s.logins
}
func (s *a263ConsoleStandIn) assertTokenAbsent(t *testing.T, raw []byte) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, token := range s.tokens {
		if err := token.value.Use(func(value []byte) error {
			if bytes.Contains(raw, value) {
				t.Fatal("native sign-in token reached recording/logs")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}
