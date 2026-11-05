// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

const a263AzureClient = "owned-application"
const a263AzureTenant = "owned-tenant"
const a263AzureScope = "https://graph.microsoft.com/.default"
const a263AzureApplicationPath = "/v1.0/applications/owned-object"
const a263AzureTokenPath = "/" + a263AzureTenant + "/oauth2/v2.0/token"

type a263AzurePassword struct {
	value *secret.Buffer
	name  string
}
type a263AzureStandIn struct {
	mu        sync.Mutex
	url       string
	passwords map[string]a263AzurePassword
	tokens    map[string]a263GCPToken
	latest    string
	grant     *secret.Buffer
	note      string
}

func newA263AzureStandIn(t *testing.T) *a263AzureStandIn {
	t.Helper()
	s := &a263AzureStandIn{passwords: map[string]a263AzurePassword{}, tokens: map[string]a263GCPToken{}, note: "ghp_" + strings.Repeat("L", 36)}
	server := httptest.NewServer(http.HandlerFunc(s.serve))
	s.url = server.URL
	t.Cleanup(func() {
		server.Close()
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, p := range s.passwords {
			p.value.Destroy()
		}
		for _, token := range s.tokens {
			token.value.Destroy()
		}
		if s.grant != nil {
			s.grant.Destroy()
		}
	})
	return s
}
func (s *a263AzureStandIn) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if strings.HasPrefix(r.URL.Path, a263AzureApplicationPath) {
		if r.Header.Get("Authorization") != "Bearer a263-owned-admin" {
			http.Error(w, "admin required", http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == a263AzureApplicationPath:
			values := []map[string]string{}
			for id, p := range s.passwords {
				values = append(values, map[string]string{"keyId": id, "displayName": p.name})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"passwordCredentials": values})
		case r.Method == http.MethodPost && r.URL.Path == a263AzureApplicationPath+"/addPassword":
			var input struct {
				PasswordCredential struct {
					DisplayName string
					EndDateTime time.Time
				}
			}
			if json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&input) != nil || !strings.HasPrefix(input.PasswordCredential.DisplayName, "trstctl-") || !input.PasswordCredential.EndDateTime.After(time.Now()) {
				http.Error(w, "invalid password request", http.StatusBadRequest)
				return
			}
			nonce, err := crypto.RandomBytes(32)
			if err != nil {
				http.Error(w, "entropy unavailable", http.StatusInternalServerError)
				return
			}
			defer secret.Wipe(nonce)
			value := base64.RawURLEncoding.AppendEncode([]byte("owned+&=% secret-é-"), nonce)
			defer secret.Wipe(value)
			held, err := secret.NewFrom(value)
			if err != nil {
				http.Error(w, "password unavailable", http.StatusInternalServerError)
				return
			}
			id := uuid.NewString()
			s.passwords[id] = a263AzurePassword{held, input.PasswordCredential.DisplayName}
			_ = json.NewEncoder(w).Encode(struct {
				ID    string           `json:"keyId"`
				Value secret.JSONBytes `json:"secretText"`
			}{id, value}) // #nosec G117 -- owned Graph addPassword protocol fixture; secret response bytes are wiped and held locked (CWE-200)
		case r.Method == http.MethodPost && r.URL.Path == a263AzureApplicationPath+"/removePassword":
			var input struct{ KeyID string }
			if json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&input) != nil {
				http.Error(w, "invalid deletion", http.StatusBadRequest)
				return
			}
			if p, ok := s.passwords[input.KeyID]; ok {
				p.value.Destroy()
				delete(s.passwords, input.KeyID)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
		return
	}
	if r.Method == http.MethodPost && r.URL.Path == a263AzureTokenPath {
		raw, err := io.ReadAll(io.LimitReader(r.Body, 64<<10+1))
		defer secret.Wipe(raw)
		if err != nil || len(raw) > 64<<10 {
			http.Error(w, "bad grant", http.StatusBadRequest)
			return
		}
		fields, ok := a263AzureForm(raw)
		defer func() {
			for _, value := range fields {
				secret.Wipe(value)
			}
		}()
		if !ok || len(fields) != 4 || !bytes.Equal(fields["grant_type"], []byte("client_credentials")) || !bytes.Equal(fields["client_id"], []byte(a263AzureClient)) || !bytes.Equal(fields["scope"], []byte(a263AzureScope)) {
			http.Error(w, "invalid application authority", http.StatusBadRequest)
			return
		}
		valid := false
		for _, password := range s.passwords {
			_ = password.value.Use(func(value []byte) error {
				valid = valid || crypto.ConstantTimeEqual(value, fields["client_secret"])
				return nil
			})
		}
		if !valid {
			http.Error(w, "invalid_client", http.StatusUnauthorized)
			return
		}
		nonce, err := crypto.RandomBytes(32)
		if err != nil {
			http.Error(w, "entropy unavailable", http.StatusInternalServerError)
			return
		}
		value := base64.RawURLEncoding.AppendEncode([]byte("a263-owned-access-"), nonce)
		secret.Wipe(nonce)
		defer secret.Wipe(value)
		held, err := secret.NewFrom(value)
		if err != nil {
			http.Error(w, "token unavailable", http.StatusInternalServerError)
			return
		}
		s.latest = crypto.SHA256Hex(value)
		s.tokens[s.latest] = a263GCPToken{value: held, expires: time.Now().Add(20 * time.Second)}
		if s.grant != nil {
			s.grant.Destroy()
		}
		s.grant, err = secret.NewFrom(raw)
		if err != nil {
			http.Error(w, "grant unavailable", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(struct {
			Value   secret.JSONBytes `json:"access_token"`
			Type    string           `json:"token_type"`
			Expires int              `json:"expires_in"`
		}{value, "Bearer", 20}) // #nosec G117 -- owned OAuth endpoint returns issued tokens; locked storage and wipeable JSON bytes (CWE-200)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/v1.0/") {
		raw := []byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		defer secret.Wipe(raw)
		token, ok := s.tokens[crypto.SHA256Hex(raw)]
		if !ok || !time.Now().Before(token.expires) {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet || r.URL.Path != "/v1.0/organization" {
			http.Error(w, "application permission denied", http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"value": []map[string]string{{"id": a263AzureTenant, "displayName": s.note}}})
		return
	}
	http.NotFound(w, r)
}
func a263AzureForm(raw []byte) (map[string][]byte, bool) {
	fields := map[string][]byte{}
	valid := true
	for _, field := range bytes.Split(raw, []byte("&")) {
		pair := bytes.SplitN(field, []byte("="), 2)
		if len(pair) != 2 {
			valid = false
			break
		}
		name := string(pair[0])
		if _, ok := fields[name]; ok {
			valid = false
			break
		}
		decoded := make([]byte, 0, len(pair[1]))
		for i := 0; i < len(pair[1]); i++ {
			switch pair[1][i] {
			case '+':
				decoded = append(decoded, ' ')
			case '%':
				if i+2 >= len(pair[1]) {
					valid = false
					break
				}
				var one [1]byte
				if _, err := hex.Decode(one[:], pair[1][i+1:i+3]); err != nil {
					valid = false
					break
				}
				decoded = append(decoded, one[0])
				i += 2
			default:
				decoded = append(decoded, pair[1][i])
			}
			if !valid {
				break
			}
		}
		fields[name] = decoded
		if !valid {
			break
		}
	}
	return fields, valid
}
func (s *a263AzureStandIn) credentialCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.passwords)
}
func (s *a263AzureStandIn) probe(t *testing.T, path string, grant bool) int {
	t.Helper()
	s.mu.Lock()
	token := s.tokens[s.latest].value
	form := s.grant
	s.mu.Unlock()
	u, err := url.Parse(s.url)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialTimeout("tcp", u.Host, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	var wire []byte
	if grant {
		err = form.Use(func(body []byte) error {
			wire = fmt.Appendf(nil, "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", a263AzureTokenPath, u.Host, len(body))
			wire = append(wire, body...)
			return nil
		})
	} else {
		err = token.Use(func(value []byte) error {
			wire = fmt.Appendf(nil, "GET %s HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer ", path, u.Host)
			wire = append(wire, value...)
			wire = append(wire, []byte("\r\nConnection: close\r\n\r\n")...)
			return nil
		})
	}
	if err != nil {
		t.Fatal(err)
	}
	held, err := secret.NewFrom(wire)
	secret.Wipe(wire)
	if err != nil {
		t.Fatal(err)
	}
	err = held.Use(func(raw []byte) error { _, err := conn.Write(raw); return err })
	held.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	_, _ = io.Copy(io.Discard, response.Body)
	return response.StatusCode
}
