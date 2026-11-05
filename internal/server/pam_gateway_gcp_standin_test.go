// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
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

const a263GCPEmail = "reader@p.iam.gserviceaccount.com"
const a263GCPKeyPath = "/v1/projects/p/serviceAccounts/" + a263GCPEmail + "/keys"
const a263GCPScope = "https://www.googleapis.com/auth/devstorage.read_only"

type a263GCPKey struct {
	certificate []byte
	public      crypto.PublicKey
}
type a263GCPToken struct {
	value   *secret.Buffer
	expires time.Time
}
type a263GCPStandIn struct {
	mu        sync.Mutex
	url       string
	keys      map[string]a263GCPKey
	tokens    map[string]a263GCPToken
	serial    int
	latest    string
	assertion *secret.Buffer
	note      string
}

func newA263GCPStandIn(t *testing.T) *a263GCPStandIn {
	t.Helper()
	stand := &a263GCPStandIn{keys: map[string]a263GCPKey{}, tokens: map[string]a263GCPToken{}, note: "ghp_" + strings.Repeat("K", 36)}
	server := httptest.NewServer(http.HandlerFunc(stand.serve))
	stand.url = server.URL
	t.Cleanup(func() {
		server.Close()
		stand.mu.Lock()
		defer stand.mu.Unlock()
		if stand.assertion != nil {
			stand.assertion.Destroy()
		}
		for _, token := range stand.tokens {
			token.value.Destroy()
		}
	})
	return stand
}

func (stand *a263GCPStandIn) serve(w http.ResponseWriter, r *http.Request) {
	stand.mu.Lock()
	defer stand.mu.Unlock()
	if strings.HasPrefix(r.URL.Path, a263GCPKeyPath) {
		if r.Header.Get("Authorization") != "Bearer a263-owned-admin" {
			http.Error(w, "admin auth required", http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == a263GCPKeyPath:
			keys := []map[string]string{}
			for id := range stand.keys {
				keys = append(keys, map[string]string{"name": strings.TrimPrefix(a263GCPKeyPath, "/v1/") + "/" + id})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
		case r.Method == http.MethodPost && r.URL.Path == a263GCPKeyPath+":upload":
			var input struct{ PublicKeyData string }
			if json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&input) != nil {
				http.Error(w, "bad upload", 400)
				return
			}
			certificate, err := base64.StdEncoding.DecodeString(input.PublicKeyData)
			if err != nil {
				http.Error(w, "bad certificate", 400)
				return
			}
			block, _ := pem.Decode(certificate)
			if block == nil {
				http.Error(w, "missing certificate", 400)
				return
			}
			der, err := crypto.PublicKeyDERFromCert(block.Bytes)
			if err != nil {
				http.Error(w, "bad public key", 400)
				return
			}
			stand.serial++
			id := fmt.Sprintf("%040x", stand.serial)
			stand.keys[id] = a263GCPKey{certificate: certificate, public: crypto.PublicKey{Algorithm: crypto.RSA2048, DER: der}}
			_ = json.NewEncoder(w).Encode(map[string]string{"name": strings.TrimPrefix(a263GCPKeyPath, "/v1/") + "/" + id})
		case strings.HasPrefix(r.URL.Path, a263GCPKeyPath+"/"):
			id := strings.TrimPrefix(r.URL.Path, a263GCPKeyPath+"/")
			key, ok := stand.keys[id]
			if !ok {
				http.NotFound(w, r)
				return
			}
			if r.Method == http.MethodDelete {
				delete(stand.keys, id)
				_ = json.NewEncoder(w).Encode(map[string]any{})
				return
			}
			if r.Method == http.MethodGet {
				_ = json.NewEncoder(w).Encode(map[string]string{"name": strings.TrimPrefix(r.URL.Path, "/v1/"), "publicKeyData": base64.StdEncoding.EncodeToString(key.certificate)})
				return
			}
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
		return
	}
	if r.URL.Path == "/oauth/token" && r.Method == http.MethodPost {
		body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
		defer secret.Wipe(body)
		if err != nil {
			http.Error(w, "bad grant", 400)
			return
		}
		var assertion []byte
		for _, field := range bytes.Split(body, []byte("&")) {
			if bytes.HasPrefix(field, []byte("assertion=")) {
				assertion = field[len("assertion="):]
			}
		}
		if !bytes.Contains(body, []byte("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer")) {
			http.Error(w, "wrong grant type", 400)
			return
		}
		jwks := crypto.JWKS{}
		for id, key := range stand.keys {
			jwk, err := crypto.PublicJWK(key.public, id)
			if err == nil {
				jwks.Keys = append(jwks.Keys, jwk)
			}
		}
		claims, err := crypto.VerifyJWTBytes(assertion, jwks)
		defer secret.Wipe(claims)
		var parsed struct {
			Iss, Aud, Scope, Sub string
			Iat, Exp             int64
		}
		if err != nil || json.Unmarshal(claims, &parsed) != nil || parsed.Iss != a263GCPEmail || parsed.Sub != "" || parsed.Aud != stand.url+"/oauth/token" || parsed.Scope != a263GCPScope || parsed.Exp <= time.Now().Unix() || parsed.Exp > parsed.Iat+3600 {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		nonce, err := crypto.RandomBytes(32)
		if err != nil {
			http.Error(w, "entropy unavailable", 500)
			return
		}
		token := base64.RawURLEncoding.AppendEncode([]byte("a263-owned-access-"), nonce)
		secret.Wipe(nonce)
		defer secret.Wipe(token)
		held, err := secret.NewFrom(token)
		if err != nil {
			http.Error(w, "token unavailable", 500)
			return
		}
		stand.latest = crypto.SHA256Hex(token)
		stand.tokens[stand.latest] = a263GCPToken{value: held, expires: time.Now().Add(20 * time.Second)}
		if stand.assertion != nil {
			stand.assertion.Destroy()
		}
		stand.assertion, err = secret.NewFrom(assertion)
		if err != nil {
			http.Error(w, "assertion unavailable", 500)
			return
		}
		_ = json.NewEncoder(w).Encode(struct { // #nosec G117 -- the owned OAuth endpoint must return its issued token; locked storage and wipeable JSON bytes (CWE-200)
			AccessToken secret.JSONBytes `json:"access_token"`
			TokenType   string           `json:"token_type"`
			Expires     int              `json:"expires_in"`
		}{token, "Bearer", 20})
		return
	}
	if strings.HasPrefix(r.URL.Path, "/storage/v1/") {
		raw := []byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		defer secret.Wipe(raw)
		token, ok := stand.tokens[crypto.SHA256Hex(raw)]
		if !ok || !time.Now().Before(token.expires) {
			http.Error(w, "token invalid", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet || r.URL.Path != "/storage/v1/b/owned-bucket/o/note" {
			http.Error(w, "scope denied", http.StatusForbidden)
			return
		}
		_, _ = io.WriteString(w, stand.note)
		return
	}
	http.NotFound(w, r)
}

func (stand *a263GCPStandIn) keyCount() int {
	stand.mu.Lock()
	defer stand.mu.Unlock()
	return len(stand.keys)
}

// Probe the same already-issued token independently of the product tunnel. Key
// deletion deliberately leaves it valid until the native token deadline.
func (stand *a263GCPStandIn) probe(t *testing.T, path string, grant bool) int {
	t.Helper()
	stand.mu.Lock()
	token := stand.tokens[stand.latest].value
	assertion := stand.assertion
	stand.mu.Unlock()
	u, err := url.Parse(stand.url)
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
		err = assertion.Use(func(value []byte) error {
			body := append([]byte("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion="), value...)
			defer secret.Wipe(body)
			wire = fmt.Appendf(nil, "POST /oauth/token HTTP/1.1\r\nHost: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", u.Host, len(body))
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
