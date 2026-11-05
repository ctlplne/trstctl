// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"io"
	"net"
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

type a263AWSIssued struct {
	id         string
	key, token *secret.Buffer
	userID     string
	expiration time.Time
	denied     bool
}

func (v *a263AWSIssued) use(fn func(awssignin.Credentials) error) error {
	return v.key.Use(func(key []byte) error {
		return v.token.Use(func(token []byte) error {
			return fn(awssignin.Credentials{AccessKeyID: []byte(v.id), SecretAccessKey: key, SessionToken: token})
		})
	})
}

type a263AWSStandIn struct {
	mu     sync.Mutex
	issued map[string]*a263AWSIssued
	url    string
	native string
}

// The fixture forwards administrator wire calls to the real LocalStack API and
// captures only the issued test leases. Its leased-user signature and permission
// checks are a stand-in: LocalStack itself does not implement IAM enforcement.
func newA263AWSStandIn(t *testing.T, native string) *a263AWSStandIn {
	t.Helper()
	stand := &a263AWSStandIn{issued: map[string]*a263AWSIssued{}, native: native}
	server := httptest.NewServer(http.HandlerFunc(stand.serve))
	stand.url = server.URL
	t.Cleanup(func() {
		server.Close()
		stand.mu.Lock()
		defer stand.mu.Unlock()
		for _, issued := range stand.issued {
			issued.key.Destroy()
			issued.token.Destroy()
		}
	})
	return stand
}

func (stand *a263AWSStandIn) serve(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20+1))
	defer secret.Wipe(body)
	if err != nil || len(body) > 1<<20 {
		http.Error(w, "bounded fixture request", http.StatusRequestEntityTooLarge)
		return
	}
	auth := []byte(r.Header.Get("Authorization"))
	defer secret.Wipe(auth)
	const prefix = "AWS4-HMAC-SHA256 Credential="
	admin := bytes.HasPrefix(auth, []byte(prefix+"test/"))
	if !admin {
		id := ""
		if bytes.HasPrefix(auth, []byte(prefix)) {
			rest := auth[len(prefix):]
			if n := bytes.IndexByte(rest, '/'); n > 0 {
				id = string(rest[:n])
			}
		}
		stand.mu.Lock()
		issued := stand.issued[id]
		allowed := issued != nil && !issued.denied && time.Now().Before(issued.expiration)
		if allowed {
			signedAt, parseErr := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
			allowed = parseErr == nil && time.Since(signedAt) < 5*time.Minute && time.Until(signedAt) < 5*time.Minute
			if allowed {
				clone := r.Clone(r.Context())
				clone.URL.Scheme = "http"
				clone.URL.Host = r.Host
				clone.RequestURI = ""
				useErr := issued.use(func(credential awssignin.Credentials) error {
					incomingToken := []byte(r.Header.Get("X-Amz-Security-Token"))
					defer secret.Wipe(incomingToken)
					expected, err := awssignin.Sign(clone, body, credential, "us-east-1", "s3", signedAt)
					defer secret.Wipe(expected)
					line := bytes.SplitN(expected, []byte("\r\n"), 2)
					allowed = err == nil && len(line) == 2 && crypto.ConstantTimeEqual(auth, bytes.TrimPrefix(line[0], []byte("Authorization: "))) && crypto.ConstantTimeEqual(incomingToken, credential.SessionToken)
					return nil
				})
				if useErr != nil {
					allowed = false
				}
			}
		}
		// This fixture's role grants only these object reads. It is deliberately
		// narrower than the LocalStack administrator the test uses for setup.
		allowed = allowed && (r.Method == http.MethodGet || r.Method == http.MethodHead) && r.URL.Path == "/a263-gateway/note"
		stand.mu.Unlock()
		if !allowed {
			http.Error(w, "AccessDenied", http.StatusForbidden)
			return
		}
	}
	request, err := http.NewRequestWithContext(r.Context(), r.Method, stand.native+r.URL.RequestURI(), bytes.NewReader(body))
	if err != nil {
		http.Error(w, "fixture route", http.StatusBadGateway)
		return
	}
	request.Header = r.Header.Clone()
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		http.Error(w, "fixture target", http.StatusBadGateway)
		return
	}
	defer func() { _ = response.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	defer secret.Wipe(raw)
	if err != nil {
		http.Error(w, "fixture response", http.StatusBadGateway)
		return
	}
	if admin && response.StatusCode == http.StatusOK {
		values, _ := url.ParseQuery(string(body))
		switch values.Get("Action") {
		case "AssumeRole":
			stand.capture(raw)
		case "PutRolePolicy":
			var policy struct {
				Statement []struct {
					Effect, Action, Resource string
					Condition                map[string]map[string]string
				}
			}
			if json.Unmarshal([]byte(values.Get("PolicyDocument")), &policy) == nil {
				stand.mu.Lock()
				for _, statement := range policy.Statement {
					if statement.Effect == "Deny" && statement.Action == "*" && statement.Resource == "*" {
						user := statement.Condition["StringEquals"]["aws:userid"]
						for _, issued := range stand.issued {
							if issued.userID == user {
								issued.denied = true
							}
						}
					}
				}
				stand.mu.Unlock()
			}
		}
	}
	for name, values := range response.Header {
		if name == "Content-Length" || name == "Transfer-Encoding" || name == "Connection" {
			continue
		}
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	w.WriteHeader(response.StatusCode)
	_, _ = w.Write(raw)
}

func (stand *a263AWSStandIn) capture(raw []byte) {
	var result struct {
		Result struct {
			Credentials struct {
				ID         string           `xml:"AccessKeyId"`
				Key        secret.JSONBytes `xml:"SecretAccessKey"`
				Token      secret.JSONBytes `xml:"SessionToken"`
				Expiration time.Time        `xml:"Expiration"`
			} `xml:"Credentials"`
			User struct {
				ID string `xml:"AssumedRoleId"`
			} `xml:"AssumedRoleUser"`
		} `xml:"AssumeRoleResult"`
	}
	if xml.Unmarshal(raw, &result) != nil {
		return
	}
	defer secret.Wipe(result.Result.Credentials.Key)
	defer secret.Wipe(result.Result.Credentials.Token)
	key, err := secret.NewFrom(result.Result.Credentials.Key)
	if err != nil {
		return
	}
	token, err := secret.NewFrom(result.Result.Credentials.Token)
	if err != nil {
		key.Destroy()
		return
	}
	stand.mu.Lock()
	defer stand.mu.Unlock()
	id := result.Result.Credentials.ID
	if old := stand.issued[id]; old != nil {
		old.key.Destroy()
		old.token.Destroy()
	}
	stand.issued[id] = &a263AWSIssued{id: id, key: key, token: token, userID: result.Result.User.ID, expiration: result.Result.Credentials.Expiration}
}

// probe uses fixture-only held bytes to independently check the very same
// issued key at the target. None of those bytes are given to the stock client.
func (stand *a263AWSStandIn) probe(t *testing.T, path string, tamper ...bool) int {
	t.Helper()
	stand.mu.Lock()
	defer stand.mu.Unlock()
	if len(stand.issued) != 1 {
		t.Fatalf("issued test leases = %d", len(stand.issued))
	}
	var issued *a263AWSIssued
	for _, candidate := range stand.issued {
		issued = candidate
	}
	request, err := http.NewRequest(http.MethodGet, stand.url+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Close = true
	var status int
	err = issued.use(func(credential awssignin.Credentials) error {
		headers, err := awssignin.Sign(request, nil, credential, "us-east-1", "s3", time.Now())
		if err != nil {
			return err
		}
		defer secret.Wipe(headers)
		if len(tamper) > 0 && tamper[0] {
			index := bytes.Index(headers, []byte("Signature="))
			if index < 0 {
				return io.ErrUnexpectedEOF
			}
			headers[index+len("Signature=")] ^= 1
		}
		var wire bytes.Buffer
		if err := request.Write(&wire); err != nil {
			return err
		}
		split := bytes.Index(wire.Bytes(), []byte("\r\n\r\n"))
		if split < 0 {
			return io.ErrUnexpectedEOF
		}
		peer, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(context.Background(), "tcp", request.URL.Host)
		if err != nil {
			return err
		}
		defer func() { _ = peer.Close() }()
		_ = peer.SetDeadline(time.Now().Add(5 * time.Second))
		// The handler needs its map mutex to verify this request. Borrowed material
		// stays alive under the test's sequential lifecycle while that lock is free.
		stand.mu.Unlock()
		defer stand.mu.Lock()
		parts := net.Buffers{wire.Bytes()[:split], []byte("\r\n"), headers, wire.Bytes()[split:]}
		if _, err := parts.WriteTo(peer); err != nil {
			return err
		}
		response, err := http.ReadResponse(bufio.NewReader(peer), request)
		if err != nil {
			return err
		}
		defer func() { _ = response.Body.Close() }()
		status = response.StatusCode
		_, _ = io.Copy(io.Discard, response.Body)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return status
}

func (stand *a263AWSStandIn) allDenied() bool {
	stand.mu.Lock()
	defer stand.mu.Unlock()
	if len(stand.issued) != 1 {
		return false
	}
	for _, issued := range stand.issued {
		if !issued.denied {
			return false
		}
	}
	return true
}
func (stand *a263AWSStandIn) assertNoCredential(t *testing.T, texts ...string) {
	t.Helper()
	stand.mu.Lock()
	defer stand.mu.Unlock()
	for _, issued := range stand.issued {
		_ = issued.use(func(c awssignin.Credentials) error {
			for _, text := range texts {
				for _, value := range [][]byte{c.AccessKeyID, c.SecretAccessKey, c.SessionToken} {
					if bytes.Contains([]byte(text), value) {
						t.Fatal("issued AWS credential escaped custody or masking")
					}
				}
			}
			return nil
		})
	}
}

func (stand *a263AWSStandIn) assertNoCredentialBytes(t *testing.T, data ...[]byte) {
	t.Helper()
	stand.mu.Lock()
	defer stand.mu.Unlock()
	for _, issued := range stand.issued {
		err := issued.use(func(c awssignin.Credentials) error {
			for _, value := range data {
				for _, field := range [][]byte{c.AccessKeyID, c.SecretAccessKey, c.SessionToken} {
					if bytes.Contains(value, field) {
						t.Fatal("issued AWS credential reached the client environment")
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
