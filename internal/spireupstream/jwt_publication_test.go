// SPDX-License-Identifier: BUSL-1.1

package spireupstream

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	upstreamauthorityv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/upstreamauthority/v1"
	typesv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
)

// jwtKeyServer is trstctl's /api/v1/spiffe/upstream-jwt-keys as the plugin
// sees it: POST publishes and lists, GET lists.
type jwtKeyServer struct {
	mu        sync.Mutex
	keys      []trstctlJWTKey
	posts     int
	idemKeys  []string
	authFails int
}

func (s *jwtKeyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/v1/spiffe/upstream-jwt-keys" {
		http.NotFound(w, r)
		return
	}
	if r.Header.Get("Authorization") != "Bearer plugin-token" {
		s.mu.Lock()
		s.authFails++
		s.mu.Unlock()
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Method == http.MethodPost {
		var key trstctlJWTKey
		if err := json.NewDecoder(r.Body).Decode(&key); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.posts++
		s.idemKeys = append(s.idemKeys, r.Header.Get("Idempotency-Key"))
		s.keys = append(s.keys, key)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"items": s.keys})
}

func (s *jwtKeyServer) add(key trstctlJWTKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys = append(s.keys, key)
}

type jwtStream struct {
	grpc.ServerStream
	ctx       context.Context
	mu        sync.Mutex
	responses []*upstreamauthorityv1.PublishJWTKeyResponse
	sent      chan struct{}
}

func (s *jwtStream) Context() context.Context { return s.ctx }

func (s *jwtStream) Send(resp *upstreamauthorityv1.PublishJWTKeyResponse) error {
	s.mu.Lock()
	s.responses = append(s.responses, resp)
	s.mu.Unlock()
	s.sent <- struct{}{}
	return nil
}

// A205: the plugin publishes the SPIRE server's JWT key to trstctl, answers
// with every key trstctl returns, and sends the set again when another server
// publishes; the key, its expiry and its taint travel intact.
func TestPluginPublishesTheJWTKeyAndSendsLaterPublications(t *testing.T) {
	keys := &jwtKeyServer{}
	srv := httptest.NewTLSServer(keys)
	t.Cleanup(srv.Close)
	caBundleFile := t.TempDir() + "/trstctl-ca.pem"
	if err := os.WriteFile(caBundleFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	p := New()
	if _, err := p.Configure(context.Background(), &configv1.ConfigureRequest{HclConfiguration: `
endpoint = "` + srv.URL + `"
ca_bundle_file = "` + caBundleFile + `"
ca_authority_id = "root-1"
token_file = "` + writeTempToken(t, []byte("plugin-token\n")) + `"
jwt_key_refresh_seconds = 1
`}); err != nil {
		t.Fatalf("configure plugin: %v", err)
	}

	expires := time.Now().Add(time.Hour).Truncate(time.Second)
	published := &typesv1.JWTKey{KeyId: "server-a-key", PublicKey: []byte{0x30, 0x59, 0x01}, ExpiresAt: expires.Unix()}
	ctx, cancel := context.WithCancel(context.Background())
	stream := &jwtStream{ctx: ctx, sent: make(chan struct{}, 8)}
	done := make(chan error, 1)
	go func() {
		done <- p.PublishJWTKeyAndSubscribe(&upstreamauthorityv1.PublishJWTKeyRequest{JwtKey: published}, stream)
	}()
	waitSent := func(what string) {
		t.Helper()
		select {
		case <-stream.sent:
		case <-time.After(10 * time.Second):
			t.Fatalf("no response %s", what)
		}
	}
	waitSent("after publishing")
	stream.mu.Lock()
	first := stream.responses[0].GetUpstreamJwtKeys()
	stream.mu.Unlock()
	if len(first) != 1 || first[0].GetKeyId() != "server-a-key" || !bytes.Equal(first[0].GetPublicKey(), published.GetPublicKey()) ||
		first[0].GetExpiresAt() != expires.Unix() {
		t.Fatalf("first response = %v", first)
	}
	keys.mu.Lock()
	if keys.posts != 1 || !strings.HasPrefix(keys.idemKeys[0], "spire-upstream-jwt-") {
		t.Fatalf("posts = %d, idempotency keys = %v", keys.posts, keys.idemKeys)
	}
	keys.mu.Unlock()

	// Another SPIRE server publishes; the subscription sends both keys.
	keys.add(trstctlJWTKey{KeyID: "server-b-key", PublicKey: []byte{0x30, 0x59, 0x02}, Tainted: true})
	waitSent("after the second server published")
	stream.mu.Lock()
	second := stream.responses[len(stream.responses)-1].GetUpstreamJwtKeys()
	stream.mu.Unlock()
	if len(second) != 2 || second[1].GetKeyId() != "server-b-key" || !second[1].GetTainted() || second[1].GetExpiresAt() != 0 {
		t.Fatalf("update = %v", second)
	}
	// No change, no response.
	select {
	case <-stream.sent:
		t.Fatal("the subscription resent an unchanged set")
	case <-time.After(2500 * time.Millisecond):
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("subscription ended with %v", err)
	}
}

// A request without a key is refused, and trstctl refusing the token on the
// first publication reaches SPIRE as the error.
func TestPluginJWTPublicationRefusesWithoutAKeyOrToken(t *testing.T) {
	p := New()
	keys := &jwtKeyServer{}
	srv := httptest.NewTLSServer(keys)
	t.Cleanup(srv.Close)
	caBundleFile := t.TempDir() + "/trstctl-ca.pem"
	if err := os.WriteFile(caBundleFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Configure(context.Background(), &configv1.ConfigureRequest{HclConfiguration: `
endpoint = "` + srv.URL + `"
ca_bundle_file = "` + caBundleFile + `"
ca_authority_id = "root-1"
token_file = "` + writeTempToken(t, []byte("wrong-token\n")) + `"
`}); err != nil {
		t.Fatalf("configure plugin: %v", err)
	}
	stream := &jwtStream{ctx: context.Background(), sent: make(chan struct{}, 1)}
	if err := p.PublishJWTKeyAndSubscribe(&upstreamauthorityv1.PublishJWTKeyRequest{}, stream); err == nil {
		t.Fatal("a request without a key was accepted")
	}
	err := p.PublishJWTKeyAndSubscribe(&upstreamauthorityv1.PublishJWTKeyRequest{JwtKey: &typesv1.JWTKey{KeyId: "k", PublicKey: []byte{1}}}, stream)
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("a rejected token = %v, want trstctl's 401", err)
	}
}

// A SPIRE server pointed at a trstctl that does not serve JWT key publication
// still starts: an older trstctl's 404 (or a 405 or 501) reaches SPIRE as
// Unimplemented, which SPIRE takes as an upstream authority that does not
// publish JWT keys, so it keeps the key in its own bundle. Any other failure
// stays an error.
func TestPluginJWTPublicationIsUnimplementedWhenTrstctlDoesNotServeIt(t *testing.T) {
	for _, tc := range []struct {
		httpStatus int
		want       codes.Code
	}{
		{http.StatusNotFound, codes.Unimplemented},
		{http.StatusMethodNotAllowed, codes.Unimplemented},
		{http.StatusNotImplemented, codes.Unimplemented},
		{http.StatusServiceUnavailable, codes.Unavailable},
		{http.StatusInternalServerError, codes.Unavailable},
	} {
		t.Run(strconv.Itoa(tc.httpStatus), func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, http.StatusText(tc.httpStatus), tc.httpStatus)
			}))
			t.Cleanup(srv.Close)
			caBundleFile := t.TempDir() + "/trstctl-ca.pem"
			if err := os.WriteFile(caBundleFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
				t.Fatal(err)
			}
			p := New()
			if _, err := p.Configure(context.Background(), &configv1.ConfigureRequest{HclConfiguration: `
endpoint = "` + srv.URL + `"
ca_bundle_file = "` + caBundleFile + `"
ca_authority_id = "root-1"
token_file = "` + writeTempToken(t, []byte("plugin-token\n")) + `"
`}); err != nil {
				t.Fatalf("configure plugin: %v", err)
			}
			stream := &jwtStream{ctx: context.Background(), sent: make(chan struct{}, 1)}
			err := p.PublishJWTKeyAndSubscribe(&upstreamauthorityv1.PublishJWTKeyRequest{JwtKey: &typesv1.JWTKey{KeyId: "k", PublicKey: []byte{1}}}, stream)
			if status.Code(err) != tc.want {
				t.Fatalf("HTTP %d reached SPIRE as %v, want code %v", tc.httpStatus, err, tc.want)
			}
			if len(stream.responses) != 0 {
				t.Fatalf("the plugin answered SPIRE with %v", stream.responses)
			}
		})
	}
}
