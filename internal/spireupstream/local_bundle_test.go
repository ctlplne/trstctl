// SPDX-License-Identifier: BUSL-1.1

package spireupstream

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	upstreamauthorityv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/upstreamauthority/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// bundleServer is trstctl's CA authority listing (two pages) and JWT key list
// as the plugin reads them. The certificates are opaque DER-shaped bytes: the
// plugin relays them and never parses one.
type bundleServer struct {
	mu       sync.Mutex
	rootDER  []byte
	keys     []trstctlJWTKey
	noJWT    bool
	listings int
}

func (s *bundleServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer plugin-token" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch r.URL.Path {
	case "/api/v1/ca/authorities":
		s.listings++
		root := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.rootDER}))
		intermediate := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x30, 0x03, 0x02, 0x01, 0x02}}))
		parent := "root-1"
		if r.URL.Query().Get("cursor") == "" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"items":       []map[string]any{{"id": "spire-int", "parent_id": parent, "certificate_pem": intermediate}},
				"next_cursor": "page-2",
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{{"id": "root-1", "parent_id": nil, "certificate_pem": root}}})
	case "/api/v1/spiffe/upstream-jwt-keys":
		if s.noJWT {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"items": s.keys})
	default:
		http.NotFound(w, r)
	}
}

// sdkClient serves the plugin over gRPC in memory and returns the SPIRE
// plugin SDK's generated UpstreamAuthority client, as SPIRE Server's plugin
// loader holds it.
func sdkClient(t *testing.T, p *Plugin) upstreamauthorityv1.UpstreamAuthorityClient {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	upstreamauthorityv1.RegisterUpstreamAuthorityServer(server, p)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	conn, err := grpc.NewClient("passthrough:///spire-plugin",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return listener.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return upstreamauthorityv1.NewUpstreamAuthorityClient(conn)
}

func configuredBundlePlugin(t *testing.T, endpoint, authority string) *Plugin {
	t.Helper()
	p := New()
	if _, err := p.Configure(context.Background(), &configv1.ConfigureRequest{HclConfiguration: `
endpoint = "` + endpoint + `"
ca_authority_id = "` + authority + `"
token_file = "` + writeTempToken(t, []byte("plugin-token\n")) + `"
jwt_key_refresh_seconds = 1
`}); err != nil {
		t.Fatalf("configure plugin: %v", err)
	}
	return p
}

// A205-L3: through the SPIRE plugin SDK's own client, SubscribeToLocalBundle
// answers with the root the configured authority chains to (found across the
// authority listing's pages) and the published JWT keys, then streams the
// bundle again when another key is published and when the root changes.
func TestSubscribeToLocalBundleOverTheSDKClientA205L3(t *testing.T) {
	backend := &bundleServer{rootDER: []byte{0x30, 0x03, 0x02, 0x01, 0x01}, keys: []trstctlJWTKey{{KeyID: "spire-a", PublicKey: []byte{0x30, 0x59, 0x01}}}}
	srv := httptest.NewServer(backend)
	t.Cleanup(srv.Close)
	client := sdkClient(t, configuredBundlePlugin(t, srv.URL, "spire-int"))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	stream, err := client.SubscribeToLocalBundle(ctx, &upstreamauthorityv1.SubscribeToLocalBundleRequest{})
	if err != nil {
		t.Fatal(err)
	}
	first, err := stream.Recv()
	if err != nil {
		t.Fatalf("first bundle: %v", err)
	}
	if roots := first.GetUpstreamX509Roots(); len(roots) != 1 || !bytes.Equal(roots[0].GetAsn1(), backend.rootDER) {
		t.Fatalf("first bundle roots = %v, want the root spire-int chains to", roots)
	}
	if keys := first.GetUpstreamJwtKeys(); len(keys) != 1 || keys[0].GetKeyId() != "spire-a" {
		t.Fatalf("first bundle JWT keys = %v", keys)
	}

	backend.mu.Lock()
	backend.keys = append(backend.keys, trstctlJWTKey{KeyID: "trstctl-spiffe-jwt-1", PublicKey: []byte{0x30, 0x59, 0x02}})
	backend.mu.Unlock()
	second, err := stream.Recv()
	if err != nil {
		t.Fatalf("bundle after a key was published: %v", err)
	}
	if keys := second.GetUpstreamJwtKeys(); len(keys) != 2 || keys[1].GetKeyId() != "trstctl-spiffe-jwt-1" {
		t.Fatalf("second bundle JWT keys = %v", keys)
	}

	rotated := []byte{0x30, 0x03, 0x02, 0x01, 0x09}
	backend.mu.Lock()
	backend.rootDER = rotated
	backend.mu.Unlock()
	third, err := stream.Recv()
	if err != nil {
		t.Fatalf("bundle after the root changed: %v", err)
	}
	if roots := third.GetUpstreamX509Roots(); len(roots) != 1 || !bytes.Equal(roots[0].GetAsn1(), rotated) || len(third.GetUpstreamJwtKeys()) != 2 {
		t.Fatalf("third bundle = roots %v keys %v", roots, third.GetUpstreamJwtKeys())
	}
}

// A205-L3: a trstctl without JWT key publication still gives SPIRE its root;
// an authority the token cannot see is refused before any bundle is sent.
func TestSubscribeToLocalBundleRootsOnlyAndRefusalsA205L3(t *testing.T) {
	backend := &bundleServer{rootDER: []byte{0x30, 0x03, 0x02, 0x01, 0x01}, noJWT: true}
	srv := httptest.NewServer(backend)
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	stream, err := sdkClient(t, configuredBundlePlugin(t, srv.URL, "spire-int")).SubscribeToLocalBundle(ctx, &upstreamauthorityv1.SubscribeToLocalBundleRequest{})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := stream.Recv()
	if err != nil || len(bundle.GetUpstreamX509Roots()) != 1 || len(bundle.GetUpstreamJwtKeys()) != 0 {
		t.Fatalf("roots-only bundle = %v, %v", bundle, err)
	}

	stream, err = sdkClient(t, configuredBundlePlugin(t, srv.URL, "unknown-authority")).SubscribeToLocalBundle(ctx, &upstreamauthorityv1.SubscribeToLocalBundleRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("an unknown authority = %v, want FailedPrecondition", err)
	}
}
