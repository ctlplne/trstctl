// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"

	upstreamauthorityv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/upstreamauthority/v1"
	typesv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/spireupstream"
)

// a205L2Stream is the SPIRE server end of PublishJWTKeyAndSubscribe.
type a205L2Stream struct {
	grpc.ServerStream
	ctx  context.Context
	mu   sync.Mutex
	sent []*upstreamauthorityv1.PublishJWTKeyResponse
	got  chan struct{}
}

func (s *a205L2Stream) Context() context.Context { return s.ctx }

func (s *a205L2Stream) Send(resp *upstreamauthorityv1.PublishJWTKeyResponse) error {
	s.mu.Lock()
	s.sent = append(s.sent, resp)
	s.mu.Unlock()
	select {
	case s.got <- struct{}{}:
	default:
	}
	return nil
}

// TestServedSPIREUpstreamKeysCarryTrstctlsJWTAuthorityA205L2 is A205-L2: the
// real upstream authority plugin, publishing a SPIRE server's JWT key to the
// served API, gets back the tenant's SPIRE keys and trstctl's own SPIFFE JWT
// authority, the key trstctl signs JWT-SVIDs with, so a JWT signed by it
// verifies with what the plugin hands SPIRE; a rotation's next key, published
// ahead of signing, joins the set on the open subscription.
func TestServedSPIREUpstreamKeysCarryTrstctlsJWTAuthorityA205L2(t *testing.T) {
	ctx := context.Background()
	tenant := uuid.NewSHA1(uuid.NameSpaceOID, []byte("a205l2-spire-tenant")).String()
	protocols := config.Protocols{SPIFFE: config.SPIFFEProtocol{
		Enabled: true, TenantID: tenant, TrustDomain: "a205l2.test", SocketPath: filepath.Join(t.TempDir(), "cp.sock"),
	}}
	h := newOperatingServedHarness(t, protocols)
	registerServedTenantID(t, h, tenant, "A205-L2 SPIRE tenant")
	sp := h.srv.spiffeForExchange()
	if sp == nil || sp.jwtKeys == nil {
		t.Fatal("the SPIFFE protocol has no workload JWT key")
	}
	_, published, err := sp.jwtKeys.keys(ctx)
	if err != nil || len(published) != 1 {
		t.Fatalf("trstctl's published JWT keys = %d, %v", len(published), err)
	}
	trstctlKey := published[0]

	pluginToken := seedScopedToken(t, h.store, tenant, "issuers:read", "issuers:write")
	tokenFile := filepath.Join(t.TempDir(), "plugin-token")
	if err := os.WriteFile(tokenFile, []byte(pluginToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	plugin := spireupstream.New()
	if _, err := plugin.Configure(ctx, &configv1.ConfigureRequest{HclConfiguration: `
endpoint = "` + h.ts.URL + `"
ca_authority_id = "` + uuid.NewString() + `"
token_file = "` + tokenFile + `"
jwt_key_refresh_seconds = 1
`}); err != nil {
		t.Fatalf("configure the plugin: %v", err)
	}

	spireKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(spireKey.Destroy)
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream := &a205L2Stream{ctx: streamCtx, got: make(chan struct{}, 8)}
	done := make(chan error, 1)
	go func() {
		done <- plugin.PublishJWTKeyAndSubscribe(&upstreamauthorityv1.PublishJWTKeyRequest{JwtKey: &typesv1.JWTKey{
			KeyId: "spire-server-a", PublicKey: spireKey.Public().DER, ExpiresAt: time.Now().Add(time.Hour).Unix(),
		}}, stream)
	}()
	latest := func(what string) []*typesv1.JWTKey {
		t.Helper()
		select {
		case <-stream.got:
		case err := <-done:
			t.Fatalf("the subscription ended %s: %v", what, err)
		case <-time.After(15 * time.Second):
			t.Fatalf("no keys %s", what)
		}
		stream.mu.Lock()
		defer stream.mu.Unlock()
		return stream.sent[len(stream.sent)-1].GetUpstreamJwtKeys()
	}
	byID := func(keys []*typesv1.JWTKey) map[string]*typesv1.JWTKey {
		out := map[string]*typesv1.JWTKey{}
		for _, key := range keys {
			out[key.GetKeyId()] = key
		}
		return out
	}

	first := byID(latest("after publishing"))
	if first["spire-server-a"] == nil || !bytes.Equal(first["spire-server-a"].GetPublicKey(), spireKey.Public().DER) {
		t.Fatalf("the SPIRE server's own key is missing: %v", first)
	}
	relayed := first[trstctlKey.KeyID]
	if relayed == nil || !bytes.Equal(relayed.GetPublicKey(), trstctlKey.Signer.Public().DER) {
		t.Fatalf("trstctl's SPIFFE JWT authority %s is not in the set SPIRE receives: %v", trstctlKey.KeyID, first)
	}
	// A JWT trstctl signs verifies with the key the plugin handed SPIRE.
	token, err := crypto.SignJWT(trstctlKey.Signer, trstctlKey.KeyID, map[string]any{
		"sub": "spiffe://a205l2.test/workload", "aud": []string{"spire"}, "exp": time.Now().Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := crypto.PublicJWK(crypto.PublicKey{Algorithm: trstctlKey.Signer.Public().Algorithm, DER: relayed.GetPublicKey()}, relayed.GetKeyId())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.VerifyJWT(token, crypto.JWKS{Keys: []crypto.JWK{jwk}}); err != nil {
		t.Fatalf("a JWT signed by trstctl's JWT authority does not verify with the relayed key: %v", err)
	}

	// The listing names trstctl's key as its own authority.
	status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/spiffe/upstream-jwt-keys", pluginToken, nil)
	var listed struct {
		Items []struct {
			KeyID       string     `json:"key_id"`
			PublishedBy string     `json:"published_by"`
			PublishedAt *time.Time `json:"published_at"`
		} `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal(raw, &listed) != nil {
		t.Fatalf("list: HTTP %d %s", status, raw)
	}
	found := false
	for _, item := range listed.Items {
		if item.KeyID == trstctlKey.KeyID {
			found = item.PublishedBy == "trstctl-spiffe-jwt-authority" && item.PublishedAt == nil
		}
	}
	if !found {
		t.Fatalf("trstctl's key is not listed as trstctl-spiffe-jwt-authority: %s", raw)
	}

	// A rotation publishes the next key ahead of signing; the open
	// subscription hands it to SPIRE.
	rotator := seedScopedToken(t, h.store, tenant, "issuers:write")
	if status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/workloads/jwt-keys/rotate", rotator, "a205l2-rotate",
		map[string]any{"publish_ahead_seconds": 3600}); status != http.StatusOK {
		t.Fatalf("rotate: HTTP %d %s", status, raw)
	}
	sp.jwtKeys.invalidate()
	_, published, err = sp.jwtKeys.keys(ctx)
	if err != nil || len(published) != 2 {
		t.Fatalf("published keys after the rotation = %d, %v", len(published), err)
	}
	next := published[1]
	deadline := time.Now().Add(15 * time.Second)
	for {
		if keys := byID(latest("after the rotation")); keys[next.KeyID] != nil && bytes.Equal(keys[next.KeyID].GetPublicKey(), next.Signer.Public().DER) && keys[trstctlKey.KeyID] != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the next key %s never reached the subscription", next.KeyID)
		}
	}
	cancel()
	t.Logf("A205L2_TRSTCTL_JWT_AUTHORITY_OK keys=%s,%s", trstctlKey.KeyID, next.KeyID)
}
