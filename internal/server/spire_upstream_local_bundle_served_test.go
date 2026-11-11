// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	upstreamauthorityv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/upstreamauthority/v1"
	typesv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/spireupstream"
	"trstctl.com/trstctl/internal/store"
)

// TestServedSPIRELocalBundleA205L3 is A205-L3 against the served API: SPIRE
// Server, through the plugin SDK's own client, subscribes to its local bundle
// and receives the root the configured intermediate chains to, read from
// trstctl's CA authority listing, and the JWT key set carrying trstctl's own
// SPIFFE JWT authority; when a SPIRE server publishes its JWT key, the open
// stream sends the bundle again with it.
func TestServedSPIRELocalBundleA205L3(t *testing.T) {
	ctx := context.Background()
	tenant := uuid.NewSHA1(uuid.NameSpaceOID, []byte("a205l3-spire-tenant")).String()
	protocols := config.Protocols{SPIFFE: config.SPIFFEProtocol{
		Enabled: true, TenantID: tenant, TrustDomain: "a205l3.test", SocketPath: filepath.Join(t.TempDir(), "cp.sock"),
	}}
	h := newOperatingServedHarness(t, protocols)
	registerServedTenantID(t, h, tenant, "A205-L3 SPIRE tenant")
	sp := h.srv.spiffeForExchange()
	if sp == nil || sp.jwtKeys == nil {
		t.Fatal("the SPIFFE protocol has no workload JWT key")
	}
	_, published, err := sp.jwtKeys.keys(ctx)
	if err != nil || len(published) != 1 {
		t.Fatalf("trstctl's published JWT keys = %d, %v", len(published), err)
	}
	trstctlKey := published[0]

	// The chain as trstctl serves it: a root, and the intermediate SPIRE's
	// X.509 CA is signed under. The plugin relays the root's DER unparsed.
	rootDER := []byte{0x30, 0x03, 0x02, 0x01, 0x05}
	certificatePEM := func(der []byte) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	notAfter := time.Now().Add(365 * 24 * time.Hour)
	root, err := h.store.InsertCAAuthority(ctx, store.CAAuthority{
		TenantID: tenant, CommonName: "a205l3 root", Kind: "root", Status: "active",
		CertificatePEM: certificatePEM(rootDER), Serial: "a205l3-root", NotAfter: &notAfter,
	})
	if err != nil {
		t.Fatalf("seed the root: %v", err)
	}
	intermediate, err := h.store.InsertCAAuthority(ctx, store.CAAuthority{
		TenantID: tenant, ParentID: &root.ID, CommonName: "a205l3 SPIRE intermediate", Kind: "intermediate", Status: "active",
		CertificatePEM: certificatePEM([]byte{0x30, 0x03, 0x02, 0x01, 0x06}), Serial: "a205l3-intermediate", NotAfter: &notAfter,
	})
	if err != nil {
		t.Fatalf("seed the intermediate: %v", err)
	}

	pluginToken := seedScopedToken(t, h.store, tenant, "issuers:read", "issuers:write")
	tokenFile := filepath.Join(t.TempDir(), "plugin-token")
	if err := os.WriteFile(tokenFile, []byte(pluginToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	plugin := spireupstream.New()
	if _, err := plugin.Configure(ctx, &configv1.ConfigureRequest{HclConfiguration: `
endpoint = "` + h.ts.URL + `"
ca_authority_id = "` + intermediate.ID + `"
token_file = "` + tokenFile + `"
jwt_key_refresh_seconds = 1
`}); err != nil {
		t.Fatalf("configure the plugin: %v", err)
	}

	// SPIRE Server holds the plugin through the SDK's generated client.
	listener := bufconn.Listen(1 << 20)
	grpcServer := grpc.NewServer()
	upstreamauthorityv1.RegisterUpstreamAuthorityServer(grpcServer, plugin)
	go func() { _ = grpcServer.Serve(listener) }()
	t.Cleanup(grpcServer.Stop)
	conn, err := grpc.NewClient("passthrough:///spire-plugin",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return listener.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := upstreamauthorityv1.NewUpstreamAuthorityClient(conn)

	streamCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	bundle, err := client.SubscribeToLocalBundle(streamCtx, &upstreamauthorityv1.SubscribeToLocalBundleRequest{})
	if err != nil {
		t.Fatal(err)
	}
	keyed := func(keys []*typesv1.JWTKey, id string, der []byte) bool {
		for _, key := range keys {
			if key.GetKeyId() == id && bytes.Equal(key.GetPublicKey(), der) {
				return true
			}
		}
		return false
	}
	first, err := bundle.Recv()
	if err != nil {
		t.Fatalf("first bundle: %v", err)
	}
	if roots := first.GetUpstreamX509Roots(); len(roots) != 1 || !bytes.Equal(roots[0].GetAsn1(), rootDER) {
		t.Fatalf("first bundle roots = %v, want the root the intermediate chains to", roots)
	}
	if !keyed(first.GetUpstreamJwtKeys(), trstctlKey.KeyID, trstctlKey.Signer.Public().DER) {
		t.Fatalf("first bundle JWT keys = %v, want trstctl's SPIFFE JWT authority %s", first.GetUpstreamJwtKeys(), trstctlKey.KeyID)
	}

	// Another SPIRE server publishes its JWT key; the open bundle stream sends
	// the bundle again with it.
	spireKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(spireKey.Destroy)
	publication, err := client.PublishJWTKeyAndSubscribe(streamCtx, &upstreamauthorityv1.PublishJWTKeyRequest{JwtKey: &typesv1.JWTKey{
		KeyId: "spire-server-b", PublicKey: spireKey.Public().DER, ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publication.Recv(); err != nil {
		t.Fatalf("publish the SPIRE server's key: %v", err)
	}
	for {
		next, err := bundle.Recv()
		if err != nil {
			t.Fatalf("the published key never reached the bundle stream: %v", err)
		}
		keys := next.GetUpstreamJwtKeys()
		if keyed(keys, "spire-server-b", spireKey.Public().DER) {
			if roots := next.GetUpstreamX509Roots(); len(roots) != 1 || !bytes.Equal(roots[0].GetAsn1(), rootDER) || !keyed(keys, trstctlKey.KeyID, trstctlKey.Signer.Public().DER) {
				t.Fatalf("bundle after the publication = roots %v keys %v", roots, keys)
			}
			break
		}
	}
	cancel()
	t.Logf("A205L3_LOCAL_BUNDLE_OK root=%x keys=%s,spire-server-b", rootDER, trstctlKey.KeyID)
}
