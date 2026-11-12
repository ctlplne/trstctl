// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	upstreamauthorityv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/upstreamauthority/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/spireupstream"
)

type servedStandingApproval struct {
	ID           string     `json:"id"`
	Principal    string     `json:"principal"`
	TrustDomain  string     `json:"trust_domain"`
	Status       string     `json:"status"`
	Signings     int64      `json:"signings"`
	LastSignedAt *time.Time `json:"last_signed_at"`
	RevokedBy    string     `json:"revoked_by"`
	CeremonyID   string     `json:"ceremony_id"`
}

// OD-8 (A205-L1): a SPIRE server holds a standing approval for its upstream
// CA requests. Two custodians approve a grant_upstream_standing_approval
// ceremony naming the authority, the plugin's token subject, the trust domain
// and the CA spec with its longest lifetime; a grant that differs from the
// ceremony is refused, and one custodian is not enough. Granted, the real
// upstream authority plugin, as SPIRE Server holds it, has SPIRE's CA CSR
// signed with no ceremony of its own: the CA names the trust domain and
// chains to the authority, and the approval counts the signing, which the
// audit trail records. A CSR naming another trust domain, a lifetime past the
// approved one and another principal are refused. Revoked, the next CSR
// needs a ceremony again.
func TestServedSPIREStandingApprovalSignsUpstreamCAsOD8(t *testing.T) {
	ctx := context.Background()
	h := newOperatingServedHarness(t, config.Protocols{})
	scopes := []string{"issuers:write", "issuers:read"}
	operator := seedServedAPIToken(t, ctx, h.store, h.tenant, "od8-operator", scopes)
	custodianA := seedServedAPIToken(t, ctx, h.store, h.tenant, "od8-custodian-a", scopes)
	custodianB := seedServedAPIToken(t, ctx, h.store, h.tenant, "od8-custodian-b", scopes)
	spireToken := seedServedAPIToken(t, ctx, h.store, h.tenant, "spire-server-a", scopes)
	otherSpire := seedServedAPIToken(t, ctx, h.store, h.tenant, "spire-server-b", scopes)
	rootSpec := map[string]any{"common_name": "od8 root", "max_path_len": 1, "ttl_seconds": int64((365 * 24 * time.Hour).Seconds()),
		"signature_algorithm": "ecdsa-p256"}
	rootCeremony := createCACeremony(t, h, operator, "create_root", "", rootSpec, 1, "od8-root-ceremony")
	approveCACeremony(t, h, custodianA, rootCeremony.ID, 1, "od8-root-approval")
	root := createRootCA(t, h, operator, rootCeremony.ID, rootSpec, "od8-root-create")

	caSpec := map[string]any{"common_name": "SPIRE Server CA", "max_path_len": 0, "ttl_seconds": 3600, "signature_algorithm": "ecdsa-p256"}
	grant := map[string]any{"principal": "spire-server-a", "trust_domain": "od8.test", "valid_for_seconds": 86400, "spec": caSpec}
	ceremonyBody := func(threshold int) map[string]any {
		body := map[string]any{"operation": "grant_upstream_standing_approval", "authority_id": root.ID, "threshold": threshold}
		for k, v := range grant {
			body[k] = v
		}
		return body
	}
	// One custodian is not enough for a standing approval.
	if code, raw := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/ceremonies", operator, "od8-grant-ceremony-1", ceremonyBody(1)); code != http.StatusUnprocessableEntity ||
		!strings.Contains(string(raw), "two distinct custodians") {
		t.Fatalf("a one-custodian standing approval ceremony = %d %s", code, raw)
	}
	// The console reviews the exact grant ceremony before it opens it.
	if code, raw := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/ceremonies/preview", operator, "", ceremonyBody(2)); code != http.StatusOK ||
		!strings.Contains(string(raw), `"ready":true`) || !strings.Contains(string(raw), `"request_fingerprint":"`) {
		t.Fatalf("preview the grant ceremony = %d %s", code, raw)
	}
	code, raw := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/ceremonies", operator, "od8-grant-ceremony", ceremonyBody(2))
	var ceremony servedCACeremony
	if code != http.StatusCreated || json.Unmarshal(raw, &ceremony) != nil || ceremony.ID == "" {
		t.Fatalf("open the grant ceremony = %d %s", code, raw)
	}
	approveCACeremony(t, h, custodianA, ceremony.ID, 1, "od8-grant-approval-a")
	approveCACeremony(t, h, custodianB, ceremony.ID, 2, "od8-grant-approval-b")

	grantPath := "/api/v1/ca/authorities/" + root.ID + "/upstream-standing-approvals"
	withCeremony := func(overrides map[string]any) map[string]any {
		body := map[string]any{"ceremony_id": ceremony.ID}
		for k, v := range grant {
			body[k] = v
		}
		for k, v := range overrides {
			body[k] = v
		}
		return body
	}
	// A grant that is not the approved one is refused and consumes nothing.
	if code, raw := doBearer(t, h.ts, http.MethodPost, grantPath, operator, "od8-grant-other-domain", withCeremony(map[string]any{"trust_domain": "other.test"})); code < 400 {
		t.Fatalf("a grant for another trust domain = %d %s", code, raw)
	}
	code, raw = doBearer(t, h.ts, http.MethodPost, grantPath, operator, "od8-grant", withCeremony(nil))
	var approval servedStandingApproval
	if code != http.StatusCreated || json.Unmarshal(raw, &approval) != nil || approval.Status != "active" || approval.Signings != 0 ||
		approval.Principal != "spire-server-a" || approval.TrustDomain != "od8.test" || approval.CeremonyID != ceremony.ID {
		t.Fatalf("grant = %d %s", code, raw)
	}

	// The real plugin, as SPIRE Server holds it.
	tokenFile := filepath.Join(t.TempDir(), "plugin-token")
	if err := os.WriteFile(tokenFile, []byte(spireToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	plugin := spireupstream.New()
	if _, err := plugin.Configure(ctx, &configv1.ConfigureRequest{HclConfiguration: `
endpoint = "` + h.ts.URL + `"
ca_authority_id = "` + root.ID + `"
token_file = "` + tokenFile + `"
common_name = "SPIRE Server CA"
max_path_len = 0
ttl_seconds = 3600
`}); err != nil {
		t.Fatalf("configure the plugin: %v", err)
	}
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
	var lastKey *crypto.LockedSigner
	csr := func(uri string) []byte {
		t.Helper()
		key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(key.Destroy)
		der, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "SPIRE Server CA", URIs: []string{uri}}, key)
		if err != nil {
			t.Fatal(err)
		}
		lastKey = key
		return der
	}
	mint := func(der []byte, ttl int32) (*upstreamauthorityv1.MintX509CAResponse, error) {
		t.Helper()
		streamCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		stream, err := client.MintX509CAAndSubscribe(streamCtx, &upstreamauthorityv1.MintX509CARequest{Csr: der, PreferredTtl: ttl})
		if err != nil {
			return nil, err
		}
		return stream.Recv()
	}
	resp, err := mint(csr("spiffe://od8.test"), 3600)
	if err != nil {
		t.Fatalf("SPIRE's CA under the standing approval: %v", err)
	}
	if len(resp.GetX509CaChain()) != 1 || len(resp.GetUpstreamX509Roots()) != 1 {
		t.Fatalf("mint response = %d chain, %d roots", len(resp.GetX509CaChain()), len(resp.GetUpstreamX509Roots()))
	}
	spireCA, spireKey := resp.GetX509CaChain()[0].GetAsn1(), lastKey
	info, err := certinfo.Inspect(spireCA)
	if err != nil || !info.IsCA || info.Issuer != "CN=od8 root" {
		t.Fatalf("signed SPIRE CA = %+v %v", info, err)
	}
	rootBlock, _ := pem.Decode([]byte(root.CertificatePEM))
	if rootBlock == nil || string(resp.GetUpstreamX509Roots()[0].GetAsn1()) != string(rootBlock.Bytes) {
		t.Fatal("the upstream root is not the authority's certificate")
	}
	// The signed CA vouches for its trust domain only: an SVID SPIRE mints
	// under it chains to the authority for spiffe://od8.test and not for
	// another trust domain (the CA's URI name constraint).
	svid := func(id string) error {
		t.Helper()
		leafKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
		if err != nil {
			t.Fatal(err)
		}
		defer leafKey.Destroy()
		leafCSR, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{URIs: []string{id}}, leafKey)
		if err != nil {
			t.Fatal(err)
		}
		leafDER, err := crypto.SignLeafFromCSR(spireCA, spireKey, leafCSR, 30*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		keyPEM, err := leafKey.PrivateKeyPEM()
		if err != nil {
			t.Fatal(err)
		}
		keyBlock, _ := pem.Decode(keyPEM)
		_, err = crypto.VerifyX509SVID(append(append([]byte{}, leafDER...), spireCA...), rootBlock.Bytes, keyBlock.Bytes, time.Now())
		return err
	}
	if err := svid("spiffe://od8.test/workload"); err != nil {
		t.Fatalf("an SVID in the trust domain under the signed CA: %v", err)
	}
	if err := svid("spiffe://other.test/workload"); err == nil {
		t.Fatal("an SVID for another trust domain chains under the signed CA")
	}

	list := func() servedStandingApproval {
		t.Helper()
		code, raw := doBearer(t, h.ts, http.MethodGet, grantPath, operator, "", nil)
		var out struct {
			Items []servedStandingApproval `json:"items"`
		}
		if code != http.StatusOK || json.Unmarshal(raw, &out) != nil || len(out.Items) != 1 {
			t.Fatalf("list = %d %s", code, raw)
		}
		return out.Items[0]
	}
	if got := list(); got.Signings != 1 || got.LastSignedAt == nil || got.Status != "active" {
		t.Fatalf("after one signing the approval = %+v", got)
	}

	// Outside the approval: another trust domain, a longer lifetime, another
	// principal.
	direct := func(token, idem string, der []byte, ttl int) (int, string) {
		t.Helper()
		spec := map[string]any{"common_name": "SPIRE Server CA", "max_path_len": 0, "ttl_seconds": ttl, "signature_algorithm": "ecdsa-p256"}
		code, raw := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/"+root.ID+"/intermediates/csr", token, idem,
			map[string]any{"csr_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), "spec": spec})
		return code, string(raw)
	}
	for name, attempt := range map[string]struct {
		token, idem string
		der         []byte
		ttl         int
		want        string
	}{
		"another trust domain": {spireToken, "od8-other-td", csr("spiffe://other.test"), 3600, "must name exactly spiffe://od8.test"},
		"a longer lifetime":    {spireToken, "od8-long", csr("spiffe://od8.test"), 7200, "approved 3600 seconds"},
		"another SPIRE server": {otherSpire, "od8-other-server", csr("spiffe://od8.test"), 3600, "no active standing approval"},
	} {
		if code, body := direct(attempt.token, attempt.idem, attempt.der, attempt.ttl); code != http.StatusUnprocessableEntity || !strings.Contains(body, attempt.want) {
			t.Fatalf("%s = %d %s", name, code, body)
		}
	}
	if got := list(); got.Signings != 1 {
		t.Fatalf("refused requests were counted: %+v", got)
	}

	// The audit trail names the signing under the approval.
	auditor := seedScopedTokenSubject(t, h.store, h.tenant, "od8-auditor", "audit:read")
	status, rawAudit := secretsReq(t, h, http.MethodGet, "/api/v1/audit/events?type=ca.upstream_standing_approval.signed&limit=10", auditor, nil)
	if status != http.StatusOK || !strings.Contains(string(rawAudit), approval.ID) || !strings.Contains(string(rawAudit), info.SerialNumber) {
		t.Fatalf("audited signing = %d %s", status, rawAudit)
	}

	// Revoked at once: the next CSR needs a ceremony again.
	code, raw = doBearer(t, h.ts, http.MethodPost, grantPath+"/"+approval.ID+"/revoke", operator, "od8-revoke", map[string]any{"reason": "SPIRE server retired"})
	if code != http.StatusOK || json.Unmarshal(raw, &approval) != nil || approval.Status != "revoked" || approval.RevokedBy != "od8-operator" {
		t.Fatalf("revoke = %d %s", code, raw)
	}
	if _, err := mint(csr("spiffe://od8.test"), 3600); err == nil || !strings.Contains(err.Error(), "ceremony_id is required") {
		t.Fatalf("SPIRE's CA after the revocation = %v; want it to need a ceremony", err)
	}
	if got := list(); got.Signings != 1 || got.Status != "revoked" {
		t.Fatalf("after the revocation the approval = %+v", got)
	}
}
