// SPDX-License-Identifier: BUSL-1.1

package signerwiring

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/succession/minter"
)

// The key is generated through internal/crypto rather than crypto/ed25519
// directly: AN-3 admits no exception for tests, and a test that reaches around
// the boundary is exactly how a second crypto path gets established.
func writeAuthorityPEM(t *testing.T, dir string) []byte {
	t.Helper()
	_, pubPEM, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, BreakGlassAuthorityFile), pubPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	der, err := crypto.ParseEd25519PublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestCR332LoadedApprovalAuthorityVerifiesAndPersistsOneUse(t *testing.T) {
	if key, err := LoadDualControlAuthority(t.TempDir()); key != nil || err != nil {
		t.Fatalf("absent approval authority: key=%v err=%v, want fail-closed nil key", key, err)
	}
	bad := t.TempDir()
	if err := os.WriteFile(filepath.Join(bad, DualControlAuthorityFile), []byte("not a public key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDualControlAuthority(bad); err == nil {
		t.Fatal("malformed approval authority did not fail signer startup")
	}
	dir := t.TempDir()
	privatePEM, publicPEM, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, DualControlAuthorityFile), publicPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	publicDER, err := LoadDualControlAuthority(dir)
	if err != nil {
		t.Fatal(err)
	}
	req := signing.MintRequest{
		IdentityID: "spiffe://d/cr332", TenantID: "tenant-a", DeploymentScope: "deployment-1",
		AssertedPredecessorEpoch: 0, TargetAlgorithm: crypto.ECDSAP384, PolicyRef: "policy:approved",
	}
	digest := minter.RequestParamsDigest(req)
	payload, err := json.Marshal(minter.AuthorizationToken{
		IdentityID: req.IdentityID, TenantID: req.TenantID,
		PredecessorCustody:       "signer",
		AssertedPredecessorEpoch: req.AssertedPredecessorEpoch, TargetAlgorithm: req.TargetAlgorithm,
		ParamsDigest: digest, Nonce: "cr332-one-use",
	})
	if err != nil {
		t.Fatal(err)
	}
	signature, err := crypto.SignEd25519(privatePEM, payload)
	if err != nil {
		t.Fatal(err)
	}
	token, err := json.Marshal(struct {
		Payload json.RawMessage `json:"payload"`
		Sig     []byte          `json:"sig"`
	}{payload, signature})
	if err != nil {
		t.Fatal(err)
	}
	first, err := minter.NewDurableSignedTokenAuthorizer(publicDER, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.VerifyAndConsume(token, req, digest); err != nil {
		t.Fatalf("signer rejected a valid operator approval: %v", err)
	}
	restarted, err := minter.NewDurableSignedTokenAuthorizer(publicDER, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.VerifyAndConsume(token, req, digest); err == nil {
		t.Fatal("signer accepted approval replay after restart")
	}
}

// TestLoadBreakGlassAuthority covers the three states an operator can leave
// the custody dir in: unconfigured (downgrades stay refused), configured with
// a real key, and half-configured (must fail loudly rather than look
// configured while behaving as if it were not).
func TestLoadBreakGlassAuthority(t *testing.T) {
	if der, err := LoadBreakGlassAuthority(""); der != nil || err != nil {
		t.Fatalf("no custody dir: der=%v err=%v, want nil/nil", der, err)
	}

	dir := t.TempDir()
	if der, err := LoadBreakGlassAuthority(dir); der != nil || err != nil {
		t.Fatalf("absent file: der=%v err=%v, want nil/nil (unconfigured is the ordinary case)", der, err)
	}

	want := writeAuthorityPEM(t, dir)
	got, err := LoadBreakGlassAuthority(dir)
	if err != nil {
		t.Fatalf("configured authority: %v", err)
	}
	if string(got) != string(want) {
		t.Fatal("loaded authority key does not match the provisioned key")
	}

	bad := t.TempDir()
	if err := os.WriteFile(filepath.Join(bad, BreakGlassAuthorityFile), []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBreakGlassAuthority(bad); err == nil || !strings.Contains(err.Error(), "break-glass") {
		t.Fatalf("half-configured authority err=%v, want a loud break-glass parse failure", err)
	}
}

// TestProductionMinterBuildsWithAndWithoutBreakGlass proves the wiring is
// opt-in: the minter constructs either way, so an unconfigured deployment
// keeps its fail-closed downgrade refusal instead of failing to start.
func TestProductionMinterBuildsWithAndWithoutBreakGlass(t *testing.T) {
	dir := t.TempDir()
	raw, err := seal.GenerateKEK()
	if err != nil {
		t.Fatal(err)
	}
	wrapper, err := seal.NewLocalKEK(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer wrapper.Destroy()
	if _, err := NewProductionMinter(Config{SignerID: "s", FloorDir: dir, JournalWrapper: wrapper}); err != nil {
		t.Fatalf("unconfigured break-glass must still build a minter: %v", err)
	}
	der := writeAuthorityPEM(t, dir)
	if _, err := NewProductionMinter(Config{SignerID: "s", FloorDir: dir, JournalWrapper: wrapper, BreakGlassAuthorityPubDER: der}); err != nil {
		t.Fatalf("configured break-glass must build a minter: %v", err)
	}
}
