// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/weakkey/weakkeytest"
)

// reportingSigner reports one public key and signs with another key.
type reportingSigner struct {
	crypto.DigestSigner
	public crypto.PublicKey
}

func (s reportingSigner) Public() crypto.PublicKey { return s.public }

func weakStartupSigner(t *testing.T) *crypto.LockedSigner {
	t.Helper()
	der, err := weakkeytest.SmallScalarPKCS8("P-384", 4)
	if err != nil {
		t.Fatal(err)
	}
	key, err := crypto.NewLockedSignerFromPKCS8(crypto.ECDSAP384, der)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	return key
}

// Owner decision (batch 11): a startup key binding takes the weak-key check,
// and a possession proof where the private key is in the signer; a failure
// names the binding and the check.
func TestStartupKeyBindingRefusesWeakKeysAndUnprovenSigners(t *testing.T) {
	weak := weakStartupSigner(t)
	for binding, holder := range map[string]crypto.DigestSigner{`agent CA (signer handle "agent-ca")`: weak, "breakglass.offline_kit_file": nil} {
		err := checkStartupKeyBinding(binding, weak.Public(), holder)
		if err == nil || !strings.Contains(err.Error(), "startup binding "+binding+": weak-key check failed") {
			t.Fatalf("weak %s = %v", binding, err)
		}
	}
	good, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(good.Destroy)
	other, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(other.Destroy)
	if err := checkStartupKeyBinding(`agent CA (signer handle "agent-ca")`, good.Public(), good); err != nil {
		t.Fatalf("a held, strong key = %v", err)
	}
	if err := checkStartupKeyBinding("breakglass.public_key_file", good.Public(), nil); err != nil {
		t.Fatalf("strong public material = %v", err)
	}
	liar := reportingSigner{DigestSigner: other, public: good.Public()}
	if err := checkStartupKeyBinding(`breakglass.signer_handle "bg-ca"`, good.Public(), liar); err == nil ||
		!strings.Contains(err.Error(), `startup binding breakglass.signer_handle "bg-ca": possession proof failed`) {
		t.Fatalf("a signer that does not hold the bound key = %v", err)
	}
}

// The configured break-glass verifier material is checked as it loads, so a
// weak recovery CA stops startup before any bundle is trusted.
func TestBreakglassVerifierMaterialRefusesAWeakKey(t *testing.T) {
	weak := weakStartupSigner(t)
	caDER, err := crypto.SelfSignedCACert(weak, "Weak Break-glass CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caPath, publicPath := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "public.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicPath, crypto.MarshalPublicKeyPEM(weak.Public().DER), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err = breakglassVerifierMaterialFromConfig(config.Breakglass{Enabled: true, CACertFile: caPath, PublicKeyFile: publicPath})
	if err == nil || !strings.Contains(err.Error(), "startup binding breakglass.public_key_file: weak-key check failed") {
		t.Fatalf("weak break-glass material = %v", err)
	}
}
