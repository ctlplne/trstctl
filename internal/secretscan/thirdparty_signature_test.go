// SPDX-License-Identifier: BUSL-1.1

package secretscan

import (
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	boundarycrypto "trstctl.com/trstctl/internal/crypto"
)

func signedArtifact(t *testing.T) (string, string, string) {
	t.Helper()
	dir := t.TempDir()
	artifact := filepath.Join(dir, "job.log")
	if err := os.WriteFile(artifact, []byte("step 1 ok\nstep 2 ok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	signer, err := boundarycrypto.GenerateLockedKey(boundarycrypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	sig, err := boundarycrypto.SignMessage(signer, []byte("step 1 ok\nstep 2 ok\n"))
	if err != nil {
		t.Fatal(err)
	}
	sigPath := filepath.Join(dir, "job.log.sig")
	if err := os.WriteFile(sigPath, []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: signer.Public().DER}))
	return artifact, sigPath, keyPEM
}

func TestVerifyThirdPartyArtifactSignatureAcceptsBase64AndRaw(t *testing.T) {
	artifact, sigPath, keyPEM := signedArtifact(t)
	cfg := ThirdPartyScanConfig{SignaturePath: sigPath, SignerPublicKeyPEM: keyPEM, RequireSignature: true}
	ev, err := VerifyThirdPartyArtifactSignature(cfg, artifact)
	if err != nil || !ev.Verified || len(ev.SignerKeySHA256) != 64 {
		t.Fatalf("base64 signature: ev=%+v err=%v", ev, err)
	}
	raw, _ := os.ReadFile(sigPath) // #nosec G304 -- test-owned temp path
	decoded, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err := os.WriteFile(sigPath, decoded, 0o600); err != nil { // #nosec G703 -- test-owned temp path
		t.Fatal(err)
	}
	if ev2, err := VerifyThirdPartyArtifactSignature(cfg, artifact); err != nil || !ev2.Verified || ev2.SignerKeySHA256 != ev.SignerKeySHA256 {
		t.Fatalf("raw signature: ev=%+v err=%v", ev2, err)
	}
}

func TestVerifyThirdPartyArtifactSignatureRefusals(t *testing.T) {
	artifact, sigPath, keyPEM := signedArtifact(t)
	t.Run("tampered artifact", func(t *testing.T) {
		if err := os.WriteFile(artifact, []byte("step 1 ok\nstep 2 FAILED\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := VerifyThirdPartyArtifactSignature(ThirdPartyScanConfig{SignaturePath: sigPath, SignerPublicKeyPEM: keyPEM}, artifact)
		if err == nil || !strings.Contains(err.Error(), "signature verification failed") {
			t.Fatalf("tampered artifact must refuse: %v", err)
		}
	})
	t.Run("required but absent", func(t *testing.T) {
		_, err := VerifyThirdPartyArtifactSignature(ThirdPartyScanConfig{RequireSignature: true}, artifact)
		if err == nil || !strings.Contains(err.Error(), "requires a provider signature") {
			t.Fatalf("required signature must refuse: %v", err)
		}
	})
	t.Run("optional and absent records nothing", func(t *testing.T) {
		ev, err := VerifyThirdPartyArtifactSignature(ThirdPartyScanConfig{}, artifact)
		if err != nil || ev.Verified || ev.SignerKeySHA256 != "" {
			t.Fatalf("unsigned optional artifact: ev=%+v err=%v", ev, err)
		}
	})
	t.Run("directory export cannot be signed", func(t *testing.T) {
		_, err := VerifyThirdPartyArtifactSignature(ThirdPartyScanConfig{SignaturePath: sigPath, SignerPublicKeyPEM: keyPEM}, filepath.Dir(artifact))
		if err == nil || !strings.Contains(err.Error(), "single regular artifact file") {
			t.Fatalf("directory must refuse: %v", err)
		}
	})
	t.Run("wrong key type", func(t *testing.T) {
		_, err := VerifyThirdPartyArtifactSignature(ThirdPartyScanConfig{SignaturePath: sigPath, SignerPublicKeyPEM: "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n"}, artifact)
		if err == nil || !strings.Contains(err.Error(), "PEM PUBLIC KEY") {
			t.Fatalf("non-key PEM must refuse: %v", err)
		}
	})
}
