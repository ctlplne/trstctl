// SPDX-License-Identifier: BUSL-1.1

package secretscan

import (
	"bytes"
	_ "embed"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	boundarycrypto "trstctl.com/trstctl/internal/crypto"
)

// Public, fixed verification fixtures; no private material is retained. The
// ECDSA signature genuinely ends in a space and the RSA signature begins in
// a newline. Those bytes are part of each signature, not text delimiters.
//
//go:embed testdata/signature-encoding/ecdsa-trailing-space.pub.pem
var ecdsaWhitespacePEM []byte

//go:embed testdata/signature-encoding/ecdsa-trailing-space.sig
var ecdsaWhitespaceSignature []byte

//go:embed testdata/signature-encoding/ecdsa-trailing-space.artifact
var ecdsaWhitespaceArtifact []byte

//go:embed testdata/signature-encoding/rsa-leading-newline.pub.pem
var rsaWhitespacePEM []byte

//go:embed testdata/signature-encoding/rsa-leading-newline.sig
var rsaWhitespaceSignature []byte

//go:embed testdata/signature-encoding/rsa-leading-newline.artifact
var rsaWhitespaceArtifact []byte

func TestArtifactSignaturePreservesBinaryWhitespace(t *testing.T) {
	fixtures := []struct {
		name                           string
		publicPEM, artifact, signature []byte
	}{
		{"ecdsa-trailing-space", ecdsaWhitespacePEM, ecdsaWhitespaceArtifact, ecdsaWhitespaceSignature},
		{"rsa-leading-newline", rsaWhitespacePEM, rsaWhitespaceArtifact, rsaWhitespaceSignature},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			block, _ := pem.Decode(fixture.publicPEM)
			if block == nil {
				t.Fatal("public verification fixture is not PEM")
			}
			if err := boundarycrypto.VerifyMessage(block.Bytes, fixture.artifact, fixture.signature); err != nil {
				t.Fatalf("fixture signature is invalid: %v", err)
			}
			if bytes.Equal(bytes.TrimSpace(fixture.signature), fixture.signature) {
				t.Fatal("fixture does not exercise binary boundary whitespace")
			}
			dir := t.TempDir()
			artifactPath := filepath.Join(dir, "artifact.log")
			signaturePath := filepath.Join(dir, "artifact.sig")
			if err := os.WriteFile(artifactPath, fixture.artifact, 0o600); err != nil {
				t.Fatal(err)
			}
			cfg := ThirdPartyScanConfig{SignaturePath: signaturePath, SignerPublicKeyPEM: string(fixture.publicPEM), RequireSignature: true}
			encodings := map[string][]byte{
				"raw":                         fixture.signature,
				"base64":                      []byte(base64.StdEncoding.EncodeToString(fixture.signature)),
				"base64-with-text-whitespace": []byte(" \t\r\n" + base64.StdEncoding.EncodeToString(fixture.signature) + "\r\n\t "),
			}
			for name, encoded := range encodings {
				t.Run(name, func(t *testing.T) {
					if err := os.WriteFile(signaturePath, encoded, 0o600); err != nil {
						t.Fatal(err)
					}
					evidence, err := VerifyThirdPartyArtifactSignature(cfg, artifactPath)
					if err != nil || !evidence.Verified || evidence.SignerKeySHA256 != boundarycrypto.SHA256Hex(block.Bytes) {
						t.Fatalf("valid %s signature refused: %v, evidence=%+v", name, err, evidence)
					}
				})
			}
			if err := os.WriteFile(signaturePath, fixture.signature, 0o600); err != nil {
				t.Fatal(err)
			}
			changed := bytes.Clone(fixture.artifact)
			changed[0] ^= 1
			if err := os.WriteFile(artifactPath, changed, 0o600); err != nil {
				t.Fatal(err)
			}
			if evidence, err := VerifyThirdPartyArtifactSignature(cfg, artifactPath); err == nil || evidence.Verified || evidence.SignerKeySHA256 != "" {
				t.Fatalf("changed artifact accepted: %v, evidence=%+v", err, evidence)
			}
			if err := os.WriteFile(artifactPath, fixture.artifact, 0o600); err != nil {
				t.Fatal(err)
			}
			truncated := bytes.TrimSpace(fixture.signature)
			if err := os.WriteFile(signaturePath, truncated, 0o600); err != nil {
				t.Fatal(err)
			}
			if evidence, err := VerifyThirdPartyArtifactSignature(cfg, artifactPath); err == nil || evidence.Verified {
				t.Fatalf("truncated signature accepted: %v, evidence=%+v", err, evidence)
			}
		})
	}
}

// The decoder handles untrusted signature files. A successful decode must still
// authenticate these exact artifact bytes, and parsing must not edit its input.
func FuzzArtifactSignatureEncoding(f *testing.F) {
	block, _ := pem.Decode(ecdsaWhitespacePEM)
	if block == nil {
		f.Fatal("public verification fixture is not PEM")
		return
	}
	f.Add(ecdsaWhitespaceSignature)
	f.Add([]byte(base64.StdEncoding.EncodeToString(ecdsaWhitespaceSignature)))
	f.Add([]byte(" \t\n" + base64.StdEncoding.EncodeToString(ecdsaWhitespaceSignature) + "\r\n "))
	f.Add([]byte{})
	f.Add([]byte{0xff, 0x00, 0x0a})
	f.Fuzz(func(t *testing.T, signature []byte) {
		if len(signature) > 8192 {
			return
		}
		before := bytes.Clone(signature)
		if err := verifyDetachedArtifactSignature(block.Bytes, ecdsaWhitespaceArtifact, signature); err == nil {
			changed := bytes.Clone(ecdsaWhitespaceArtifact)
			changed[0] ^= 1
			if verifyDetachedArtifactSignature(block.Bytes, changed, signature) == nil {
				t.Fatal("signature authenticated a changed artifact")
			}
		}
		if !bytes.Equal(signature, before) {
			t.Fatal("signature parser edited its input")
		}
	})
}
