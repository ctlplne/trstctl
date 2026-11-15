// SPDX-License-Identifier: BUSL-1.1

package cbom

import (
	"testing"
	"time"
)

// TestKeyExchangeGroupsAreRatedAndExportedX2L7: a TLS key-exchange group (a
// product default's group, X2-L7) is rated as a key exchange, not as an
// unrecognized key: an ML-KEM group is strong and resists a quantum computer,
// a classical group is acceptable and quantum vulnerable. The CycloneDX
// export describes it as a key agreement (or a KEM), never as a signature
// key, and carries a product default's config source and version.
func TestKeyExchangeGroupsAreRatedAndExportedX2L7(t *testing.T) {
	for name, want := range map[string]struct {
		strength   Strength
		vulnerable bool
		primitive  string
		level      int
	}{
		"X25519MLKEM768":     {StrengthStrong, false, "kem", 3},
		"SecP384r1MLKEM1024": {StrengthStrong, false, "kem", 5},
		"X25519":             {StrengthAcceptable, true, "key-agree", 0},
		"secp256r1":          {StrengthAcceptable, true, "key-agree", 0},
		"ffdhe2048":          {StrengthAcceptable, true, "key-agree", 0},
	} {
		c := Classify(Finding{Kind: AssetHostConfig, Location: "/etc/ssl/openssl.cnf", Algorithm: name}, DefaultPolicy())
		if c.Strength != want.strength || c.QuantumVulnerable != want.vulnerable || len(c.Reasons) != 1 {
			t.Errorf("%s classified %+v", name, c)
		}
		bom := CycloneDX([]CycloneDXAsset{{ID: "a-" + name, Kind: string(AssetHostConfig), Location: "/etc/ssl/openssl.cnf",
			Algorithm: name, Library: "openssl-config", Strength: string(c.Strength), QuantumVulnerable: c.QuantumVulnerable,
			ConfigSource: ConfigSourceDefault, ProductVersion: "libssl3 3.5.9-r0"}},
			CycloneDXMeta{SerialUUID: "3f2f1c1e-7c1a-5b7e-9a1d-3e2c1b0a9f8e", GeneratedAt: time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC), ToolVersion: "test"})
		comp := bom.Components[0]
		p := comp.CryptoProperties.AlgorithmProperties
		if comp.Name != name || comp.CryptoProperties.AssetType != "algorithm" || p == nil || p.Primitive != want.primitive ||
			p.NISTQuantumSecurityLevel == nil || *p.NISTQuantumSecurityLevel != want.level {
			t.Errorf("%s exported as %+v / %+v", name, comp, p)
			continue
		}
		props := map[string]string{}
		for _, prop := range comp.Properties {
			props[prop.Name] = prop.Value
		}
		if props["trstctl:config_source"] != "default" || props["trstctl:product_version"] != "libssl3 3.5.9-r0" {
			t.Errorf("%s export properties %v", name, props)
		}
	}
	// A stated fact carries neither property, and a key is still a key.
	bom := CycloneDX([]CycloneDXAsset{{ID: "k", Kind: string(AssetCertKey), Location: "app:443", Algorithm: "ECDSA", KeyBits: 256}},
		CycloneDXMeta{SerialUUID: "3f2f1c1e-7c1a-5b7e-9a1d-3e2c1b0a9f8e", GeneratedAt: time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC), ToolVersion: "test"})
	for _, prop := range bom.Components[0].Properties {
		if prop.Name == "trstctl:config_source" || prop.Name == "trstctl:product_version" {
			t.Fatalf("a stated fact exported %s", prop.Name)
		}
	}
	if bom.Components[0].CryptoProperties.AlgorithmProperties.Primitive != "signature" || IsKeyExchangeGroup("ECDSA") {
		t.Fatal("a certificate key stopped reading as a signature key")
	}
}
