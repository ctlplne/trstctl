// SPDX-License-Identifier: BUSL-1.1

package pfx

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
	"trstctl.com/trstctl/internal/crypto/secret"
)

func generatedAliasFixture(t testing.TB, password []byte) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := pkcs12.Modern2023.Encode(key, cert, nil, string(password))
	if err != nil {
		t.Fatal(err)
	}
	return blob
}

func TestAliasAdapterPreservesCiphertextsAndRefusesInvalidAuthentication(t *testing.T) {
	name, err := javaAliasAttribute("payments")
	if err != nil {
		t.Fatal(err)
	}
	for _, password := range [][]byte{nil, []byte("p"), []byte("é中\x00long-password"), bytes.Repeat([]byte("p"), 65)} {
		blob := generatedAliasFixture(t, password)
		defer secret.Wipe(blob)
		changed, err := nameGeneratedKeyEntry(blob, password, name)
		if err != nil {
			t.Fatal(err)
		}
		defer secret.Wipe(changed)
		if _, _, _, err := pkcs12.DecodeChain(changed, string(password)); err != nil {
			t.Fatal(err)
		}
		var oldPFX, newPFX aliasPFX
		if err := aliasUnmarshal(blob, &oldPFX); err != nil {
			t.Fatal(err)
		}
		if err := aliasUnmarshal(changed, &newPFX); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(oldPFX.MACData.Salt, newPFX.MACData.Salt) {
			t.Fatal("MAC salt changed")
		}
		extract := func(p aliasPFX) ([]aliasContentInfo, []aliasBag) {
			var raw []byte
			if err := aliasUnmarshal(p.AuthSafe.Content.Bytes, &raw); err != nil {
				t.Fatal(err)
			}
			var safes []aliasContentInfo
			if err := aliasUnmarshal(raw, &safes); err != nil {
				t.Fatal(err)
			}
			if err := aliasUnmarshal(safes[1].Content.Bytes, &raw); err != nil {
				t.Fatal(err)
			}
			var bags []aliasBag
			if err := aliasUnmarshal(raw, &bags); err != nil {
				t.Fatal(err)
			}
			return safes, bags
		}
		oldSafes, oldBags := extract(oldPFX)
		newSafes, newBags := extract(newPFX)
		foundName := false
		for _, attribute := range newBags[0].Attributes {
			if attribute.ID.Equal(aliasOIDFriendlyName) {
				var got string
				rest, err := asn1.Unmarshal(attribute.Value.Bytes, &got)
				if err != nil || len(rest) != 0 || got != "payments" {
					t.Fatal("standard BMP friendlyName did not survive authenticated encoding")
				}
				foundName = true
			}
		}
		if !foundName {
			t.Fatal("Java key alias missing")
		}
		if !bytes.Equal(oldSafes[0].Content.FullBytes, newSafes[0].Content.FullBytes) || !bytes.Equal(oldBags[0].Value.FullBytes, newBags[0].Value.FullBytes) {
			t.Fatal("alias changed encrypted certificates or encrypted private key")
		}
		for _, change := range []func(*aliasPFX){
			func(p *aliasPFX) { p.MACData.MAC.Digest[0] ^= 1 },
			func(p *aliasPFX) { p.MACData.Iterations = 1 },
			func(p *aliasPFX) { p.MACData.Iterations = 1 << 30 },
			func(p *aliasPFX) { p.MACData.Salt = nil },
			func(p *aliasPFX) { p.MACData.MAC.Algorithm.Algorithm = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26} },
		} {
			var bad aliasPFX
			if err := aliasUnmarshal(bytes.Clone(blob), &bad); err != nil {
				t.Fatal(err)
			}
			change(&bad)
			raw, err := asn1.Marshal(bad)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := nameGeneratedKeyEntry(raw, password, name); err == nil || got != nil {
				t.Fatal("invalid authentication/layout accepted")
			}
		}
	}
}

// Although production only passes our freshly encoded PFX, fuzz the adapter's
// ASN.1 boundary too. Its fixed MAC parameters refuse attacker-chosen KDF work.
func FuzzGeneratedPKCS12Alias(f *testing.F) {
	password := []byte("qa-only-password")
	f.Add(generatedAliasFixture(f, password), "payments")
	f.Add([]byte("not-pfx"), "付款")
	f.Fuzz(func(t *testing.T, blob []byte, alias string) {
		if len(blob) > 64<<10 || len(alias) > 2048 {
			t.Skip()
		}
		name, err := javaAliasAttribute(alias)
		if err != nil {
			return
		}
		got, err := nameGeneratedKeyEntry(blob, password, name)
		if err != nil {
			if got != nil {
				t.Fatal("failed alias returned a container")
			}
			return
		}
		defer secret.Wipe(got)
		key, chain, err := Decode(got, string(password))
		defer secret.Wipe(key)
		if err != nil || len(chain) == 0 {
			t.Fatal("accepted alias is not an authenticated usable PFX")
		}
	})
}
