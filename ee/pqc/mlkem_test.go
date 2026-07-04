// SPDX-License-Identifier: LicenseRef-trstctl-EE

package pqc

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

type mlkemKATFile struct {
	Vectors []mlkemKAT `json:"vectors"`
}

type mlkemKAT struct {
	ParameterSet string `json:"parameterSet"`
	KeyGen       struct {
		D  string `json:"d"`
		Z  string `json:"z"`
		EK string `json:"ek"`
		DK string `json:"dk"`
	} `json:"keyGen"`
	Encapsulate struct {
		EK string `json:"ek"`
		M  string `json:"m"`
		C  string `json:"c"`
		K  string `json:"k"`
	} `json:"encapsulate"`
	Decapsulate struct {
		DK string `json:"dk"`
		C  string `json:"c"`
		K  string `json:"k"`
	} `json:"decapsulate"`
}

func TestMLKEMFIPS203KATVectors(t *testing.T) {
	fixture, err := os.ReadFile("testdata/mlkem_fips203_subset.json")
	if err != nil {
		t.Fatal(err)
	}
	var kats mlkemKATFile
	if err := json.Unmarshal(fixture, &kats); err != nil {
		t.Fatal(err)
	}

	for _, kat := range kats.Vectors {
		kat := kat
		t.Run(kat.ParameterSet, func(t *testing.T) {
			alg := mlkemAlgorithm(t, kat.ParameterSet)

			keySeed := append(mustHex(t, kat.KeyGen.D), mustHex(t, kat.KeyGen.Z)...)
			key, err := DeriveKEMKey(alg, keySeed)
			if err != nil {
				t.Fatalf("DeriveKEMKey: %v", err)
			}
			defer key.Destroy()

			if got, want := key.Public().DER, mustHex(t, kat.KeyGen.EK); !bytes.Equal(got, want) {
				t.Fatalf("keygen public key mismatch\n got: %X\nwant: %X", got, want)
			}
			privateKey, err := key.PrivateKeyBytes()
			if err != nil {
				t.Fatalf("PrivateKeyBytes: %v", err)
			}
			defer secret.Wipe(privateKey)
			if want := mustHex(t, kat.KeyGen.DK); !bytes.Equal(privateKey, want) {
				t.Fatalf("keygen private key mismatch\n got: %X\nwant: %X", privateKey, want)
			}

			encPublic := crypto.PublicKey{Algorithm: alg, DER: mustHex(t, kat.Encapsulate.EK)}
			ct, ss, err := EncapsulateDeterministically(encPublic, mustHex(t, kat.Encapsulate.M))
			if err != nil {
				t.Fatalf("EncapsulateDeterministically: %v", err)
			}
			if want := mustHex(t, kat.Encapsulate.C); !bytes.Equal(ct, want) {
				t.Fatalf("encapsulation ciphertext mismatch\n got: %X\nwant: %X", ct, want)
			}
			if want := mustHex(t, kat.Encapsulate.K); !bytes.Equal(ss, want) {
				t.Fatalf("encapsulation shared secret mismatch\n got: %X\nwant: %X", ss, want)
			}

			decKeyBytes := mustHex(t, kat.Decapsulate.DK)
			defer secret.Wipe(decKeyBytes)
			decKey, err := NewKEMPrivateKey(alg, decKeyBytes)
			if err != nil {
				t.Fatalf("NewKEMPrivateKey: %v", err)
			}
			defer decKey.Destroy()
			decSS, err := decKey.Decapsulate(mustHex(t, kat.Decapsulate.C))
			if err != nil {
				t.Fatalf("Decapsulate: %v", err)
			}
			if want := mustHex(t, kat.Decapsulate.K); !bytes.Equal(decSS, want) {
				t.Fatalf("decapsulation shared secret mismatch\n got: %X\nwant: %X", decSS, want)
			}
		})
	}
}

func TestMLKEMRoundTrip(t *testing.T) {
	for _, alg := range []crypto.Algorithm{MLKEM512, MLKEM768, MLKEM1024} {
		alg := alg
		t.Run(string(alg), func(t *testing.T) {
			key, err := GenerateKEMKey(alg)
			if err != nil {
				t.Fatalf("GenerateKEMKey: %v", err)
			}
			defer key.Destroy()

			ct, ss, err := Encapsulate(key.Public())
			if err != nil {
				t.Fatalf("Encapsulate: %v", err)
			}
			decSS, err := key.Decapsulate(ct)
			if err != nil {
				t.Fatalf("Decapsulate: %v", err)
			}
			if !bytes.Equal(decSS, ss) {
				t.Fatalf("shared secret mismatch\nenc: %X\ndec: %X", ss, decSS)
			}

			key.Destroy()
			if _, err := key.Decapsulate(ct); err == nil {
				t.Fatal("Decapsulate after Destroy succeeded")
			}
		})
	}
}

func mlkemAlgorithm(t *testing.T, parameterSet string) crypto.Algorithm {
	t.Helper()
	switch parameterSet {
	case "ML-KEM-512":
		return MLKEM512
	case "ML-KEM-768":
		return MLKEM768
	case "ML-KEM-1024":
		return MLKEM1024
	default:
		t.Fatalf("unknown ML-KEM parameter set %q", parameterSet)
		return ""
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return b
}
