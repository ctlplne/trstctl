// SPDX-License-Identifier: BUSL-1.1

package bwsm

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// The public test vector of Bitwarden's open-source SDK (access_token.rs):
// a token whose 16-byte seed derives this 64-byte key. The parts are joined
// at run time; none of them is a live credential.
const (
	vectorID   = "ec2c1d46-6a4b-4751-a310-af9601317f2d"
	vectorSeed = "X8vbvA0bduihIDe/" + "qrzIQQ=="
)

var vectorToken = "0." + vectorID + "." + "C2IgxjjLF7qSshsbwe8J" + "GcbM075YXw" + ":" + vectorSeed

// vectorKey is the 64-byte key the SDK derives from vectorSeed.
var vectorKey = []byte{
	0x1f, 0xdf, 0xe8, 0x21, 0x12, 0xed, 0x2f, 0xd9, 0xc6, 0x09, 0x03, 0x95, 0x0e, 0x34, 0x8c, 0xa0,
	0x46, 0xc9, 0xb2, 0x35, 0x97, 0x48, 0xe0, 0x9b, 0xde, 0xa7, 0xb2, 0x0e, 0xde, 0x9c, 0x93, 0x34,
	0xb7, 0x16, 0x1c, 0x9b, 0xa0, 0x40, 0xd6, 0xc9, 0x33, 0xff, 0x09, 0x07, 0xdb, 0x22, 0xcc, 0xcd,
	0x98, 0x05, 0x60, 0xd8, 0x4c, 0x45, 0x81, 0xa9, 0xc6, 0xd4, 0x55, 0x45, 0x19, 0x73, 0xbf, 0x26,
}

// OD-13: the access token parses as the SDK parses it and its key derives
// exactly as the SDK derives it.
func TestAccessTokenKeyMatchesTheSDKVectorOD13(t *testing.T) {
	token, err := ParseAccessToken([]byte(vectorToken))
	if err != nil {
		t.Fatal(err)
	}
	defer token.Destroy()
	if token.ID != "ec2c1d46-6a4b-4751-a310-af9601317f2d" || string(token.ClientSecret.Bytes()) != "C2IgxjjLF7qSshsbwe8JGcbM075YXw" {
		t.Fatalf("parsed id %q secret %q", token.ID, token.ClientSecret.Bytes())
	}
	key, err := token.TokenKey()
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	if !bytes.Equal(key.buf.Bytes(), vectorKey) {
		t.Fatalf("derived key %x, want %x", key.buf.Bytes(), vectorKey)
	}
	// The seed's padding is optional, as in the SDK.
	if unpadded, err := ParseAccessToken([]byte(strings.TrimRight(vectorToken, "="))); err != nil {
		t.Fatalf("unpadded seed: %v", err)
	} else {
		unpadded.Destroy()
	}
	compose := func(version, id, clientSecret, seed string) string {
		return version + "." + id + "." + clientSecret + ":" + seed
	}
	shortSeed := strings.TrimSuffix(vectorSeed, "QQ==")
	for name, raw := range map[string]string{
		"no key":          "0." + vectorID + ".x",
		"version 1":       compose("1", vectorID, "x", vectorSeed),
		"not a uuid":      compose("0", "not-a-uuid", "x", vectorSeed),
		"no secret":       compose("0", vectorID, "", vectorSeed),
		"short seed":      compose("0", vectorID, "x", shortSeed),
		"long seed":       compose("0", vectorID, "x", shortSeed+"QQAA"),
		"two parts":       "0." + vectorID + ":" + vectorSeed,
		"not base64 seed": compose("0", vectorID, "x", shortSeed+"!Q=="),
	} {
		if _, err := ParseAccessToken([]byte(raw)); !errors.Is(err, ErrAccessToken) {
			t.Errorf("%s: %v, want ErrAccessToken", name, err)
		}
	}
}

// OD-13: a type-2 encrypted string round-trips; a changed IV, ciphertext or
// tag, another key, another type and malformed parts all refuse to open.
func TestEncStringOpensOnlyUnderItsKeyOD13(t *testing.T) {
	raw := bytes.Repeat([]byte{7}, 64)
	key, err := KeyFromBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	for _, plain := range []string{"", "a", "exactly sixteen!", "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"} {
		sealed, err := key.Encrypt([]byte(plain))
		if err != nil {
			t.Fatal(err)
		}
		opened, err := key.Decrypt(sealed)
		if err != nil || string(opened) != plain {
			t.Fatalf("round trip of %q = %q, %v", plain, opened, err)
		}
	}
	sealed, _ := key.Encrypt([]byte("database password"))
	parts := strings.Split(strings.TrimPrefix(sealed, "2."), "|")
	flip := func(s string) string {
		b, _ := base64.StdEncoding.DecodeString(s)
		b[0] ^= 1
		return base64.StdEncoding.EncodeToString(b)
	}
	other, _ := KeyFromBytes(bytes.Repeat([]byte{8}, 64))
	defer other.Destroy()
	for name, bad := range map[string]string{
		"changed iv":   "2." + flip(parts[0]) + "|" + parts[1] + "|" + parts[2],
		"changed data": "2." + parts[0] + "|" + flip(parts[1]) + "|" + parts[2],
		"changed tag":  "2." + parts[0] + "|" + parts[1] + "|" + flip(parts[2]),
		"type 0":       "0." + parts[0] + "|" + parts[1],
		"two parts":    "2." + parts[0] + "|" + parts[1],
		"not base64":   "2." + parts[0] + "|" + parts[1] + "|!!",
		"short iv":     "2." + base64.StdEncoding.EncodeToString([]byte("short")) + "|" + parts[1] + "|" + parts[2],
	} {
		if _, err := key.Decrypt(bad); !errors.Is(err, ErrEncString) {
			t.Errorf("%s opened: %v", name, err)
		}
	}
	if _, err := other.Decrypt(sealed); !errors.Is(err, ErrEncString) {
		t.Errorf("another key opened it: %v", err)
	}
	if _, err := KeyFromBytes(raw[:32]); err == nil {
		t.Error("a 32-byte key was accepted")
	}
}
