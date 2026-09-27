// SPDX-License-Identifier: BUSL-1.1

package clusterfuzz

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// The fixture contains public certificates, signed evidence and no private key.
// Its fractional manifest time, whole-second CMS time and nonce were verified
// independently with OpenSSL before this verifier was implemented.
//
//go:embed testdata/timestamp-public.json
var timestampFixtureJSON []byte

func FuzzVerifyRFC3161Timestamp(f *testing.F) {
	var fixture struct {
		DER         []byte    `json:"der"`
		Certificate []byte    `json:"certificate"`
		Policy      string    `json:"policy"`
		Imprint     []byte    `json:"imprint"`
		Serial      uint64    `json:"serial"`
		Time        time.Time `json:"time"`
	}
	if err := json.Unmarshal(timestampFixtureJSON, &fixture); err != nil {
		f.Fatal(err)
	}
	expected := crypto.TSTInfoParams{PolicyOID: fixture.Policy, HashedMessage: fixture.Imprint, SerialNumber: fixture.Serial, GenTime: fixture.Time, Nonce: big.NewInt(739)}
	if err := crypto.VerifyTimeStampToken(fixture.DER, fixture.Certificate, expected); err != nil {
		f.Fatalf("public timestamp seed must verify: %v", err)
	}
	f.Add(fixture.DER)
	f.Add([]byte(nil))
	f.Add([]byte{0x30, 0x84})
	f.Add([]byte("not a timestamp"))
	f.Fuzz(func(t *testing.T, der []byte) {
		if err := crypto.VerifyTimeStampToken(der, fixture.Certificate, expected); err != nil {
			return
		}
		wrong := expected
		wrong.HashedMessage = bytes.Clone(expected.HashedMessage)
		wrong.HashedMessage[0] ^= 1
		if err := crypto.VerifyTimeStampToken(der, fixture.Certificate, wrong); err == nil {
			t.Fatal("accepted CMS is not bound to its message imprint")
		}
		wrong = expected
		wrong.SerialNumber++
		if err := crypto.VerifyTimeStampToken(der, fixture.Certificate, wrong); err == nil {
			t.Fatal("accepted CMS is not bound to its issuance serial")
		}
		wrong = expected
		wrong.GenTime = expected.GenTime.Add(time.Second)
		if err := crypto.VerifyTimeStampToken(der, fixture.Certificate, wrong); err == nil {
			t.Fatal("accepted CMS is not bound to its timestamp")
		}
	})
}
