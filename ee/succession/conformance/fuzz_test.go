// SPDX-License-Identifier: LicenseRef-trstctl-EE

package conformance

import (
	"encoding/json"
	"os"
	"testing"

	"trstctl.com/trstctl/ee/succession"
	"trstctl.com/trstctl/ee/succession/minter"
	"trstctl.com/trstctl/ee/succession/staple"
)

// seedFromVector adds a valid encoded artifact from the published vector, plus a few
// adversarial seeds, to a fuzz corpus. The seed corpus runs under an ordinary
// `go test` (and `make fuzz-smoke`), so the targets execute in CI without -fuzz.
func recordSeed() []byte {
	raw, err := os.ReadFile(chainVectorPath)
	if err != nil {
		return []byte("{}")
	}
	var v ChainVector
	if err := json.Unmarshal(raw, &v); err != nil || len(v.Chain) == 0 {
		return []byte("{}")
	}
	b, _ := json.Marshal(v.Chain[0])
	return b
}

func chainSeed() []byte {
	raw, err := os.ReadFile(chainVectorPath)
	if err != nil {
		return []byte("[]")
	}
	var v ChainVector
	if err := json.Unmarshal(raw, &v); err != nil {
		return []byte("[]")
	}
	b, _ := json.Marshal(v.Chain)
	return b
}

// FuzzDecodeRecord: decoding then verifying an arbitrary record must never panic.
func FuzzDecodeRecord(f *testing.F) {
	f.Add(recordSeed())
	for _, s := range [][]byte{[]byte(""), []byte("{}"), []byte("null"), []byte(`{"Fields":{}}`), []byte("not-json")} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		rec, err := minter.DecodeRecord(data)
		if err != nil {
			return
		}
		_ = succession.VerifyRecord(rec) // must not panic on any decoded record
	})
}

// FuzzVerifyChain: verifying an arbitrary decoded chain against a genesis must never
// panic.
func FuzzVerifyChain(f *testing.F) {
	f.Add(chainSeed())
	for _, s := range [][]byte{[]byte("[]"), []byte("null"), []byte(`[{}]`), []byte("garbage")} {
		f.Add(s)
	}
	genesis := succession.GenesisRecord{
		DeploymentScope: e2eScope, IdentityID: e2eIdentity, TenantID: e2eTenant,
		Algorithm: "ECDSA-P256", PublicKey: []byte{0x30}, Epoch: 0,
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var chain []succession.SuccessionRecord
		if err := json.Unmarshal(data, &chain); err != nil {
			return
		}
		_ = succession.VerifyChain(genesis, chain, 0) // must not panic
	})
}

// FuzzStapleDecode: parsing an arbitrary stapled attachment must never panic.
func FuzzStapleDecode(f *testing.F) {
	for _, s := range [][]byte{[]byte("{}"), []byte(""), []byte("null"), []byte(`{"records":[{}]}`), []byte("garbage")} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		att, err := staple.Decode(data)
		if err != nil {
			return
		}
		_, _ = staple.VerifyStapled(&att, staple.Policy{}) // must not panic
	})
}
