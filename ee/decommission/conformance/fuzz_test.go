// SPDX-License-Identifier: LicenseRef-trstctl-EE

package conformance

import (
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/ee/decommission/depstate"
	"trstctl.com/trstctl/ee/decommission/record"
	vdecverify "trstctl.com/trstctl/ee/decommission/verify"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/eventspec"
)

func FuzzVDECRecordDecode(f *testing.F) {
	f.Add(vectorRecordSeed())
	for _, seed := range [][]byte{[]byte(""), []byte("{}"), []byte("null"), []byte("not-json")} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		rec, err := record.DecodeRecord(raw)
		if err != nil {
			return
		}
		_, _ = record.EncodeRecord(rec)
		_ = record.VerifyRecord(rec, recPublicKey(rec))
	})
}

func FuzzVDECVerifyRequestJSON(f *testing.F) {
	f.Add(vectorRequestSeed())
	for _, seed := range [][]byte{[]byte(""), []byte("{}"), []byte("null"), []byte(`{"record":{}}`), []byte("not-json")} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		var req vdecverify.Request
		if err := json.Unmarshal(raw, &req); err != nil {
			return
		}
		_, _ = vdecverify.Verify(req)
	})
}

func FuzzVDECDepstateEventDecode(f *testing.F) {
	f.Add(depstateEventSeed())
	for _, seed := range [][]byte{[]byte(""), []byte("{}"), []byte("null"), []byte(`{"type":"dependency.registered","schema_version":1,"data":{broken}`)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		var ev eventspec.Event
		if err := json.Unmarshal(raw, &ev); err != nil {
			return
		}
		_, _ = depstate.Decode(ev)
	})
}

func recPublicKey(rec record.SignedRecord) crypto.PublicKey {
	return crypto.PublicKey{Algorithm: rec.AttestationAlgorithm, DER: append([]byte(nil), rec.AttestationPublicKeyDER...)}
}
