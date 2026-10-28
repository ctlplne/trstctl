// SPDX-License-Identifier: BUSL-1.1

package clusterfuzz

import (
	"encoding/base64"
	"testing"

	"trstctl.com/trstctl/internal/crypto/ctlog"
	"trstctl.com/trstctl/internal/crypto/ctlog/ctlogtest"
)

func FuzzCTLog(f *testing.F) {
	// Valid seeds so the corpus also reaches the success paths.
	f.Add(ctlogtest.GetSTHBody(42))
	if der, _, err := ctlogtest.IssueCert("seed", "seed.example.com"); err == nil {
		f.Add(ctlogtest.GetEntriesBody(ctlogtest.X509Entry(der)))
	}
	// Malformed / hostile seeds spanning each decode stage.
	f.Add([]byte(""))
	f.Add([]byte("{"))
	f.Add([]byte("not json"))
	f.Add([]byte(`{"tree_size":-1}`))                                                    // negative tree size
	f.Add([]byte(`{"entries":[{"leaf_input":"@@@","extra_data":""}]}`))                  // leaf_input not base64
	f.Add([]byte(`{"entries":[{"leaf_input":"AAAB","extra_data":""}]}`))                 // decodes but framing truncated
	f.Add([]byte(`{"entries":[{"leaf_input":"AAAAAAAAAAAAAAD/////","extra_data":""}]}`)) // 24-bit length overflow

	f.Fuzz(func(t *testing.T, body []byte) {
		// ParseSTH must never panic and must never accept a negative tree size.
		if sth, err := ctlog.ParseSTH(body); err == nil {
			if sth.TreeSize < 0 {
				t.Fatalf("ParseSTH accepted a negative tree size: %d", sth.TreeSize)
			}
		}
		// ParseEntries must never panic; if it succeeds, the framing and the
		// embedded certificate were well-formed, so the result is self-consistent.
		entries, err := ctlog.ParseEntries(0, body)
		if err != nil {
			return
		}
		for i, e := range entries {
			if e.Index != int64(i) {
				t.Fatalf("entry %d parsed with non-contiguous index %d", i, e.Index)
			}
			if e.FingerprintSHA256 == "" {
				t.Fatalf("entry %d parsed with an empty fingerprint", i)
			}
		}
	})
}

// FuzzCTLogTransparency drives arbitrary bytes through the A213 parsers a CT
// log's answers reach — an add-chain SCT, a signed tree head and an inclusion
// proof — and through SCT and inclusion verification. A hostile log must get
// an error, never a panic, and never a parsed value that breaks its bounds.
func FuzzCTLogTransparency(f *testing.F) {
	node := base64.StdEncoding.EncodeToString(make([]byte, 32))
	f.Add([]byte(`{"sct_version":0,"id":"` + node + `","timestamp":1700000000000,"extensions":"","signature":"BAMABDBEAA=="}`))
	f.Add([]byte(`{"tree_size":3,"timestamp":1700000000000,"sha256_root_hash":"` + node + `","tree_head_signature":"BAMAAA=="}`))
	f.Add([]byte(`{"leaf_index":2,"audit_path":["` + node + `","` + node + `"]}`))
	f.Add([]byte(`{"sct_version":1,"id":"","timestamp":0,"signature":""}`))
	f.Add([]byte(`{"tree_size":-1,"sha256_root_hash":"AA=="}`))
	f.Add([]byte(`{"leaf_index":-5,"audit_path":["@@@"]}`))
	f.Add([]byte("{"))
	log := ctlogtest.NewSigningServer()
	defer log.Close()
	key := log.PublicKeyDER()

	f.Fuzz(func(t *testing.T, body []byte) {
		if sct, err := ctlog.ParseSCT(body); err == nil {
			if len(sct.LogID) != 32 || len(sct.Signature) < 4 {
				t.Fatalf("ParseSCT accepted an SCT outside its bounds: %+v", sct)
			}
			_, _ = ctlog.VerifySCT(sct, key, [][]byte{body}, false)
			_, _ = ctlog.VerifySCT(sct, key, [][]byte{body, body}, true)
		}
		if sth, err := ctlog.ParseSignedTreeHead(body); err == nil {
			if len(sth.RootHash) != 32 {
				t.Fatalf("ParseSignedTreeHead accepted a root of %d bytes", len(sth.RootHash))
			}
			_ = ctlog.VerifySignedTreeHead(sth, key)
		}
		if proof, err := ctlog.ParseInclusionProof(body); err == nil {
			if len(proof.AuditPath) > 64 {
				t.Fatalf("ParseInclusionProof accepted %d nodes", len(proof.AuditPath))
			}
			_ = ctlog.VerifyInclusion(make([]byte, 32), proof.LeafIndex, proof.LeafIndex+1, proof.AuditPath, make([]byte, 32))
		}
	})
}
