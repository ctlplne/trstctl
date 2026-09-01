// SPDX-License-Identifier: LicenseRef-trstctl-EE

package clusterfuzz

import (
	"bytes"
	"testing"

	"trstctl.com/trstctl/ee/agentid/agentstack"
)

func FuzzParse(f *testing.F) {
	// Seed with valid canonical bytes for both forms, plus hostile shapes.
	seed := func(m agentstack.Model) []byte {
		rep, err := agentstack.New([]byte("seed prompt"), agentstack.NewToolManifest("fs.read"), m)
		if err != nil {
			f.Fatalf("seed New: %v", err)
		}
		rep.Orchestrator = "o"
		rep.Runtime = "r"
		cb, err := rep.CanonicalBytes()
		if err != nil {
			f.Fatalf("seed CanonicalBytes: %v", err)
		}
		return cb
	}
	valid := seed(agentstack.Model{Form: agentstack.ModelFormProviderID, ProviderModelID: "p", ModelVersion: "v"})
	f.Add(valid)
	f.Add(seed(agentstack.Model{Form: agentstack.ModelFormWeightsDigest, WeightsDigest: bytes.Repeat([]byte{1}, 32)}))
	if len(valid) > 0 {
		f.Add(valid[:len(valid)-1]) // truncated
		f.Add(append(append([]byte(nil), valid...), 0xff))
	}
	f.Add([]byte{})
	f.Add([]byte("agid/agentstack/v1")) // prefix only
	// A length header claiming a huge size must not allocate or panic.
	f.Add([]byte("agid/agentstack/v1\x00\x00\x00\x00\xff\xff\xff\xff"))

	f.Fuzz(func(t *testing.T, data []byte) {
		rep, err := agentstack.Parse(data)
		if err != nil {
			return // rejecting hostile input is fine
		}
		// If Parse accepted, the representation must be valid and re-encode.
		if verr := rep.Validate(); verr != nil {
			t.Fatalf("Parse returned an invalid representation: %v", verr)
		}
		reCB, cerr := rep.CanonicalBytes()
		if cerr != nil {
			t.Fatalf("accepted representation failed to re-encode: %v", cerr)
		}
		// The re-encoded bytes must parse back to an equal representation
		// (idempotent canonical form).
		rep2, err2 := agentstack.Parse(reCB)
		if err2 != nil {
			t.Fatalf("re-encoded bytes did not parse: %v", err2)
		}
		reCB2, _ := rep2.CanonicalBytes()
		if !bytes.Equal(reCB, reCB2) {
			t.Fatal("canonical form is not idempotent under Parse/CanonicalBytes")
		}
	})
}
