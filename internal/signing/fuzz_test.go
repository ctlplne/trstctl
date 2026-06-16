package signing

import (
	"testing"

	"google.golang.org/protobuf/proto"

	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// FuzzSignRequestParser fuzzes the protocol parser: arbitrary bytes are decoded
// as a SignRequest and validated. Neither the protobuf decode nor the
// validation may ever panic on malformed or adversarial input.
func FuzzSignRequestParser(f *testing.F) {
	valid, err := proto.Marshal(&signerpb.SignRequest{
		Handle: &signerpb.KeyHandle{Id: "abc123"},
		Digest: make([]byte, 32),
		Hash:   signerpb.Hash_HASH_SHA256,
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte{})
	f.Add([]byte{0xFF, 0x00, 0x10, 0x7F})

	f.Fuzz(func(t *testing.T, data []byte) {
		var req signerpb.SignRequest
		if err := proto.Unmarshal(data, &req); err != nil {
			return // not a valid SignRequest encoding
		}
		_ = validateSignRequest(&req) // must never panic
	})
}
