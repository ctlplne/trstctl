package crypto

import (
	"runtime"

	"trstctl.com/trstctl/internal/crypto/secret"
)

type binaryPrivateKey interface {
	MarshalBinary() ([]byte, error)
	UnmarshalBinary([]byte) error
}

// WipeBinaryPrivateKey best-effort zeroizes transient private-key objects from
// libraries that expose binary marshal/unmarshal but do not expose an explicit
// Destroy method. It marshals the key to learn its exact encoded shape, overwrites
// that encoding with zeroes, unmarshals the zero encoding back into the object, and
// then wipes the temporary slice.
//
// This is intentionally narrow: it is for short-lived, heap-resident parsed keys
// whose durable copy already lives in secret.Buffer. If a concrete key rejects an
// all-zero encoding, the helper still wipes the temporary encoding and returns; the
// stronger production answer for those algorithms remains HSM/provider custody.
func WipeBinaryPrivateKey(key any) {
	k, ok := key.(binaryPrivateKey)
	if !ok || k == nil {
		return
	}
	encoded, err := k.MarshalBinary()
	if err != nil {
		runtime.KeepAlive(key)
		return
	}
	secret.Wipe(encoded)
	_ = k.UnmarshalBinary(encoded)
	secret.Wipe(encoded)
	runtime.KeepAlive(key)
}
