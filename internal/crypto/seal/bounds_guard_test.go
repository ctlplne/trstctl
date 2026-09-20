// SPDX-License-Identifier: BUSL-1.1

package seal_test

import (
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/crypto/seal"
)

// oversizedWrapper reports success but returns a wrapped DEK larger than the
// container's 2-byte length prefix can carry.
type oversizedWrapper struct{}

func (oversizedWrapper) WrapDEK([]byte) ([]byte, error)   { return make([]byte, 1<<16), nil }
func (oversizedWrapper) UnwrapDEK([]byte) ([]byte, error) { return nil, errors.New("unused") }

// emptyWrapper reports success with a zero-length wrapped DEK, which the
// container format treats as malformed rather than encoding a zero prefix.
type emptyWrapper struct{}

func (emptyWrapper) WrapDEK([]byte) ([]byte, error)   { return nil, nil }
func (emptyWrapper) UnwrapDEK([]byte) ([]byte, error) { return nil, errors.New("unused") }

// A wrapped DEK that does not fit the uint16 length prefix must be refused,
// not silently truncated into a mis-framed container (CWE-190). The guard for
// the fix at Seal's length-prefix write: delete the bounds check and this
// fails with a mis-framed blob instead of ErrFormat.
func TestSealRefusesOversizedWrappedDEK(t *testing.T) {
	if _, err := seal.Seal(oversizedWrapper{}, []byte("plaintext"), nil); !errors.Is(err, seal.ErrFormat) {
		t.Fatalf("Seal with a >65535-byte wrapped DEK returned %v, want ErrFormat: a truncated uint16 length prefix mis-frames the container", err)
	}
	if _, err := seal.Seal(emptyWrapper{}, []byte("plaintext"), nil); !errors.Is(err, seal.ErrFormat) {
		t.Fatalf("Seal with an empty wrapped DEK returned %v, want ErrFormat", err)
	}
}
