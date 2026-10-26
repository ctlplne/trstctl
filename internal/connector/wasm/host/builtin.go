// SPDX-License-Identifier: BUSL-1.1

package host

import (
	"bytes"
	"compress/gzip"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"trstctl.com/trstctl/internal/crypto"
)

// The first-party connector module this binary ships, built from this tree by
// `make connector-wasm` (see gen). The digest is the uncompressed module's.
var (
	//go:embed builtin.wasm.gz
	builtinCompressed []byte
	//go:embed builtin.sha256
	builtinDigest string
)

const maxModuleBytes = 64 << 20

var (
	builtinOnce    sync.Once
	builtinRuntime *Runtime
	builtinErr     error
)

// Builtin returns the runtime for the embedded first-party connector module,
// verifying it against its digest and compiling it on first use. Compilation is
// detached from the caller's context so one cancelled caller cannot leave every
// later one without a runtime.
func Builtin() (*Runtime, error) {
	builtinOnce.Do(func() { builtinRuntime, builtinErr = loadBuiltin() })
	return builtinRuntime, builtinErr
}

// BuiltinDigest is the SHA-256 of the embedded module.
func BuiltinDigest() string { return strings.TrimSpace(builtinDigest) }

func loadBuiltin() (*Runtime, error) {
	zr, err := gzip.NewReader(bytes.NewReader(builtinCompressed))
	if err != nil {
		return nil, fmt.Errorf("connector sandbox: embedded module: %w", err)
	}
	module, err := io.ReadAll(io.LimitReader(zr, maxModuleBytes+1))
	if err != nil {
		return nil, fmt.Errorf("connector sandbox: embedded module: %w", err)
	}
	if len(module) > maxModuleBytes {
		return nil, errors.New("connector sandbox: embedded module is too large")
	}
	if crypto.SHA256Hex(module) != BuiltinDigest() {
		return nil, errors.New("connector sandbox: embedded module does not match its digest")
	}
	return New(context.Background(), module)
}
