// SPDX-License-Identifier: BUSL-1.1

// Command gen pins a freshly built first-party connector module beside the host
// package: it writes the module gzip-compressed with its SHA-256, so the
// binaries embed exactly the module this tree builds. `make connector-wasm`
// builds the module for wasip1 and runs this; run it whenever a connector
// family, the native census or the wasm packages change — the host package's
// freshness test fails until the committed module matches.
//
// The whole pipeline is reproducible: the build uses -trimpath, no VCS stamping
// and fixed flags, and the gzip stream carries no name or timestamp.
package main

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"trstctl.com/trstctl/internal/crypto"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "connector-wasm:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: gen <built module.wasm>")
	}
	module, err := os.ReadFile(args[0]) // #nosec G304 G703 -- a developer tool reading the module the make target just built (CWE-22).
	if err != nil {
		return err
	}
	var compressed bytes.Buffer
	zw, err := gzip.NewWriterLevel(&compressed, gzip.BestCompression)
	if err != nil {
		return err
	}
	if _, err := zw.Write(module); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	target := filepath.Join("internal", "connector", "wasm", "host")
	if err := os.WriteFile(filepath.Join(target, "builtin.wasm.gz"), compressed.Bytes(), 0o644); err != nil { // #nosec G306 G703 -- a public build artifact at a fixed repository path (CWE-276, CWE-22).
		return err
	}
	digest := crypto.SHA256Hex(module) + "\n"
	if err := os.WriteFile(filepath.Join(target, "builtin.sha256"), []byte(digest), 0o644); err != nil { // #nosec G306 G703 -- a public digest at a fixed repository path (CWE-276, CWE-22).
		return err
	}
	fmt.Printf("connector-wasm: %d bytes (%d compressed), sha256 %s", len(module), compressed.Len(), digest)
	return nil
}
