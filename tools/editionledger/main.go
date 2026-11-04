// SPDX-License-Identifier: BUSL-1.1

// Command editionledger writes the edition and qualification ledger (A253):
// docs/editions-ledger.json, docs/editions-ledger.md, and the marked blocks in
// README.md and docs/editions.md. With -check it changes nothing and exits 1 if
// any of them differs from what it would write.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"trstctl.com/trstctl/internal/editionledger"
)

func main() {
	root := flag.String("root", ".", "repository root")
	check := flag.Bool("check", false, "report drift instead of writing")
	flag.Parse()
	if err := run(*root, *check); err != nil {
		fmt.Fprintln(os.Stderr, "editionledger:", err)
		os.Exit(1)
	}
}

func run(root string, check bool) error {
	l, err := editionledger.Build()
	if err != nil {
		return err
	}
	ledgerJSON, err := l.JSON()
	if err != nil {
		return err
	}
	want := map[string][]byte{
		"docs/editions-ledger.json": ledgerJSON,
		"docs/editions-ledger.md":   []byte(l.Markdown()),
	}
	for _, page := range []string{"README.md", "docs/editions.md"} {
		current, err := os.ReadFile(filepath.Join(root, page)) // #nosec G304 -- developer tool reading the repo paths it is pointed at (CWE-22)
		if err != nil {
			return err
		}
		rendered, err := editionledger.ReplaceBlocks(current, l.Blocks())
		if err != nil {
			return fmt.Errorf("%s: %w", page, err)
		}
		want[page] = rendered
	}
	drift := false
	for path, content := range want {
		full := filepath.Join(root, path)
		current, _ := os.ReadFile(full) // #nosec G304 -- developer tool reading the repo paths it is pointed at (CWE-22)
		if bytes.Equal(current, content) {
			continue
		}
		if check {
			fmt.Fprintf(os.Stderr, "editionledger: %s is out of date; run go run ./tools/editionledger\n", path)
			drift = true
			continue
		}
		if err := os.WriteFile(full, content, 0o644); err != nil { // #nosec G306 -- a public documentation file (CWE-276)
			return err
		}
	}
	if drift {
		return fmt.Errorf("the ledger and its blocks are out of date")
	}
	return nil
}
