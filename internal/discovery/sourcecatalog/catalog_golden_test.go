// SPDX-License-Identifier: BUSL-1.1

package sourcecatalog

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"testing"
)

var updateSourceCatalogGolden = flag.Bool("update-source-catalog-golden", false, "update the discovery source capability golden after reviewing its UI, docs, and test impact")

const catalogGoldenPath = "testdata/catalog.golden.json"

func TestCatalogGolden(t *testing.T) {
	want, err := json.MarshalIndent(All(), "", "  ")
	if err != nil {
		t.Fatalf("marshal source capability catalog: %v", err)
	}
	want = append(want, '\n')
	if *updateSourceCatalogGolden {
		if err := os.MkdirAll("testdata", 0o750); err != nil {
			t.Fatalf("create golden directory: %v", err)
		}
		if err := os.WriteFile(catalogGoldenPath, want, 0o600); err != nil {
			t.Fatalf("write source capability golden: %v", err)
		}
	}
	got, err := os.ReadFile(catalogGoldenPath)
	if err != nil {
		t.Fatalf("read source capability golden: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("source capability contract changed; update the golden only after the console adapter, docs, and journey proof have an explicit disposition")
	}
}
