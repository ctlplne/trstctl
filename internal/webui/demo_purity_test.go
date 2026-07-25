// SPDX-License-Identifier: MPL-2.0

package webui_test

import (
	"bytes"
	"io/fs"
	"testing"

	"trstctl.com/trstctl/internal/webui"
)

// TestEmbeddedConsoleCarriesNoPreviewIdentity is the embed-purity half of the
// demo-site contract (demo.trstctl.com). The static demo build enables the
// in-browser preview showcase with VITE_TRSTCTL_DEMO=1; the PRODUCT build
// must never set that flag, and when it does not, Vite tree-shakes the
// preview identity out of the bundle entirely. This test proves the property
// on the committed artifact: no embedded asset may contain the preview
// principal. If it fires, the embed under internal/webui/dist was built with
// the demo flag — rebuild with `make web`.
func TestEmbeddedConsoleCarriesNoPreviewIdentity(t *testing.T) {
	forbidden := [][]byte{
		[]byte("dev-preview"),
		[]byte("preview@trstctl.local"),
	}
	assets := webui.Assets()
	checked := 0
	err := fs.WalkDir(assets, ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		raw, readErr := fs.ReadFile(assets, path)
		if readErr != nil {
			t.Fatalf("read embedded %s: %v", path, readErr)
		}
		checked++
		for _, needle := range forbidden {
			if bytes.Contains(raw, needle) {
				t.Errorf("embedded asset %s contains %q — the product embed was built with the demo flag; rebuild with `make web` (never VITE_TRSTCTL_DEMO=1)", path, needle)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk embedded assets: %v", err)
	}
	if checked == 0 {
		t.Fatal("no embedded assets walked — embed layout changed?")
	}
}
