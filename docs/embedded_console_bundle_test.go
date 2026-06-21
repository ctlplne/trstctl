package docs

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestEmbeddedConsoleBundleBoundary(t *testing.T) {
	index := read(t, "../internal/webui/dist/index.html")
	for _, want := range []string{
		`<div id="root"></div>`,
		`type="module"`,
		`/assets/index-`,
	} {
		if !strings.Contains(index, want) {
			t.Errorf("embedded console index must be a real Vite shell; missing %q", want)
		}
	}
	if strings.Contains(strings.ToLower(index), "has not been built") {
		t.Fatal("embedded console regressed to the placeholder index")
	}
	if len(index) < 500 {
		t.Fatalf("embedded console index is unexpectedly tiny: %d bytes", len(index))
	}

	assetRE := regexp.MustCompile(`/assets/index-[^"']+\.(?:js|css)`)
	matches := assetRE.FindAllString(index, -1)
	seen := map[string]bool{}
	for _, asset := range matches {
		ext := filepath.Ext(asset)
		seen[ext] = true
		path := filepath.Join("..", "internal", "webui", "dist", strings.TrimPrefix(asset, "/"))
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("embedded console asset %s is referenced but missing: %v", asset, err)
		}
		switch ext {
		case ".js":
			if info.Size() < 100_000 {
				t.Fatalf("embedded console JS asset %s is too small for the real SPA bundle: %d bytes", asset, info.Size())
			}
		case ".css":
			if info.Size() < 1_000 {
				t.Fatalf("embedded console CSS asset %s is too small for the real SPA bundle: %d bytes", asset, info.Size())
			}
		}
	}
	for _, ext := range []string{".js", ".css"} {
		if !seen[ext] {
			t.Errorf("embedded console index did not reference a hashed %s asset", ext)
		}
	}

	handler := read(t, "../internal/webui/webui.go")
	for _, want := range []string{
		`clean == "/api" || strings.HasPrefix(clean, "/api/")`,
		`return`,
		`serveFile(w, r, assets, "index.html")`,
		`http.ServeContent`,
		`index.html`,
	} {
		if !strings.Contains(handler, want) {
			t.Errorf("webui handler must keep /api separate and serve SPA fallback; missing %q", want)
		}
	}

	servedTests := read(t, "../internal/webui/served_console_test.go")
	for _, want := range []string{
		"TestServedRootIsTheRealConsoleNotThePlaceholder",
		"TestServedHashedAssetsResolve",
		"TestServedSPAFallbackOverRealEmbed",
		"hashed Vite bundle",
		"has not been built",
	} {
		if !strings.Contains(servedTests, want) {
			t.Errorf("served console tests must keep the real-bundle proof; missing %q", want)
		}
	}
}
