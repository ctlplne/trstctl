package webui_test

import (
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	"trstctl.com/trstctl/internal/webui"
)

func fixtureFS() fs.FS {
	return fstest.MapFS{
		"index.html":     {Data: []byte("<!doctype html><title>trstctl</title><div id=root></div>")},
		"assets/app.js":  {Data: []byte("console.log('trstctl')")},
		"assets/app.css": {Data: []byte("body{color:#000}")},
		"favicon.svg":    {Data: []byte("<svg/>")},
	}
}

func get(t *testing.T, h http.Handler, path string) (*http.Response, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	res := rec.Result()
	body := rec.Body.String()
	return res, body
}

func TestServesIndexAtRoot(t *testing.T) {
	res, body := get(t, webui.Handler(fixtureFS()), "/")
	if res.StatusCode != 200 {
		t.Fatalf("GET / = %d", res.StatusCode)
	}
	if !strings.Contains(body, "id=root") {
		t.Errorf("root did not serve index.html: %q", body)
	}
	if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("index Content-Type = %q, want text/html", ct)
	}
}

func TestServesAssetWithContentType(t *testing.T) {
	res, body := get(t, webui.Handler(fixtureFS()), "/assets/app.js")
	if res.StatusCode != 200 || !strings.Contains(body, "trstctl") {
		t.Fatalf("asset = %d %q", res.StatusCode, body)
	}
	if ct := res.Header.Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Errorf("asset Content-Type = %q, want javascript", ct)
	}
}

// An unknown client-side route falls back to index.html so the SPA router can
// handle it — this is what makes deep links work.
func TestSPAFallback(t *testing.T) {
	for _, p := range []string{"/certificates", "/risk", "/graph/abc-123"} {
		res, body := get(t, webui.Handler(fixtureFS()), p)
		if res.StatusCode != 200 || !strings.Contains(body, "id=root") {
			t.Errorf("SPA fallback %s = %d, body %q", p, res.StatusCode, body)
		}
	}
}

// The UI handler must never serve index.html for API paths — those belong to the
// API handler when composed.
func TestDoesNotShadowAPI(t *testing.T) {
	res, _ := get(t, webui.Handler(fixtureFS()), "/api/v1/certificates")
	if res.StatusCode != http.StatusNotFound {
		t.Errorf("GET /api/... = %d, want 404 (left for the API handler)", res.StatusCode)
	}
}

// With no built UI (index.html absent), the handler degrades to 404 rather than
// panicking.
func TestMissingIndexIs404(t *testing.T) {
	empty := fstest.MapFS{"robots.txt": {Data: []byte("ok")}}
	res, _ := get(t, webui.Handler(empty), "/dashboard")
	if res.StatusCode != http.StatusNotFound {
		t.Errorf("missing index = %d, want 404", res.StatusCode)
	}
}

// The package ships embedded assets (a placeholder until the real build), so the
// binary always has something to serve.
func TestEmbeddedAssetsHaveIndex(t *testing.T) {
	f, err := webui.Assets().Open("index.html")
	if err != nil {
		t.Fatalf("embedded assets missing index.html: %v", err)
	}
	_ = f.Close()
}

// indexIsPlaceholder reports whether the REAL embedded index.html (not a fixture)
// is the committed "not built" placeholder rather than a real Vite build. A real
// build injects a hashed module bundle (<script ... src=".../assets/index-XXXX.js">);
// the placeholder has no such script and carries the "has not been built" text.
func indexIsPlaceholder(t *testing.T) (placeholder bool, idx string) {
	t.Helper()
	f, err := webui.Assets().Open("index.html")
	if err != nil {
		t.Fatalf("embedded assets missing index.html: %v", err)
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	idx = string(b)
	hasHashedBundle := strings.Contains(idx, "assets/index-") && strings.Contains(idx, "<script")
	saysNotBuilt := strings.Contains(strings.ToLower(idx), "has not been built")
	return saysNotBuilt || !hasHashedBundle, idx
}

// TestEmbeddedIndexIsInternallyConsistent asserts against the REAL go:embed artifact
// (NOT a fixture FS), closing the SURFACE-006 fixture-masking gap: the prior tests
// proved the SPA handler works against a hand-written fixture index.html, which hid
// the fact that the committed embedded index.html is a dead placeholder. Here:
//   - if the embed is a real Vite build, every hashed asset it references must
//     actually exist in the embedded FS (no dangling bundle), and
//   - if it is the placeholder, it must honestly say so (so the EXC-WIRE-04
//     not-yet-served disclosure in docs/limitations.md stays truthful).
//
// Either way the embedded artifact is self-consistent — a build that referenced a
// missing bundle, or a "real-looking" page that is actually dead, fails here.
func TestEmbeddedIndexIsInternallyConsistent(t *testing.T) {
	placeholder, idx := indexIsPlaceholder(t)
	if placeholder {
		// Honest placeholder: it must declare itself, so docs disclosure is truthful.
		if !strings.Contains(strings.ToLower(idx), "has not been built") {
			t.Error("the embedded index.html neither references a hashed Vite bundle nor declares itself a placeholder; it is a dead/over-claiming page (SURFACE-006)")
		}
		return
	}
	// Real build: every referenced /assets/index-*.{js,css} must exist in the embed.
	re := regexp.MustCompile(`(?:src|href)="(/?assets/index-[A-Za-z0-9_-]+\.(?:js|css))"`)
	matches := re.FindAllStringSubmatch(idx, -1)
	if len(matches) == 0 {
		t.Fatal("embedded index.html looks like a real build but references no hashed /assets/index-*.{js,css} bundle (SURFACE-006)")
	}
	assets := webui.Assets()
	for _, m := range matches {
		name := strings.TrimPrefix(m[1], "/")
		f, err := assets.Open(name)
		if err != nil {
			t.Errorf("embedded index.html references %q but it is not in the embedded FS (dangling bundle) (SURFACE-006): %v", m[1], err)
			continue
		}
		_ = f.Close()
	}
}

// TestEmbeddedUIIsARealBuild is the SURFACE-006 RELEASE GATE: it FAILS on the
// committed placeholder and PASSES only on a real Vite build embedded into dist/.
// It is opt-in so it does not break `make test` while the embedded UI is the
// honest, disclosed placeholder (EXC-WIRE-04) — the release pipeline sets
// TRSTCTL_REQUIRE_BUILT_UI=1 (after `make web`) so a release artifact cannot ship
// the "not built" page at /. Run locally with: TRSTCTL_REQUIRE_BUILT_UI=1 go test
// ./internal/webui/... (after `make web`).
func TestEmbeddedUIIsARealBuild(t *testing.T) {
	if os.Getenv("TRSTCTL_REQUIRE_BUILT_UI") == "" {
		t.Skip("set TRSTCTL_REQUIRE_BUILT_UI=1 to require a real embedded Vite build (release gate; the embed is the disclosed placeholder by default — SURFACE-006/EXC-WIRE-04)")
	}
	placeholder, idx := indexIsPlaceholder(t)
	if placeholder {
		t.Fatalf("TRSTCTL_REQUIRE_BUILT_UI is set but the embedded index.html is the placeholder (run `make web` to embed a real Vite bundle) (SURFACE-006):\n%s", idx)
	}
}
