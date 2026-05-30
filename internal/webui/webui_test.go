package webui_test

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"certctl.io/certctl/internal/webui"
)

func fixtureFS() fs.FS {
	return fstest.MapFS{
		"index.html":     {Data: []byte("<!doctype html><title>certctl</title><div id=root></div>")},
		"assets/app.js":  {Data: []byte("console.log('certctl')")},
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
	if res.StatusCode != 200 || !strings.Contains(body, "certctl") {
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
