package webui_test

import (
	"net/http"
	"regexp"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/webui"
)

// This file proves EXC-WIRE-04 / SURFACE-001 end-to-end on the SERVED path: it boots
// the exact handler the binary mounts at "/" — webui.Handler(webui.Assets()) — over the
// REAL go:embed artifact (not a fixture FS, closing SURFACE-006's masking) and asserts
// the served bytes are the real React console:
//
//   - GET / returns an index.html that references a hashed Vite module bundle
//     (<script ... src="/assets/index-XXXX.js">), NOT the "has not been built"
//     placeholder; and
//   - every hashed /assets/index-*.{js,css} the index references is itself served 200
//     by the same handler with a sensible content type — i.e. the SPA the browser
//     loads is actually wired, not a dangling reference.
//
// These run by default (no opt-in): the committed embed IS a real build, so on the
// shipped tree they PASS, and they FAIL loudly the moment the embed regresses to the
// placeholder (the pre-fix state). That is the served-vs-library proof the audit
// demands — a test that drills the binary's default served path, not a library proxy.

// servedAssetRef matches a hashed Vite bundle reference in the built index.html, e.g.
// src="/assets/index-pO_Zdefz.js" or href="/assets/index-D6rDP558.css".
var servedAssetRef = regexp.MustCompile(`(?:src|href)="(/assets/index-[A-Za-z0-9_-]+\.(?:js|css))"`)

func servedHandler() http.Handler { return webui.Handler(webui.Assets()) }

func TestServedRootIsTheRealConsoleNotThePlaceholder(t *testing.T) {
	res, body := get(t, servedHandler(), "/")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("GET / Content-Type = %q, want text/html", ct)
	}
	// The dead placeholder says so in plain text; the served console must not.
	if strings.Contains(strings.ToLower(body), "has not been built") {
		t.Fatalf("served / is the 'not built' placeholder — the real React console is NOT embedded (run `make web`) (SURFACE-001):\n%s", body)
	}
	// The real build injects at least one hashed module bundle.
	if !servedAssetRef.MatchString(body) {
		t.Fatalf("served / does not reference a hashed Vite bundle (/assets/index-*.js|css); it is not a real build (SURFACE-001):\n%s", body)
	}
}

func TestServedHashedAssetsResolve(t *testing.T) {
	h := servedHandler()
	_, index := get(t, h, "/")
	matches := servedAssetRef.FindAllStringSubmatch(index, -1)
	if len(matches) == 0 {
		t.Fatal("served index.html references no hashed /assets/index-* bundle (SURFACE-001/006)")
	}
	sawJS := false
	for _, m := range matches {
		assetPath := m[1] // e.g. /assets/index-XXXX.js
		res, body := get(t, h, assetPath)
		if res.StatusCode != http.StatusOK {
			t.Errorf("served index references %q but the handler returns %d for it (dangling bundle) (SURFACE-001/006)", assetPath, res.StatusCode)
			continue
		}
		if len(body) == 0 {
			t.Errorf("served asset %q is empty", assetPath)
		}
		ct := res.Header.Get("Content-Type")
		switch {
		case strings.HasSuffix(assetPath, ".js"):
			sawJS = true
			if !strings.Contains(ct, "javascript") {
				t.Errorf("served %q Content-Type = %q, want javascript", assetPath, ct)
			}
		case strings.HasSuffix(assetPath, ".css"):
			if !strings.Contains(ct, "css") {
				t.Errorf("served %q Content-Type = %q, want css", assetPath, ct)
			}
		}
	}
	if !sawJS {
		t.Error("the served console references no hashed JS module bundle — a real SPA must ship one (SURFACE-001)")
	}
}

// TestServedSPAFallbackOverRealEmbed confirms a deep link (a client-side route) falls
// back to the real built index over the real embed, so browser-refreshing /certificates
// loads the SPA rather than 404ing — exercised against the actual artifact, not a fixture.
func TestServedSPAFallbackOverRealEmbed(t *testing.T) {
	h := servedHandler()
	res, body := get(t, h, "/certificates")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("deep-link GET /certificates = %d, want 200 (SPA fallback)", res.StatusCode)
	}
	if !servedAssetRef.MatchString(body) {
		t.Errorf("SPA fallback did not serve the real built index (no hashed bundle reference)")
	}
	// Sanity: the fallback body must equal what / serves (same index document).
	_, root := get(t, h, "/")
	if body != root {
		t.Errorf("SPA fallback body differs from GET / — fallback is not serving index.html")
	}
}
