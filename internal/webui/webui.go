// SPDX-License-Identifier: MPL-2.0

// Package webui serves trstctl's single-page web application (F12) from assets
// embedded in the binary. Real asset files are served with their content type;
// any other non-API path falls back to index.html so the client-side router can
// own deep links. Paths under /api are left unhandled so the API handler owns
// them when the two are composed.
package webui

import (
	"bytes"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"
)

// Handler serves the SPA from the given asset filesystem.
func Handler(assets fs.FS) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := path.Clean(r.URL.Path)
		if clean == "/openapi.json" {
			http.Redirect(w, r, "/api/v1/openapi.json", http.StatusPermanentRedirect)
			return
		}
		if clean == "/api" || strings.HasPrefix(clean, "/api/") {
			http.NotFound(w, r) // belongs to the API handler
			return
		}
		name := strings.TrimPrefix(clean, "/")
		if name == "" || name == "." {
			serveFile(w, r, assets, "index.html")
			return
		}
		if serveFile(w, r, assets, name) {
			return
		}
		if looksLikeAssetRequest(name) {
			http.NotFound(w, r)
			return
		}
		serveFile(w, r, assets, "index.html") // SPA fallback
	})
}

func looksLikeAssetRequest(name string) bool {
	switch strings.ToLower(path.Ext(name)) {
	case ".css", ".gif", ".ico", ".jpeg", ".jpg", ".js", ".json", ".map", ".mjs", ".png", ".svg", ".txt", ".webmanifest", ".woff", ".woff2", ".xml", ".yaml", ".yml":
		return true
	default:
		return false
	}
}

// serveFile serves a named asset and reports whether it existed. A missing
// asset other than index.html writes nothing (so the caller can fall back); a
// missing index.html writes a 404.
func serveFile(w http.ResponseWriter, r *http.Request, assets fs.FS, name string) bool {
	f, err := assets.Open(name)
	if err != nil {
		if name == "index.html" {
			http.NotFound(w, r)
		}
		return false
	}
	defer func() { _ = f.Close() }()

	stat, err := f.Stat()
	if err != nil || stat.IsDir() {
		if name == "index.html" {
			http.NotFound(w, r)
		}
		return false
	}
	data, err := io.ReadAll(f)
	if err != nil {
		http.Error(w, "read asset", http.StatusInternalServerError)
		return true
	}
	var mt time.Time
	if stat != nil {
		mt = stat.ModTime()
	}
	http.ServeContent(w, r, name, mt, bytes.NewReader(data))
	return true
}
