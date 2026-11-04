// SPDX-License-Identifier: BUSL-1.1

package registry

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Served is one file the registry handed out.
type Served struct {
	Path   string
	Status int
}

// Handler serves dir as four local registries:
//
//	/go/     the Go module proxy protocol (GOPROXY=<base>/go)
//	/npm/    an npm registry (npm --registry <base>/npm/)
//	/pypi/   a PEP 503 simple index (pip --index-url <base>/pypi/simple/)
//	/maven/  a Maven 2 repository
//
// Seen, when set, hears every request and its status.
type Handler struct {
	Dir  string
	Seen func(Served)
	once sync.Once
	fs   http.Handler
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.once.Do(func() { h.fs = http.FileServer(http.Dir(h.Dir)) })
	sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
	if h.Seen != nil {
		defer func() { h.Seen(Served{Path: r.URL.Path, Status: sw.status}) }()
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(sw, "a local registry is read-only", http.StatusMethodNotAllowed)
		return
	}
	switch {
	case strings.HasPrefix(r.URL.Path, "/npm/") && !strings.HasPrefix(r.URL.Path, "/npm/tarballs/"):
		h.packument(sw, r)
	case strings.HasPrefix(r.URL.Path, "/go/"), strings.HasPrefix(r.URL.Path, "/npm/tarballs/"),
		strings.HasPrefix(r.URL.Path, "/pypi/"), strings.HasPrefix(r.URL.Path, "/maven/"):
		h.fs.ServeHTTP(sw, r)
	default:
		http.NotFound(sw, r)
	}
}

// packument serves an npm package's registry document, its tarball
// addresses made absolute against the address the client used.
func (h *Handler) packument(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/npm/")
	if name == "" || strings.Contains(name, "..") {
		http.NotFound(w, r)
		return
	}
	raw, err := os.ReadFile(filepath.Join(h.Dir, "npm", "meta", url2file(name)+".json")) // #nosec G304 G703 -- a fixed directory and an escaped package name with no parent references (CWE-22)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	var doc struct {
		Name     string                    `json:"name"`
		DistTags map[string]string         `json:"dist-tags"`
		Versions map[string]map[string]any `json:"versions"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		http.Error(w, "bad package document", http.StatusInternalServerError)
		return
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	for _, v := range doc.Versions {
		if dist, ok := v["dist"].(map[string]any); ok {
			if tarball, ok := dist["tarball"].(string); ok && !strings.Contains(tarball, "://") {
				dist["tarball"] = scheme + "://" + r.Host + "/npm/" + tarball
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"name": doc.Name, "dist-tags": doc.DistTags, "versions": doc.Versions})
}
