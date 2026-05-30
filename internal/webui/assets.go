package webui

import (
	"embed"
	"io/fs"
)

// distFS holds the built UI. The real assets are produced by `make web` (Vite)
// into dist/; a committed placeholder index.html keeps the embed valid and the
// binary serving something even before a build.
//
//go:embed all:dist
var distFS embed.FS

// Assets returns the embedded built UI, rooted at dist/.
func Assets() fs.FS {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		panic("webui: dist not embedded: " + err.Error()) // embedded at build time
	}
	return sub
}
