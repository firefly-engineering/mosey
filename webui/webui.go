// Package webui holds the static assets served by `mosey web` — the
// browser terminal front-end. Assets are embedded into the binary so
// the gateway ships as a single container with no external file or CDN
// dependency for its own code (xterm.js itself is currently pulled from
// a CDN by index.html; vendoring it is a follow-up).
package webui

import (
	"embed"
	"io/fs"
)

//go:embed all:assets
var assets embed.FS

// FS returns the asset filesystem rooted at the assets directory, ready
// to hand to http.FileServer(http.FS(webui.FS())).
func FS() fs.FS {
	sub, err := fs.Sub(assets, "assets")
	if err != nil {
		// The embed path is a compile-time constant; a failure here is
		// a build-level bug, not a runtime condition.
		panic(err)
	}
	return sub
}
