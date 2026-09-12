// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	_ "embed"
	"net/http"
)

// Embedded, so the binary really is the whole program: one file to copy to a
// server, with nothing next to it to forget.
//
//go:embed panel.html
var panelHTML []byte

func (s *server) handlePanel(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	// The panel is one page that asks for the password itself, so it is served
	// to anyone: there is nothing in it. Everything it can DO is behind the
	// session cookie.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy",
		// img-src 'self' and nothing else: the map is served by THIS server,
		// already assembled (see map.go), so nothing external is still loaded.
		"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "+
			"connect-src 'self'; img-src 'self'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(panelHTML)
}
