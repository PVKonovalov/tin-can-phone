// Package web holds the static client files embedded into the binary.
package web

import "embed"

// FS contains the client files. index.html is an html/template.
//
//go:embed index.html style.css
var FS embed.FS
