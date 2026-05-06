// Package protocols exposes the bundled P4 vocabulary as an embed.FS.
// Keeping the embed at the vocabulary's own directory lets every
// consumer (the top-level dsl facade, the vocab loader tests, the
// resolver tests) import it without creating a cycle through the
// dsl package itself.
package protocols

import "embed"

//go:embed *.p4
var FS embed.FS
