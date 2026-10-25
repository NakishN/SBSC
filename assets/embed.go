package assets

import "embed"

// FS contains the rule database and the bundled CFR decompiler.
//
//go:embed rules/*.json tools/cfr.jar
var FS embed.FS
