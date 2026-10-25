package engine

import (
	"archive/zip"
	"bytes"
	"strings"
)

// archiveKind quickly classifies a zip/jar without parsing classes.
func archiveKind(data []byte) (classes int, modMeta bool, nestedJars int) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return 0, false, 0
	}
	for i, f := range zr.File {
		if i > 20000 {
			break
		}
		n := strings.ToLower(strings.ReplaceAll(f.Name, "\\", "/"))
		switch {
		case strings.HasSuffix(n, ".class"):
			classes++
		case strings.HasSuffix(n, ".jar"):
			nestedJars++
		case n == "fabric.mod.json" || n == "quilt.mod.json" || n == "mods.toml" || n == "neoforge.mods.toml" || n == "mcmod.info":
			modMeta = true
		}
	}
	return
}
