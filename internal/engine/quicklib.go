package engine

import (
	"archive/zip"
	"bytes"
	"io"
	"path/filepath"
	"strings"
)

// quickLibraryJar avoids parsing thousands of classes for obvious launcher
// dependencies (fabric-api, Kotlin runtime, Maven libs). It only looks at the
// ZIP entry names.
func quickLibraryJar(path string, data []byte) (bool, string) {
	name := strings.ToLower(strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)))
	for _, p := range []string{
		"fabric-api", "fabric_api", "fabric-language-kotlin", "quilted-fabric-api", "architectury", "cloth-config",
		"geckolib", "citresewn", "fabric-loader", "mojang", "authlib", "brigadier", "datafixerupper",
		"logging", "netty", "oshi", "jsr305", "error_prone", "failureaccess", "listenablefuture",
		"protobuf", "json-simple", "disruptor", "mysql-connector", "snakeyaml", "log4j", "slf4j",
		"guava", "gson", "asm", "kotlin", "fastutil", "commons-", "httpclient", "httpcore",
		"jackson", "adventure", "examination", "checker-qual", "auto-service", "junit", "mockito",
		"byte-buddy", "classgraph", "reflections", "javassist", "paper", "spigot", "bukkit", "purpur",
	} {
		if strings.Contains(name, p) {
			return true, "известный библиотечный мод: " + p
		}
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return false, ""
	}
	hasMod := false
	maven := false
	moduleInfo := false
	mainClass := false
	maxDLL := uint64(0)
	for i, f := range zr.File {
		if i > 5000 {
			break
		}
		n := strings.ToLower(strings.ReplaceAll(f.Name, "\\", "/"))
		switch {
		case n == "fabric.mod.json" || n == "quilt.mod.json" || n == "mods.toml" || n == "neoforge.mods.toml" || n == "mcmod.info":
			hasMod = true
		case strings.HasPrefix(n, "meta-inf/maven/"):
			maven = true
		case n == "module-info.class":
			moduleInfo = true
		case n == "meta-inf/manifest.mf":
			if rc, err := f.Open(); err == nil {
				b, _ := io.ReadAll(io.LimitReader(rc, 64<<10))
				rc.Close()
				if strings.Contains(strings.ToLower(string(b)), "main-class:") {
					mainClass = true
				}
			}
		}
		if strings.HasSuffix(n, ".dll") && f.UncompressedSize64 > maxDLL {
			maxDLL = f.UncompressedSize64
		}
	}
	// A loader that maps a big native payload into Minecraft is not a library.
	if mainClass && maxDLL > 5<<20 {
		return false, ""
	}
	if !hasMod && (maven || moduleInfo) {
		return true, "Maven/module-info JAR без Minecraft-метаданных"
	}
	return false, ""
}
