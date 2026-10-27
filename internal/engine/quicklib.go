package engine

import (
	"archive/zip"
	"bytes"
	"io"
	"path/filepath"
	"strings"
)

// quickLibraryJar avoids parsing thousands of classes for obvious launcher
// dependencies (fabric-api, Kotlin runtime, Maven libs). It only skips a jar
// when the archive itself proves it is a library (Maven metadata or
// module-info). A library-looking file name is not enough: a cheat renamed to
// guava-x.jar must still be analysed.
func quickLibraryJar(path string, data []byte) (bool, string) {
	name := strings.ToLower(strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)))
	nameHint := ""
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
			nameHint = p
			break
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
	agent := false
	maxDLL := uint64(0)
	suspicious := false
	terms := []string{
		"killaura", "kill_aura", "aimbot", "aimassist", "reachhack", "scaffold",
		"nuker", "cheststealer", "crystalaura", "autototem", "antiknockback",
		"velocity", "nofall", "xray", "freecam",
	}
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
				low := strings.ToLower(string(b))
				if strings.Contains(low, "main-class:") {
					mainClass = true
				}
				if strings.Contains(low, "premain-class:") || strings.Contains(low, "agent-class:") {
					agent = true
				}
			}
		}
		for _, t := range terms {
			if strings.Contains(n, t) {
				suspicious = true
				break
			}
		}
		if strings.HasSuffix(n, ".dll") && f.UncompressedSize64 > maxDLL {
			maxDLL = f.UncompressedSize64
		}
	}
	// A Minecraft mod (even a library mod) is scanned: metadata is exactly
	// what a renamed cheat can carry.
	if hasMod || agent {
		return false, ""
	}
	// A loader that maps a big native payload into Minecraft is not a library.
	if mainClass && maxDLL > 5<<20 {
		return false, ""
	}
	if suspicious {
		return false, ""
	}
	if maven || moduleInfo {
		if nameHint != "" {
			return true, "Maven/module-info JAR с библиотечным именем: " + nameHint
		}
		return true, "Maven/module-info JAR без Minecraft-метаданных"
	}
	return false, ""
}
