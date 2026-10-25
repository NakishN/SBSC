package engine

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func normPath(p string) string {
	p = filepath.ToSlash(strings.TrimSpace(p))
	return strings.ToLower(p)
}

func systemRoots() []string {
	var roots []string
	add := func(s string) {
		if s == "" {
			return
		}
		roots = append(roots, strings.TrimRight(normPath(s), "/"))
	}
	if runtime.GOOS == "windows" {
		for _, k := range []string{"SystemRoot", "windir"} {
			add(os.Getenv(k))
			add(os.Getenv(k) + "/System32")
			add(os.Getenv(k) + "/SysWOW64")
			add(os.Getenv(k) + "/WinSxS")
		}
		add(os.Getenv("ProgramFiles") + "/WindowsApps")
		add(os.Getenv("ProgramData") + "/Microsoft/Windows")
		add("C:/Windows")
		add("C:/Windows/System32")
		add("C:/Windows/SysWOW64")
		add("C:/Windows/WinSxS")
		add("C:/Program Files/WindowsApps")
		add("C:/ProgramData/Microsoft/Windows")
		add("C:/$Recycle.Bin")
		add("C:/System Volume Information")
	}
	add(os.Getenv("JAVA_HOME"))
	add(os.Getenv("LOCALAPPDATA") + "/SBSC")
	add(os.Getenv("LOCALAPPDATA") + "/MCCheatScanner")
	for _, k := range []string{"APPDATA", "HOME", "USERPROFILE"} {
		base := os.Getenv(k)
		if base == "" {
			continue
		}
		add(base + "/.minecraft/runtime")
		add(base + "/.minecraft/libraries")
		add(base + "/.minecraft/versions")
		add(base + "/.minecraft/assets")
		add(base + "/.minecraft/natives")
		add(base + "/.minecraft/logs")
		add(base + "/.minecraft/saves")
		add(base + "/.minecraft/backups")
		add(base + "/.minecraft/crash-reports")
	}
	if runtime.GOOS != "windows" {
		roots = append(roots, "/usr/lib", "/usr/lib64", "/usr/share/java", "/lib", "/lib64", "/system", "/library")
	}
	return roots
}

func pathUnder(p string, roots []string) bool {
	p = strings.TrimRight(normPath(p), "/")
	for _, r := range roots {
		r = strings.TrimRight(r, "/")
		if r == "" {
			continue
		}
		if p == r || strings.HasPrefix(p, r+"/") {
			return true
		}
	}
	return false
}

// isIgnoredPath reports whether a directory/file belongs to an OS/Java runtime
// area that should not be scanned by default.
func isIgnoredPath(p string) bool {
	return isSystemPath(p) || pathUnder(p, systemRoots())
}

// isSystemPath marks trusted runtime locations even when explicitly scanned.
func isSystemPath(p string) bool {
	n := normPath(p)
	if pathUnder(n, systemRoots()) {
		return true
	}
	// Minecraft launcher runtime and Maven libraries, even with custom roots.
	for _, marker := range []string{
		"/.minecraft/runtime/", "/.minecraft/libraries/", "/.minecraft/versions/",
		"/.minecraft/assets/", "/.minecraft/natives/", "/.minecraft/logs/", "/.minecraft/saves/",
		"/runtime/", "/jre", "/jdk", "/jbr/", "/java/", "/openjdk/",
		"/temurin/", "/corretto/", "/zulu/", "/graalvm/", "/liberica/", "/semeru/",
		"/sbsc/", "/mccheatscanner/",
		"/assets/", "/versions/", "/natives/",
		"/.fabric/", "/.quilt/", "/remappedjars/", "/processedmods/",
		"/backup/", "/backups/",
		"/common files/system/", "/common files/microsoft shared/",
		"/internet explorer/", "/windows media player/", "/windows nt/",
		"/windows defender/", "/windows mail/", "/microsoft.net/", "/dotnet/",
	} {
		if strings.Contains(n, marker) {
			return true
		}
	}
	if strings.Contains(n, "/windows/system32/") || strings.Contains(n, "/windows/syswow64/") || strings.Contains(n, "/windows/winsxs/") {
		return true
	}
	// Launcher library folders: only trust them when they are clearly part of
	// an installed launcher/Java runtime, not a user's "mods/../libraries".
	if strings.Contains(n, "/libraries/") && (strings.Contains(n, "/.minecraft/") || strings.Contains(n, "/appdata/") || strings.Contains(n, "/program files/")) {
		return true
	}
	return false
}
