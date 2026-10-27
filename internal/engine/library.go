package engine

import (
	"path/filepath"
	"regexp"
	"strings"
)

var libraryNameRe = regexp.MustCompile(`(?i)(^|[-_.])(lz4|zstd|snappy|sqlite|jna|netty|guava|gson|kotlin|kotlinx|log4j|slf4j|asm|commons|jackson|okhttp|okio|bcprov|bouncycastle|javafx|openjfx|jogl|lwjgl|protobuf|intellij|fernflower|cfr|procyon|launcher|installer|jdk|jre|gradle|maven|apache|spring|hibernate|tomcat|jetty|scala|groovy|jython|jruby|jansi|winpty|pty4j|leveldb|rocksdb|trove|fastutil|reactor|rxjava|vertx|json|yaml|snakeyaml|slf4j|jul|jcommander|picocli|gson|errorprone|checker|junit|testng|mockito|hamcrest|junixsocket|jna|mixinextras|reflect|lenni|kohlschutter|sqlite-jdbc|authlib|brigadier|datafixerupper|mojang|paper|spigot|bukkit|oshi|jsr305|error_prone|failureaccess|listenablefuture|protobuf|json-simple|disruptor|mysql-connector|snakeyaml|log4j|slf4j|guava|gson|netty|fastutil|asm)([-_.]|$)`)

var libraryPackageRe = regexp.MustCompile(`(?i)^(org/lz4|com/github/luben|org/sqlite|com/sun/jna|net/java/dev/jna|io/netty|com/google/common|com/google/gson|org/apache|org/jetbrains|kotlin/|kotlinx/|org/slf4j|org/log4j|org/objectweb/asm|com/fasterxml|okhttp3|okio|org/bouncycastle|javafx/|org/lwjgl|org/jogl|com/jogamp|com/google/protobuf|org/intellij|org/benf|org/vineflower|org/junit|org/testng|org/mockito|org/hamcrest|com/beust|org/yaml|com/electronwill|net/bytebuddy|org/springframework|org/hibernate|org/eclipse|com/sun/|jdk/|java/|com/kohlschutter|com/llamalad7|net/lenni0451)`)

// isLibraryJar is deliberately conservative: it only tags jars that clearly
// look like ordinary Java libraries (Maven metadata, module-info, or a very
// well-known library name/package) and have no cheat-client/module signals.
func isLibraryJar(ja *jarAnalysis) bool {
	if ja == nil || ja.ClientName != "" || len(ja.Modules) > 0 {
		return false
	}
	// Behavioural/code evidence always wins over a library-looking name.
	for _, f := range ja.Findings {
		if f.Source == "source" || (f.Source == "jar" && f.Category != "client") {
			return false
		}
	}
	root := ja.RootPaths
	if len(root) == 0 {
		root = ja.Paths
	}
	paths := strings.ToLower(strings.Join(root, "\n"))
	meta := strings.ToLower(strings.Join(ja.RootMeta, "\n"))
	_ = meta
	hasModMeta := strings.Contains(paths, "fabric.mod.json") ||
		strings.Contains(paths, "quilt.mod.json") ||
		strings.Contains(paths, "mods.toml") ||
		strings.Contains(paths, "neoforge.mods.toml") ||
		strings.Contains(paths, "mcmod.info")
	maven := strings.Contains(paths, "meta-inf/maven/")
	moduleInfo := strings.Contains(paths, "module-info.class")
	// A native loader is not a library, even if it carries Maven metadata.
	if strings.Contains(strings.ToLower(strings.Join(ja.Meta, "\n")), "main-class:") {
		for _, n := range ja.Natives {
			if n.Size > 5<<20 {
				return false
			}
		}
	}
	name := strings.ToLower(strings.TrimSuffix(filepath.Base(ja.Name), filepath.Ext(ja.Name)))
	nameHit := libraryNameRe.MatchString(name)
	pkgHit := false
	for _, c := range ja.Tokens.Classes {
		if libraryPackageRe.MatchString(strings.ToLower(c)) {
			pkgHit = true
			break
		}
	}
	if hasModMeta {
		// Well-known mod-loader/library mods are not cheat clients. Scanning
		// them only slows down the analysis and produces noise.
		for _, p := range []string{"fabric-api", "fabric_api", "fabric-language-kotlin", "quilted-fabric-api", "architectury", "cloth-config", "geckolib", "citresewn", "fabric-loader", "mixinextras"} {
			if strings.Contains(name, p) {
				return true
			}
		}
		return false
	}
	if maven || moduleInfo {
		return true
	}
	if nameHit && pkgHit {
		return true
	}
	if nameHit && len(ja.Classes) > 0 && !strings.Contains(strings.ToLower(ja.Tokens.Classes[0]), "net/minecraft") {
		return true
	}
	return false
}

func markLibraryResult(res *ScanResult, ja *jarAnalysis) {
	res.Verdict = "БИБЛИОТЕКА"
	res.Proof = "clean"
	res.Risk = 0
	res.Confidence = 95
	res.Categories = []CategoryScore{{Category: "trusted", Label: categoryLabel("trusted"), Score: 0}}
	res.Findings = nil
	res.Modules = nil
	res.Natives = nil
	res.Notes = append(res.Notes,
		"похоже на обычную Java-библиотеку, а не Minecraft-мод",
		"проверка читов для библиотек не требуется (--scan-libraries для принудительного скана)")
}
