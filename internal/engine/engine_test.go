package engine

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sbsc/assets"
)

func TestCodeFirstVerdict(t *testing.T) {
	// Known path/name alone must not be a cheat verdict.
	ja := &jarAnalysis{
		Name: "KnownCheat.jar",
		Findings: []Finding{{
			RuleID: "known_test", Title: "KnownCheat", Category: "client",
			Severity: 5, Weight: 90, Source: "known",
		}},
	}
	risk, _, verdict, _ := scoreJar(ja)
	if ja.CodeScore != 0 || ja.ContextScore == 0 {
		t.Fatalf("expected context-only: code=%d context=%d", ja.CodeScore, ja.ContextScore)
	}
	if verdict == "ЧИТ-КЛИЕНТ" {
		t.Fatalf("known-only match must not be a cheat verdict: %s (risk %d)", verdict, risk)
	}

	// Code evidence plus context is a cheat verdict.
	ja.Findings = append(ja.Findings, Finding{
		RuleID: "src_killaura", Title: "KillAura", Category: "combat",
		Severity: 5, Weight: 32, Source: "source",
	})
	risk, _, verdict, _ = scoreJar(ja)
	if verdict != "ЧИТ-КЛИЕНТ" {
		t.Fatalf("code+context should be cheat, got %s (risk %d, code %d)", verdict, risk, ja.CodeScore)
	}
}

func TestAnalyzeDecompiledSources(t *testing.T) {
	dir := t.TempDir()
	src := `package cheat;
import java.util.List;
public class KillAuraModule {
  List<Object> getEntities(){ return null; }
  double getDistance(Object o){ return 0; }
  void setYaw(float y){}
  void setPitch(float p){}
  void attackEntity(Object o){}
  public void onUpdate(){
    for (Object e : getEntities()) {
      if (getDistance(e) < 6.0) {
        setYaw((float)Math.toDegrees(Math.atan2(1.0, 2.0)));
        setPitch(0.0f);
        attackEntity(e);
      }
    }
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "KillAuraModule.java"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, _ := analyzeDecompiledSources(dir)
	found := false
	for _, f := range findings {
		if f.RuleID == "src_killaura" {
			found = true
			if f.File == "" || f.Line == 0 || f.Snippet == "" {
				t.Fatalf("source finding must include file/line/snippet: %+v", f)
			}
		}
	}
	if !found {
		t.Fatalf("src_killaura not detected: %+v", findings)
	}
}

func TestUnlimitedFileCollection(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.jar", "b.jar", "c.jar"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	files, truncated, err := collectFiles([]string{dir}, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if truncated || len(files) != 3 {
		t.Fatalf("unlimited scan: files=%d truncated=%v", len(files), truncated)
	}
	files, truncated, err = collectFiles([]string{dir}, false, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !truncated || len(files) != 2 {
		t.Fatalf("limited scan: files=%d truncated=%v", len(files), truncated)
	}
}

func TestDriveRootDetection(t *testing.T) {
	if !isDriveRoot("/") || !isDriveRoot(`C:\`) || !isDriveRoot("D:/") || !isDriveRoot("C:") {
		t.Fatal("drive roots must be recognized")
	}
	if isDriveRoot("/home/user") || isDriveRoot(`C:\Users`) {
		t.Fatal("ordinary folders must not be treated as drive roots")
	}
	if !hasDriveRoot([]string{"/home/user", "/"}) || hasDriveRoot([]string{"/home/user"}) {
		t.Fatal("hasDriveRoot returned a wrong result")
	}
}

func TestPreferredDirs(t *testing.T) {
	root := t.TempDir()
	mustMkdir := func(p string) {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	downloads := filepath.Join(root, "Users", "alice", "Downloads")
	mc := filepath.Join(root, "Users", "alice", ".minecraft")
	games := filepath.Join(root, "Games")
	mustMkdir(downloads)
	mustMkdir(mc)
	mustMkdir(games)
	dirs := preferredDirs(root)
	if len(dirs) == 0 {
		t.Fatal("preferredDirs returned nothing")
	}
	if !strings.HasSuffix(dirs[0], "Downloads") {
		t.Fatalf("Downloads must be scanned first, got %v", dirs)
	}
	seen := map[string]bool{}
	for _, d := range dirs {
		seen[strings.ToLower(d)] = true
	}
	if !seen[strings.ToLower(mc)] || !seen[strings.ToLower(games)] {
		t.Fatalf("expected .minecraft and Games in %v", dirs)
	}
}

func TestSystemAndLauncherPaths(t *testing.T) {
	if !isSystemPath("/tmp/winroot/windows/system32/version.dll") {
		t.Fatal("windows/system32 must be a system path")
	}
	if isSystemPath("/tmp/opencode/launcher/mods/Cheat.jar") {
		t.Fatal("launcher mods must not be treated as a system path")
	}
	if isSystemPath("/home/user/.minecraft/mods/Cheat.jar") {
		t.Fatal("minecraft mods must not be treated as a system path")
	}
	if !isSystemPath("/home/user/.minecraft/libraries/foo/bar.jar") {
		t.Fatal("minecraft libraries must be a system path")
	}
}

func TestStrongKnownPath(t *testing.T) {
	if !strongKnownPath("net/wurstclient/wurstclient.class") {
		t.Fatal("package path should be strong")
	}
	if strongKnownPath("clientplayerinteractionmanagermixin.class") {
		t.Fatal("bare class name must not be strong")
	}
}

func TestHitboxCodeVsVisual(t *testing.T) {
	dir := t.TempDir()
	visual := `package visual;
import net.minecraft.entity.Entity;
public class HitBoxRenderMixin {
  public void render(Entity e) {
    Object box = e.getBoundingBox();
    e.getBoundingBox().expand(0.5, 0.5, 0.5);
  }
}`
	cheat := `package combat;
public class HitBox extends Module {
  public double determineSize(Entity e) {
    return 0.4D;
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "HitBoxRenderMixin.java"), []byte(visual), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "HitBox.java"), []byte(cheat), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, _ := analyzeDecompiledSources(dir)
	var visualHit, cheatHit bool
	for _, f := range findings {
		if f.RuleID == "src_hitbox_expand" && strings.Contains(f.Class, "HitBoxRenderMixin") {
			visualHit = true
		}
		if f.RuleID == "src_hitbox_module" && strings.Contains(f.Class, "HitBox") {
			cheatHit = true
		}
	}
	if visualHit {
		t.Fatal("visual hitbox renderer must not be flagged as hitbox expansion")
	}
	if !cheatHit {
		t.Fatalf("HitBox.determineSize not detected: %+v", findings)
	}
}

func writeTestZip(t *testing.T, path string, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestQuickLibraryDoesNotSkipRenamedMod(t *testing.T) {
	dir := t.TempDir()
	mod := filepath.Join(dir, "guava-totally-legit.jar")
	data := writeTestZip(t, mod, map[string]string{
		"fabric.mod.json":      `{"id":"totally-legit","version":"1.0.0"}`,
		"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\n",
	})
	if lib, why := quickLibraryJar(mod, data); lib {
		t.Fatalf("renamed Minecraft mod must not be skipped as a library: %s", why)
	}

	lib := filepath.Join(dir, "guava-31.jar")
	data = writeTestZip(t, lib, map[string]string{
		"META-INF/maven/com.google.guava/guava/pom.properties": "version=31\n",
	})
	if ok, _ := quickLibraryJar(lib, data); !ok {
		t.Fatal("a Maven JAR without mod metadata should still be recognized as a library")
	}
}

func TestCollectFilesSniffsDisguisedArchive(t *testing.T) {
	dir := t.TempDir()
	writeTestZip(t, filepath.Join(dir, "harmless.dat"), map[string]string{
		"fabric.mod.json": `{"id":"test","version":"1"}`,
	})
	files, _, err := collectFilesOpts([]string{dir}, false, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || !strings.HasSuffix(files[0], "harmless.dat") {
		t.Fatalf("disguised archive was not discovered: %v", files)
	}
	files, _, err = collectFilesOpts([]string{dir}, false, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Fatalf("sniffing disabled must keep the extension filter: %v", files)
	}
}

func TestScanFileDisguisedJar(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "harmless.dat")
	writeTestZip(t, p, map[string]string{
		"fabric.mod.json": `{"id":"test","version":"1"}`,
	})
	eng, err := New(Options{OutDir: t.TempDir(), Decompile: false, Deep: false, ScanNatives: true})
	if err != nil {
		t.Fatal(err)
	}
	res := eng.ScanFile(p)
	if res.Error != "" {
		t.Fatalf("disguised jar failed: %s", res.Error)
	}
	if res.Kind != "jar" {
		t.Fatalf("kind = %q, want jar (detected by magic bytes)", res.Kind)
	}
	if !strings.Contains(strings.Join(res.Notes, " "), "по содержимому") {
		t.Fatalf("expected a content-sniff note, got %v", res.Notes)
	}
}

func TestXrayDetectorIgnoresBlockSearch(t *testing.T) {
	dir := t.TempDir()
	lithium := `package net.caffeinemc.mods.lithium.common.world.block_pattern_matching;
public class BlockSearch {
  public static int countBlocksInBoxInSection(Object section, Object requiredBlock) {
    for (int y = 0; y < 16; y++) {
      Object state = section.getBlockState(0, y, 0);
      if (state.isOpaque() && state == requiredBlock) {
        return 1;
      }
    }
    return 0;
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "BlockSearch.java"), []byte(lithium), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, _ := analyzeDecompiledSources(dir)
	for _, f := range findings {
		if f.RuleID == "src_xray" {
			t.Fatalf("block-search optimisation must not be flagged as X-Ray: %+v", f)
		}
	}

	real := `package cheat;
public class XRayMixin {
  public boolean shouldDrawSide(Object state) {
    Object s = world.getBlockState(pos);
    return s.isOpaque() && !s.isAir();
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "XRayMixin.java"), []byte(real), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, _ = analyzeDecompiledSources(dir)
	found := false
	for _, f := range findings {
		if f.RuleID == "src_xray" {
			found = true
		}
	}
	if !found {
		t.Fatalf("real X-Ray render override not detected: %+v", findings)
	}
}

func TestObfuscatedCleanIsSuspicious(t *testing.T) {
	ja := &jarAnalysis{Obfuscation: 22, ClassCount: 100}
	risk, _, verdict, _ := scoreJar(ja)
	if verdict != "ПОДОЗРИТЕЛЬНО" {
		t.Fatalf("obfuscated archive must not be clean, got %s", verdict)
	}
	if risk < 30 {
		t.Fatalf("obfuscated archive risk = %d, want >= 30", risk)
	}
	if ja.Proof != "insufficient" {
		t.Fatalf("proof = %q, want insufficient", ja.Proof)
	}
}

func TestConditionHintsAreSound(t *testing.T) {
	rules, err := LoadRules(assets.FS)
	if err != nil {
		t.Fatal(err)
	}
	tokens := []string{
		"render", "range", "search", "opaque", "native", "packet", "c0", "aim", "fly",
		"attack", "look", "yaw", "pitch", "timer", "tick", "world", "entity", "chest",
		"click", "mouse", "target", "bypass", "flag", "exploit", "hack", "cheat", "inject",
		"payload", "class_2881", "Mixin", "Inject", "System.load", "loadLibrary", "Runtime.load",
		"ServerCrasher", "ForceOp", "C03PacketPlayer", "getBlockState", "shouldDrawSide",
		"isOpaque", "hitbox", "reach", "aura", "killaura", "aimbot", "velocity", "antiknockback",
		"scaffold", "nuker", "xray", "blockesp", "esp", "tracer", "chams", "wallhack",
		"autoclicker", "triggerbot", "cheststealer", "nofall", "antiaim", "backtrack",
		"onnxruntime", "catboost", "NeuroModel", "RotationPredictor", "Premain-Class",
		"determineSize", "getReachDistance", "net/minecraft/util/math/Box", "class_238",
	}
	var hints []string
	allRules := append(append([]*CompiledRule{}, rules.Clients...), rules.Behaviors...)
	allRules = append(allRules, rules.Native...)
	for _, r := range allRules {
		for _, group := range [][]compiledCond{r.all, r.any, r.none} {
			for _, c := range group {
				hints = append(hints, c.hints...)
			}
		}
	}
	for _, h := range hints {
		tokens = append(tokens, h, "x"+h+"x")
	}
	for _, r := range allRules {
		for _, group := range [][]compiledCond{r.all, r.any, r.none} {
			for _, c := range group {
				ts := &TokenSet{
					Classes: tokens, ClassSimple: tokens, Strings: tokens, Methods: tokens,
					Fields: tokens, Refs: tokens, Paths: tokens, Meta: tokens, DLLStrings: tokens,
				}
				ts.buildAll()
				got := matchCond(c, ts)
				want := false
				for _, tok := range tokensFor(c.typ, ts) {
					if c.re.MatchString(tok) {
						want = true
						break
					}
				}
				if want && len(got) == 0 {
					t.Fatalf("hint prefilter lost a match for rule %s condition %q (hints %v)", r.ID, c.re.String(), c.hints)
				}
			}
		}
	}
}

func TestLiteralHints(t *testing.T) {
	if hints := literalHints("(?i)(xray|blockesp)"); len(hints) != 2 {
		t.Fatalf("simple alternation hints = %v", hints)
	}
	if hints := literalHints("(?i)(C0[0-9]|Packet)"); hints != nil {
		t.Fatalf("character class must not produce hints, got %v", hints)
	}
	if hints := literalHints(`(?i)(System\.load|loadLibrary)`); len(hints) != 2 {
		t.Fatalf("escaped dot hints = %v", hints)
	}
	if hints := literalHints(`(?i)(foo\s+bar)`); hints != nil {
		t.Fatalf("whitespace class must not produce hints, got %v", hints)
	}
}

func TestParallelScanKeepsOrder(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.jar", "b.jar", "c.jar", "d.jar"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("not a zip"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	eng, err := New(Options{OutDir: t.TempDir(), Workers: 4, Decompile: false, Deep: false})
	if err != nil {
		t.Fatal(err)
	}
	results, err := eng.ScanPaths([]string{dir}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 4 {
		t.Fatalf("got %d results, want 4", len(results))
	}
	for i, want := range []string{"a.jar", "b.jar", "c.jar", "d.jar"} {
		if results[i].Name != want {
			t.Fatalf("result %d = %s, want %s", i, results[i].Name, want)
		}
	}
}

func TestHintMatcher(t *testing.T) {
	m := newHintMatcher([]string{"killaura", "blockesp", "xray"})
	if !m.Match("net/cheat/KillAuraModule") || !m.Match("BlockESP") || !m.Match("xray") {
		t.Fatal("hint matcher missed a literal")
	}
	if m.Match("clean/render/entity") {
		t.Fatal("hint matcher false positive")
	}
	// Overlapping suffixes exercise failure links.
	m = newHintMatcher([]string{"abcd", "bc"})
	if !m.Match("zbc") || !m.Match("abcd") {
		t.Fatal("failure-link matching failed")
	}
	if m.Match("abx") {
		t.Fatal("failure-link false positive")
	}
}
