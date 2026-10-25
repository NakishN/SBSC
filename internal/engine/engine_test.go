package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
