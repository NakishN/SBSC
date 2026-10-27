package engine

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"sbsc/assets"
)

type Decompiler struct {
	mu       sync.Mutex
	JavaPath string
	JavaVer  string
	CFRPath  string
	WorkDir  string
}

func NewDecompiler(opts Options) *Decompiler {
	work := opts.OutDir
	if work == "" {
		work = filepath.Join(os.TempDir(), "sbsc")
	}
	return &Decompiler{WorkDir: work}
}

// FindJava locates a Java runtime. Minecraft 1.16.5 ships Java 8, and CFR
// supports Java 8+, so almost any installed JVM works.
func (d *Decompiler) FindJava(override string) (string, string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var candidates []string
	if override != "" {
		candidates = append(candidates, override)
	}
	if exe, err := os.Executable(); err == nil {
		base := filepath.Dir(exe)
		for _, rel := range []string{"jre8/bin/java.exe", "jre/bin/java.exe"} {
			p := filepath.Join(base, filepath.FromSlash(rel))
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				candidates = append(candidates, preferWorker(p))
			}
		}
	}
	if runtime.GOOS == "windows" {
		if p, err := ensureBundledJRE(); err == nil {
			candidates = append(candidates, p)
		}
	}
	if jh := os.Getenv("JAVA_HOME"); jh != "" {
		candidates = append(candidates, filepath.Join(jh, "bin", javaExe()))
	}
	if p, err := exec.LookPath(javaExe()); err == nil {
		candidates = append(candidates, p)
	}
	if runtime.GOOS == "windows" {
		appData := os.Getenv("APPDATA")
		local := os.Getenv("LOCALAPPDATA")
		progFiles := os.Getenv("ProgramFiles")
		progFilesX86 := os.Getenv("ProgramFiles(x86)")
		globs := []string{
			filepath.Join(appData, ".minecraft", "runtime", "*", "*", "bin", "java.exe"),
			filepath.Join(appData, ".minecraft", "runtime", "*", "bin", "java.exe"),
			filepath.Join(local, "Programs", "Eclipse Adoptium", "*", "bin", "java.exe"),
			filepath.Join(local, "Programs", "Java", "*", "bin", "java.exe"),
			filepath.Join(progFiles, "Java", "*", "bin", "java.exe"),
			filepath.Join(progFiles, "Eclipse Adoptium", "*", "bin", "java.exe"),
			filepath.Join(progFiles, "BellSoft", "*", "bin", "java.exe"),
			filepath.Join(progFiles, "Zulu", "*", "bin", "java.exe"),
			filepath.Join(progFilesX86, "Java", "*", "bin", "java.exe"),
			filepath.Join(local, "Programs", "Microsoft", "jdk-*", "bin", "java.exe"),
		}
		for _, g := range globs {
			if m, _ := filepath.Glob(g); len(m) > 0 {
				sort.Sort(sort.Reverse(sort.StringSlice(m)))
				candidates = append(candidates, m...)
			}
		}
	} else {
		globs := []string{
			"/usr/lib/jvm/*/bin/java",
			"/usr/java/*/bin/java",
			"/opt/java/*/bin/java",
			filepath.Join(os.Getenv("HOME"), ".sdkman", "candidates", "java", "*", "bin", "java"),
		}
		for _, g := range globs {
			if m, _ := filepath.Glob(g); len(m) > 0 {
				sort.Sort(sort.Reverse(sort.StringSlice(m)))
				candidates = append(candidates, m...)
			}
		}
	}
	seen := map[string]bool{}
	for _, c := range candidates {
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		if st, err := os.Stat(c); err != nil || st.IsDir() {
			continue
		}
		if v, err := javaVersion(c); err == nil {
			d.JavaPath = c
			d.JavaVer = v
			return c, v, nil
		}
	}
	return "", "", fmt.Errorf("Java не найдена. Установите Java 8+ или укажите путь в настройках")
}

var (
	jreOnce sync.Once
	jrePath string
	jreErr  error
)

// ensureBundledJRE extracts the embedded Temurin JRE 8 on first use. The user
// only downloads the scanner executable; no Java installation or extra files
// are required.
func ensureBundledJRE() (string, error) {
	if runtime.GOOS != "windows" || len(assets.JREZip) == 0 {
		return "", fmt.Errorf("встроенная Java недоступна")
	}
	jreOnce.Do(func() {
		cacheRoot := os.Getenv("LOCALAPPDATA")
		if cacheRoot == "" {
			cacheRoot = os.Getenv("TEMP")
		}
		if cacheRoot == "" {
			cacheRoot = os.TempDir()
		}
		cacheRoot = filepath.Join(cacheRoot, "SBSC")
		jreDir := filepath.Join(cacheRoot, "jre8")
		java := filepath.Join(jreDir, "bin", "java.exe")
		if st, err := os.Stat(java); err == nil && st.Size() > 0 {
			jrePath = preferWorker(java)
			return
		}
		if err := os.MkdirAll(cacheRoot, 0o755); err != nil {
			jreErr = err
			return
		}
		tmp := jreDir + ".tmp"
		_ = os.RemoveAll(tmp)
		if err := extractJRE(assets.JREZip, tmp); err != nil {
			jreErr = err
			return
		}
		_ = os.RemoveAll(jreDir)
		if err := os.Rename(tmp, jreDir); err != nil {
			// Antivirus may hold files; fall back to the temp directory.
			jreDir = tmp
			java = filepath.Join(jreDir, "bin", "java.exe")
		}
		if st, err := os.Stat(java); err != nil || st.Size() == 0 {
			jreErr = fmt.Errorf("встроенная Java не распаковалась: %v", err)
			return
		}
		jrePath = preferWorker(java)
	})
	return jrePath, jreErr
}

// preferWorker copies java.exe to SBSC-worker.exe inside the bundled JRE.
// Windows Task Manager then shows SBSC-worker.exe instead of a stack of
// java.exe background processes. The copy shares the same bin directory, so
// java.dll and jvm.dll are found normally.
func preferWorker(java string) string {
	if runtime.GOOS != "windows" {
		return java
	}
	worker := filepath.Join(filepath.Dir(java), "SBSC-worker.exe")
	if st, err := os.Stat(worker); err == nil && st.Size() > 0 {
		return worker
	}
	data, err := os.ReadFile(java)
	if err != nil {
		return java
	}
	tmp := worker + ".tmp"
	if err := os.WriteFile(tmp, data, 0o755); err != nil {
		return java
	}
	if err := os.Rename(tmp, worker); err != nil {
		_ = os.Remove(tmp)
		return java
	}
	return worker
}

func extractJRE(data []byte, dst string) error {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}
	dst = filepath.Clean(dst)
	for _, f := range zr.File {
		name := filepath.ToSlash(f.Name)
		if i := strings.Index(name, "/"); i >= 0 {
			name = name[i+1:]
		} else {
			continue
		}
		if name == "" || strings.Contains(name, "..") {
			continue
		}
		target := filepath.Join(dst, filepath.FromSlash(name))
		if !strings.HasPrefix(filepath.Clean(target), dst+string(os.PathSeparator)) {
			continue
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if f.Mode()&os.ModeSymlink != 0 {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			rc.Close()
			return err
		}
		_, cerr := io.Copy(out, rc)
		out.Close()
		rc.Close()
		if cerr != nil {
			return cerr
		}
	}
	return nil
}

func javaExe() string {
	if runtime.GOOS == "windows" {
		return "java.exe"
	}
	return "java"
}

func javaVersion(java string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	versionCmd := exec.CommandContext(ctx, java, "-version")
	hideConsole(versionCmd)
	out, err := versionCmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	s := string(out)
	re := regexp.MustCompile(`(?m)(?:version\s+"|openjdk\s+)([0-9][^\s"]*)`)
	if m := re.FindStringSubmatch(s); len(m) > 1 {
		return m[1], nil
	}
	re2 := regexp.MustCompile(`(?m)([0-9]+\.[0-9]+\.[0-9]+[^\s"]*)`)
	if m := re2.FindStringSubmatch(s); len(m) > 1 {
		return m[1], nil
	}
	return strings.TrimSpace(s), nil
}

func (d *Decompiler) ensureCFR() (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.CFRPath != "" {
		if st, err := os.Stat(d.CFRPath); err == nil && st.Size() > 0 {
			return d.CFRPath, nil
		}
	}
	if err := os.MkdirAll(d.WorkDir, 0o755); err != nil {
		return "", err
	}
	p := filepath.Join(d.WorkDir, "cfr.jar")
	if st, err := os.Stat(p); err == nil && st.Size() > 100000 {
		d.CFRPath = p
		return p, nil
	}
	b, err := assets.FS.ReadFile("tools/cfr.jar")
	if err != nil {
		return "", fmt.Errorf("встроенный CFR не найден: %w", err)
	}
	if err := os.WriteFile(p, b, 0o644); err != nil {
		return "", err
	}
	d.CFRPath = p
	return p, nil
}

func (d *Decompiler) currentJava() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.JavaPath
}

// DecompileJar decompiles a jar. If filter is non-empty, CFR's --jarfilter is
// used to decompile only matching classes.
func (d *Decompiler) DecompileJar(jarPath, outDir string, filter []string) error {
	java := d.currentJava()
	if java == "" {
		j, _, err := d.FindJava("")
		if err != nil {
			return err
		}
		java = j
	}
	cfr, err := d.ensureCFR()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	args := []string{"-Xmx1G", "-jar", cfr, jarPath, "--outputdir", outDir, "--silent", "true", "--comments", "false", "--hideutf", "false"}
	if len(filter) > 0 {
		var parts []string
		for _, f := range filter {
			f = strings.TrimSpace(f)
			if f == "" {
				continue
			}
			f = strings.ReplaceAll(f, "/", ".")
			parts = append(parts, regexp.QuoteMeta(f))
			if len(parts) >= 80 {
				break
			}
		}
		if len(parts) > 0 {
			args = append(args, "--jarfilter", strings.Join(parts, "|"))
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, java, args...)
	hideConsole(cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("CFR: %v: %s", err, truncate(string(out), 800))
	}
	// CFR can exit 0 without producing files if the filter matched nothing.
	has := false
	_ = filepath.Walk(outDir, func(p string, info os.FileInfo, err error) error {
		if err == nil && info != nil && !info.IsDir() && strings.HasSuffix(strings.ToLower(p), ".java") {
			has = true
			return filepath.SkipAll
		}
		return nil
	})
	if !has {
		return fmt.Errorf("CFR не создал .java файлы: %s", truncate(string(out), 500))
	}
	return nil
}

// DisassembleNative is a best-effort "decompilation" for native DLLs: it uses
// objdump/dumpbin/ilspycmd if available. PE import/export/string analysis is
// always performed by the scanner itself.
func (d *Decompiler) DisassembleNative(path, outDir string) (string, error) {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", err
	}
	outFile := filepath.Join(outDir, filepath.Base(path)+".asm.txt")
	type tool struct {
		name string
		args []string
	}
	tools := []tool{
		{"objdump", []string{"-d", "-M", "intel", path}},
		{"dumpbin", []string{"/disasm", path}},
		{"ilspycmd", []string{"-o", outDir, path}},
	}
	for _, t := range tools {
		exe, err := exec.LookPath(t.name)
		if err != nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		cmd := exec.CommandContext(ctx, exe, t.args...)
		hideConsole(cmd)
		out, err := cmd.CombinedOutput()
		cancel()
		if err != nil && len(out) == 0 {
			continue
		}
		if t.name == "ilspycmd" {
			return outDir, nil
		}
		if err := os.WriteFile(outFile, out, 0o644); err != nil {
			return "", err
		}
		return outFile, nil
	}
	return "", fmt.Errorf("нет objdump/dumpbin/ilspycmd для дизассемблирования DLL")
}
