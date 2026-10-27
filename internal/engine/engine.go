package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"sbsc/assets"
)

const Version = "1.0.1"

type Engine struct {
	opts         Options
	rules        *RuleSet
	decomp       *Decompiler
	decompileSem chan struct{}
	fileParallel int32
}

func New(opts Options) (*Engine, error) {
	rules, err := LoadRules(assets.FS)
	if err != nil {
		return nil, err
	}
	if opts.OutDir == "" {
		opts.OutDir = filepath.Join(os.TempDir(), "sbsc")
	}
	return &Engine{
		opts:         opts,
		rules:        rules,
		decomp:       NewDecompiler(opts),
		decompileSem: make(chan struct{}, 2),
		fileParallel: 1,
	}, nil
}

func (e *Engine) Options() Options { return e.opts }

func (e *Engine) workers() int {
	w := e.opts.Workers
	if w <= 0 {
		w = runtime.GOMAXPROCS(0)
		if w > 8 {
			w = 8
		}
	}
	if w < 1 {
		w = 1
	}
	return w
}

// classWorkers keeps total CPU concurrency near GOMAXPROCS: one large JAR
// uses several class workers, while a parallel folder scan leaves CPU for the
// other files.
func (e *Engine) classWorkers() int {
	fp := int(atomic.LoadInt32(&e.fileParallel))
	if fp < 1 {
		fp = 1
	}
	w := runtime.GOMAXPROCS(0) / fp
	if w < 1 {
		w = 1
	}
	if w > 8 {
		w = 8
	}
	return w
}

// ScanPaths expands roots into supported files and scans them.
func (e *Engine) ScanPaths(roots []string, progress func(Progress)) ([]*ScanResult, error) {
	if hasDriveRoot(roots) && progress != nil {
		limitText := "без лимита по файлам"
		if m := e.opts.maxFiles(); m > 0 {
			limitText = fmt.Sprintf("лимит %d файлов", m)
		}
		progress(Progress{Stage: "warning", Message: fmt.Sprintf("скан диска: системные папки пропускаются, %s; для быстрого скана используйте --no-deep", limitText)})
	}
	// User-selected folders are sniffed for disguised archives. A whole-disk
	// scan keeps the extension filter unless --all-files is set.
	sniffUnknown := e.opts.AllFiles || !hasDriveRoot(roots)
	files, truncated, err := collectFilesOpts(roots, e.opts.IncludeSystem, e.opts.maxFiles(), sniffUnknown)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("не найдено файлов .jar/.zip/.dll/.exe/.class; выбери папку с модами или корень диска (для файлов с чужим расширением — --all-files)")
	}
	if truncated && progress != nil {
		progress(Progress{Stage: "warning", Total: len(files), Message: fmt.Sprintf("найдено больше %d файлов — взяты первые %d. Увеличь --max-files или выбери папку", e.opts.maxFiles(), len(files))})
	}
	workers := e.workers()
	if workers <= 1 || len(files) <= 1 {
		atomic.StoreInt32(&e.fileParallel, 1)
		results := make([]*ScanResult, 0, len(files))
		for i, p := range files {
			if progress != nil {
				progress(Progress{Index: i, Total: len(files), Path: p, Stage: "scan"})
			}
			r := e.ScanFile(p)
			results = append(results, r)
			if progress != nil {
				progress(Progress{Index: i + 1, Total: len(files), Path: p, Stage: "done", Result: r})
			}
		}
		return results, nil
	}

	results := make([]*ScanResult, len(files))
	var completed int64
	active := workers
	if active > len(files) {
		active = len(files)
	}
	atomic.StoreInt32(&e.fileParallel, int32(active))
	var progressMu sync.Mutex
	emit := func(p Progress) {
		if progress == nil {
			return
		}
		progressMu.Lock()
		defer progressMu.Unlock()
		progress(p)
	}
	jobs := make(chan int)
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for i := range jobs {
				p := files[i]
				emit(Progress{Index: i, Total: len(files), Path: p, Stage: "scan"})
				r := e.ScanFile(p)
				results[i] = r
				done := int(atomic.AddInt64(&completed, 1))
				emit(Progress{Index: done, Total: len(files), Path: p, Stage: "done", Result: r})
			}
		}()
	}
	for i := range files {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return results, nil
}

// These directories are skipped only when a whole drive is scanned. If the
// user explicitly selects one of them, it is still scanned.
var diskSkipDirNames = map[string]bool{
	"program files": true, "program files (x86)": true, "programdata": true,
	"windows.old": true, "$windows.~bt": true, "$windows.~ws": true,
}

var skipDirNames = map[string]bool{
	// VCS, build and dependency folders.
	".git": true, ".svn": true, ".hg": true, "node_modules": true,
	".gradle": true, ".m2": true, ".ivy2": true, ".sdkman": true,
	".cargo": true, ".rustup": true, ".cache": true, "caches": true,
	"__pycache__": true, "site-packages": true, "dist-packages": true,
	"venv": true, ".venv": true,
	// Launcher/runtime copies that are not user mods.
	".fabric": true, ".quilt": true, "processedmods": true, "remappedjars": true,
	"backup": true, "backups": true, "crash-reports": true, "logs": true,
	// Caches and temporary data. A cheat downloaded to Temp is rare; scanning
	// every browser/IDE cache makes a disk scan unusably slow.
	"temp": true, "tmp": true, "cache": true, "code cache": true,
	"gpucache": true, "shadercache": true, "crashpad": true,
	"packages": true,
	// Windows and Linux system areas.
	"windows": true, "winsxs": true, "system32": true, "syswow64": true,
	"windows.old": true, "$recycle.bin": true, "system volume information": true,
	"recovery": true, "perflogs": true, "msocache": true, "config.msi": true,
	"$winreagent": true,
	"snap":        true, "usr": true, "lib": true, "lib64": true, "opt": true,
	"var": true, "proc": true, "sys": true, "dev": true, "run": true,
	"android-sdk": true, "burpsuite": true, "comfyui": true, "comfyui-venv": true,
}

func collectFiles(roots []string, includeSystem bool, maxFiles int) ([]string, bool, error) {
	return collectFilesOpts(roots, includeSystem, maxFiles, false)
}

// collectFilesOpts expands roots into candidate files. When sniffUnknown is
// true, files with an unexpected extension are included when their first bytes
// look like ZIP/JAR, PE or a JVM class file. This closes the "rename the cheat
// to .dat" bypass without walking every file on a full-disk scan.
func collectFilesOpts(roots []string, includeSystem bool, maxFiles int, sniffUnknown bool) ([]string, bool, error) {
	limited := maxFiles > 0
	seen := make(map[string]bool)
	var out []string
	add := func(p string) {
		abs, err := filepath.Abs(p)
		if err != nil {
			abs = p
		}
		key := strings.ToLower(filepath.Clean(abs))
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, abs)
	}
	supported := func(p string) bool {
		switch strings.ToLower(filepath.Ext(p)) {
		case ".jar", ".zip", ".dll", ".exe", ".class":
			return true
		}
		return false
	}
	truncated := false
	for _, rawRoot := range roots {
		root := strings.TrimSpace(rawRoot)
		if len(root) == 2 && root[1] == ':' {
			root += string(os.PathSeparator)
		}
		root = filepath.Clean(root)
		st, err := os.Stat(root)
		if err != nil {
			return nil, false, err
		}
		if !st.IsDir() {
			// An explicitly selected file is always scanned; ScanFile sniffs
			// its content and returns ПРОПУЩЕН for unsupported data.
			add(root)
			continue
		}
		// A drive root is scanned as a disk. User folders are walked first,
		// otherwise Program Files can fill the file cap before Downloads or
		// .minecraft are even reached.
		diskMode := isDriveRoot(root)
		var priority []string
		skipDirs := make(map[string]bool)
		if diskMode {
			priority = preferredDirs(root)
			for _, sub := range priority {
				skipDirs[strings.ToLower(filepath.Clean(sub))] = true
			}
		}
		walkList := append(priority, root)
		for _, walkRoot := range walkList {
			err = filepath.WalkDir(walkRoot, func(p string, d fs.DirEntry, err error) error {
				if err != nil {
					return nil
				}
				if d.Type()&os.ModeSymlink != 0 {
					if d.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}
				if d.IsDir() {
					// Do not walk priority folders twice when their parent
					// (Users, home, or the drive root) is processed later.
					if !samePath(p, walkRoot) && skipDirs[strings.ToLower(filepath.Clean(p))] {
						return filepath.SkipDir
					}
					base := strings.ToLower(d.Name())
					if diskMode && diskSkipDirNames[base] {
						return filepath.SkipDir
					}
					if skipDirNames[base] {
						return filepath.SkipDir
					}
					if !includeSystem && isIgnoredPath(p) {
						return filepath.SkipDir
					}
					return nil
				}
				if d.Type().IsRegular() && (includeSystem || !isIgnoredPath(p)) {
					if supported(p) {
						add(p)
					} else if sniffUnknown {
						size := int64(0)
						if info, ierr := d.Info(); ierr == nil {
							size = info.Size()
						}
						if size >= 4 && size <= 512<<20 && sniffFileKind(p) != "" {
							add(p)
						}
					}
				}
				if limited && len(out) >= maxFiles {
					truncated = true
					return filepath.SkipAll
				}
				return nil
			})
			if err != nil {
				return nil, false, err
			}
			if truncated {
				break
			}
		}
		if truncated {
			break
		}
	}
	sort.Strings(out)
	return out, truncated, nil
}

func preferredDirs(root string) []string {
	var specific, top []string
	add := func(dst *[]string, p string) {
		p = filepath.Clean(p)
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			*dst = append(*dst, p)
		}
	}
	var userRoots []string
	for _, name := range []string{"Users", "home"} {
		p := filepath.Join(root, name)
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			userRoots = append(userRoots, p)
			add(&top, p)
		}
	}
	for _, ur := range userRoots {
		entries, err := os.ReadDir(ur)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			home := filepath.Join(ur, e.Name())
			for _, sub := range []string{
				"Downloads", "Desktop", ".minecraft",
				"AppData/Roaming/.minecraft", "AppData/Local/.minecraft",
			} {
				add(&specific, filepath.Join(home, sub))
			}
		}
	}
	for _, name := range []string{"Games", "mnt", "media"} {
		add(&top, filepath.Join(root, name))
	}
	return append(specific, top...)
}

func samePath(a, b string) bool {
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}

// sniffBytes classifies a buffer by its magic bytes.
func sniffBytes(b []byte) string {
	if len(b) >= 4 && b[0] == 'P' && b[1] == 'K' {
		switch {
		case b[2] == 3 && b[3] == 4, b[2] == 5 && b[3] == 6, b[2] == 7 && b[3] == 8:
			return "zip"
		}
	}
	if len(b) >= 2 && b[0] == 'M' && b[1] == 'Z' {
		return "pe"
	}
	if len(b) >= 4 && b[0] == 0xCA && b[1] == 0xFE && b[2] == 0xBA && b[3] == 0xBE {
		return "class"
	}
	return ""
}

func kindFromExt(ext string) string {
	switch ext {
	case ".jar", ".zip":
		return "zip"
	case ".dll", ".exe":
		return "pe"
	case ".class":
		return "class"
	}
	return ""
}

// sniffFileKind returns "zip", "pe" or "class" when the file content matches
// a known container signature, regardless of the file extension.
func sniffFileKind(p string) string {
	f, err := os.Open(p)
	if err != nil {
		return ""
	}
	defer f.Close()
	var b [8]byte
	n, _ := f.Read(b[:])
	return sniffBytes(b[:n])
}

func isDriveRoot(p string) bool {
	p = strings.TrimSpace(p)
	if p == "/" {
		return true
	}
	if len(p) == 2 && p[1] == ':' {
		return true
	}
	if len(p) == 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/') {
		return true
	}
	return false
}

func hasDriveRoot(roots []string) bool {
	for _, r := range roots {
		if isDriveRoot(r) {
			return true
		}
	}
	return false
}

// ScanFile scans one file and never returns nil.
func (e *Engine) ScanFile(p string) *ScanResult {
	start := time.Now()
	res := &ScanResult{
		Path:      p,
		Name:      filepath.Base(p),
		ScannedAt: start,
	}
	st, err := os.Stat(p)
	if err != nil {
		res.Error = err.Error()
		res.Verdict = "ОШИБКА"
		res.DurationMS = time.Since(start).Milliseconds()
		return res
	}
	res.Size = st.Size()
	if st.Size() > e.opts.maxSize() {
		res.Error = fmt.Sprintf("файл больше лимита (%d байт)", e.opts.maxSize())
		res.Verdict = "ОШИБКА"
		res.DurationMS = time.Since(start).Milliseconds()
		return res
	}
	data, err := os.ReadFile(p)
	if err != nil {
		res.Error = err.Error()
		res.Verdict = "ОШИБКА"
		res.DurationMS = time.Since(start).Milliseconds()
		return res
	}
	sum := sha256.Sum256(data)
	res.SHA256 = hex.EncodeToString(sum[:])
	ext := strings.ToLower(filepath.Ext(p))
	res.Kind = strings.TrimPrefix(ext, ".")
	if ext == ".zip" {
		res.Kind = "zip"
	}
	// Content wins over extension. A cheat renamed to .dat/.txt/.dll must not
	// disappear from a screenshare scan.
	sniffed := sniffBytes(data)
	kind := kindFromExt(ext)
	if sniffed != "" && kind != sniffed {
		switch sniffed {
		case "zip":
			ext, res.Kind = ".jar", "jar"
		case "pe":
			ext, res.Kind = ".exe", "exe"
		case "class":
			ext, res.Kind = ".class", "class"
		}
		res.Notes = append(res.Notes, fmt.Sprintf("тип определён по содержимому (%s), расширение %q не совпало", sniffed, filepath.Ext(p)))
	} else if kind == "" && sniffed == "" {
		res.Verdict = "ПРОПУЩЕН"
		res.Proof = "clean"
		res.Notes = append(res.Notes, "неизвестный формат: нет ZIP/PE/class-сигнатуры")
		res.DurationMS = time.Since(start).Milliseconds()
		return res
	}
	if h := e.rules.Hashes.Lookup(res.SHA256); h != nil {
		e.applyHashResult(res, h)
		res.DurationMS = time.Since(start).Milliseconds()
		return res
	}

	switch ext {
	case ".jar", ".zip":
		classes, modMeta, nested := archiveKind(data)
		if classes == 0 && !modMeta {
			res.Verdict = "АРХИВ"
			res.Proof = "clean"
			res.Confidence = 90
			res.Notes = append(res.Notes,
				fmt.Sprintf("в архиве нет .class и метаданных мода (nested jar: %d); это ресурспак/архив, а не мод", nested),
				"для проверки содержимого распакуйте его и сканируйте jar-файлы отдельно")
			res.DurationMS = time.Since(start).Milliseconds()
			return res
		}
		if !e.opts.ScanLibraries {
			if lib, why := quickLibraryJar(p, data); lib {
				res.Kind = "jar"
				res.Verdict = "БИБЛИОТЕКА"
				res.Proof = "clean"
				res.Confidence = 95
				res.Categories = []CategoryScore{{Category: "trusted", Label: categoryLabel("trusted"), Score: 0}}
				res.Notes = append(res.Notes, "пропущено: "+why, "это не Minecraft-чит (--scan-libraries для принудительного анализа)")
				res.DurationMS = time.Since(start).Milliseconds()
				return res
			}
		}
		ja, err := e.analyzeJar(p, data, 0)
		if ja != nil {
			res.MCVersion = ja.MCVersion
			res.Loader = ja.Loader
			res.Mappings = ja.Mappings
			res.Signed = ja.Signed
			res.Obfuscation = ja.Obfuscation
			res.ClassCount = ja.ClassCount
			res.Findings = ja.Findings
			res.Modules = ja.Modules
			res.Natives = ja.Natives
			res.Notes = append(res.Notes, ja.Notes...)
			if !e.opts.ScanLibraries && isLibraryJar(ja) {
				markLibraryResult(res, ja)
			} else {
				res.Risk, res.Confidence, res.Verdict, res.Categories = scoreJar(ja)
				res.CodeScore = ja.CodeScore
				res.ContextScore = ja.ContextScore
				res.Proof = ja.Proof
				if e.opts.Decompile && e.opts.Deep {
					e.decompileAndAnalyze(res, ja)
				}
			}
		}
		if err != nil {
			res.Error = err.Error()
			res.Verdict = "ОШИБКА"
		}
	case ".dll", ".exe":
		if !e.opts.ScanNatives {
			res.Verdict = "ПРОПУЩЕН"
			res.Notes = append(res.Notes, "анализ DLL отключён")
			break
		}
		ni := analyzePE(p, data, false, e.rules, e.opts.AllDLL)
		if ni == nil {
			res.Error = "не удалось разобрать PE"
			res.Verdict = "ОШИБКА"
			break
		}
		var known []Finding
		if !ni.Trusted || e.opts.AllDLL {
			known = e.matchKnownNative(ni)
		}
		if len(known) > 0 {
			ni.Findings = append(ni.Findings, known...)
			for _, f := range known {
				if f.Weight > ni.Risk {
					ni.Risk = f.Weight
				}
			}
			applyNativeVerdict(ni)
		}
		res.Natives = []NativeInfo{*ni}
		res.Risk, res.Confidence, res.Verdict, res.Categories = scoreNative(ni)
		res.CodeScore = ni.CodeScore
		res.ContextScore = ni.ContextScore
		res.Proof = ni.Proof
		if ni.System {
			res.Risk = 0
			res.Proof = "clean"
			res.Verdict = "СИСТЕМНЫЙ / ДОВЕРЕННЫЙ"
			res.Categories = []CategoryScore{{Category: "trusted", Label: categoryLabel("trusted"), Score: 0}}
			res.Notes = append(res.Notes, "системный файл Windows/Java runtime: правила читов не применяются")
		}
		res.Findings = append(res.Findings, ni.Findings...)
		res.Notes = append(res.Notes, ni.Notes...)
		if ni.Trusted {
			res.Notes = append(res.Notes, "DLL в белом списке (доверенная библиотека)")
		}
		if e.opts.Decompile && ni.Risk >= 25 {
			out := filepath.Join(e.opts.OutDir, "native", safeName(res.Name))
			if asm, derr := e.decomp.DisassembleNative(p, out); derr == nil {
				res.DecompiledDir = out
				res.Notes = append(res.Notes, "дизассемблирование: "+asm)
			} else {
				res.DecompileError = derr.Error()
			}
		}
	case ".class":
		cf, err := parseClassFile(p, data)
		if err != nil {
			res.Error = err.Error()
			res.Verdict = "ОШИБКА"
			break
		}
		ja := &jarAnalysis{
			Path: p, Name: res.Name, Size: res.Size, SHA256: res.SHA256,
			Classes: []*ClassFile{cf}, ClassCount: 1,
		}
		ja.Tokens.Classes = append(ja.Tokens.Classes, cf.Name, cf.Super)
		ja.Tokens.Classes = append(ja.Tokens.Classes, cf.Interfaces...)
		ja.Tokens.Classes = append(ja.Tokens.Classes, cf.ClassRefs...)
		ja.Tokens.ClassSimple = append(ja.Tokens.ClassSimple, simpleClassName(cf.Name))
		ja.Tokens.Strings = append(ja.Tokens.Strings, cf.Strings...)
		ja.Tokens.Methods = append(ja.Tokens.Methods, cf.MethodRefs...)
		ja.Tokens.Fields = append(ja.Tokens.Fields, cf.FieldRefs...)
		ja.Tokens.Refs = append(ja.Tokens.Refs, cf.MethodRefs...)
		ja.Tokens.Refs = append(ja.Tokens.Refs, cf.ClassRefs...)
		ja.Tokens.Paths = []string{p}
		ja.Tokens.buildAll()
		ja.Findings, ja.Modules, ja.ClientName = e.matchJarRules(ja)
		ja.Obfuscation = computeObfuscation(ja.Classes, ja.Tokens.Strings)
		res.Mappings = detectMappings(ja)
		res.Obfuscation = ja.Obfuscation
		res.ClassCount = 1
		res.Findings = ja.Findings
		res.Modules = ja.Modules
		res.Risk, res.Confidence, res.Verdict, res.Categories = scoreJar(ja)
		res.CodeScore = ja.CodeScore
		res.ContextScore = ja.ContextScore
		res.Proof = ja.Proof
	default:
		res.Verdict = "ПРОПУЩЕН"
	}
	res.DurationMS = time.Since(start).Milliseconds()
	return res
}

func (e *Engine) applyHashResult(res *ScanResult, h *KnownHash) {
	res.HashMatch = true
	res.KnownName = h.Name
	res.Proof = "confirmed"
	res.Confidence = 100
	cat := "trusted"
	switch h.Category {
	case "cheat":
		res.Verdict = "ЧИТ-КЛИЕНТ"
		res.Risk = 100
		cat = "client"
	case "injector", "malware":
		res.Verdict = "ЧИТ-КЛИЕНТ"
		res.Risk = 100
		cat = "client"
	default:
		res.Verdict = "ЧИСТО (ЭТАЛОН)"
		res.Risk = 0
	}
	res.Categories = []CategoryScore{{Category: cat, Label: categoryLabel(cat), Score: res.Risk}}
	sev := 5
	if h.Category == "clean" {
		sev = 1
	}
	res.Findings = []Finding{{
		RuleID: "hash_exact", Title: "Точное совпадение SHA-256", Category: cat,
		Severity: sev, Weight: res.Risk, Source: "hash",
		Description: "Файл побайтно совпал с эталоном базы: " + h.Name + ". " + h.Comment,
		Evidence:    []string{h.SHA256, h.Name},
	}}
	res.Notes = append(res.Notes, "SHA-256 совпал с эталоном: "+h.Name)
	if h.Comment != "" {
		res.Notes = append(res.Notes, h.Comment)
	}
}

func (e *Engine) decompileAndAnalyze(res *ScanResult, ja *jarAnalysis) {
	out := filepath.Join(e.opts.OutDir, "decompiled", safeName(res.Name)+"-"+shortHash(res.SHA256)+"-"+shortHash(pathHash(res.Path)))
	filter := ja.Suspects
	// Full decompilation is much more useful for source analysis. Limit it for
	// enormous jars to keep runtime and disk usage sane.
	if e.opts.DeepAll || (len(ja.Classes) <= 2500 && res.Size <= 35<<20) {
		filter = nil
	}
	if len(filter) == 0 && !e.opts.DeepAll && (len(ja.Classes) > 2500 || res.Size > 35<<20) {
		res.Notes = append(res.Notes, "jar слишком большой для полной декомпиляции; глубокий анализ пропущен")
		return
	}
	cached := hasJavaSources(out)
	if cached {
		res.Notes = append(res.Notes, "использован кэш декомпиляции")
	} else {
		if e.decompileSem != nil {
			e.decompileSem <- struct{}{}
		}
		err := e.decomp.DecompileJar(res.Path, out, filter)
		if e.decompileSem != nil {
			<-e.decompileSem
		}
		if err != nil {
			res.DecompileError = err.Error()
			res.Notes = append(res.Notes, "глубокая декомпиляция не удалась: "+err.Error())
			return
		}
	}
	res.DecompiledDir = out
	if java := e.decomp.currentJava(); java != "" && strings.Contains(strings.ToLower(java), "sbsc") {
		res.Notes = append(res.Notes, "используется встроенная Java — дополнительно ничего устанавливать не нужно")
	}
	findings, notes := analyzeDecompiledSources(out)
	if len(findings) > 0 {
		ja.Findings = append(ja.Findings, findings...)
	}
	res.Notes = append(res.Notes, notes...)
	res.Findings = ja.Findings
	res.Risk, res.Confidence, res.Verdict, res.Categories = scoreJar(ja)
	res.CodeScore = ja.CodeScore
	res.ContextScore = ja.ContextScore
	res.Proof = ja.Proof
	res.Notes = append(res.Notes, fmt.Sprintf("глубокий анализ кода: %d находок", len(findings)))
}

// hasJavaSources reports whether a decompilation directory already contains
// usable CFR output, so repeated scans can skip the expensive decompiler.
func hasJavaSources(dir string) bool {
	found := false
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if strings.HasSuffix(strings.ToLower(p), ".java") {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

func pathHash(p string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(filepath.Clean(p))))
	return hex.EncodeToString(sum[:])
}

func safeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	if b.Len() == 0 {
		return "file"
	}
	return b.String()
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}
