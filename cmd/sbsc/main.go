package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"sbsc/internal/applog"
	"sbsc/internal/engine"
	"sbsc/internal/ui"
)

func main() {
	applog.Write("start version=%s os=%s arch=%s args=%q", engine.Version, runtime.GOOS, runtime.GOARCH, os.Args)
	defer func() {
		if r := recover(); r != nil {
			applog.Write("PANIC: %v\n%s", r, debug.Stack())
			ui.ShowError("SBSC — ошибка", fmt.Sprintf("%v\n\nЛог: %s", r, applog.Path()))
		}
	}()
	var (
		cli         = flag.Bool("cli", false, "консольный режим (без GUI)")
		guiMode     = flag.Bool("gui", false, "запустить GUI (можно передать файлы для предзагрузки)")
		noDecompile = flag.Bool("no-decompile", false, "не декомпилировать и не анализировать исходники")
		noDeep      = flag.Bool("no-deep", false, "отключить глубокий анализ декомпилированного кода")
		deepAll     = flag.Bool("deep-all", false, "глубоко анализировать все jar, включая чистые")
		noNative    = flag.Bool("no-native", false, "не анализировать DLL/EXE")
		allDLL      = flag.Bool("all-dll", false, "анализировать DLL даже из белого списка")
		includeSys  = flag.Bool("include-system", false, "сканировать системные папки Windows/Java runtime")
		scanLibs    = flag.Bool("scan-libraries", false, "сканировать обычные Java-библиотеки")
		allFiles    = flag.Bool("all-files", false, "искать JAR/PE/class по сигнатуре даже с чужим расширением (медленнее на диске)")
		workers     = flag.Int("workers", 0, "сколько файлов анализировать параллельно (0 — авто)")
		outDir      = flag.String("out", "", "папка для отчётов и декомпиляции (по умолчанию reports рядом с exe)")
		javaPath    = flag.String("java", "", "путь к java.exe/java")
		jsonPath    = flag.String("json", "", "путь к JSON-отчёту")
		htmlPath    = flag.String("html", "", "путь к HTML-отчёту")
		showVersion = flag.Bool("version", false, "показать версию")
		maxMB       = flag.Int64("max-mb", 512, "максимальный размер файла в МБ")
		maxFiles    = flag.Int("max-files", 0, "максимум файлов за один скан (0 — без лимита)")
	)
	flag.Usage = usage
	flag.Parse()
	if *showVersion {
		fmt.Println("SBSC", engine.Version)
		return
	}
	paths := flag.Args()
	opts := engine.Options{
		Decompile:     !*noDecompile,
		Deep:          !*noDeep,
		DeepAll:       *deepAll,
		ScanNatives:   !*noNative,
		AllDLL:        *allDLL,
		IncludeSystem: *includeSys,
		ScanLibraries: *scanLibs,
		AllFiles:      *allFiles,
		Workers:       *workers,
		MaxFileSize:   *maxMB << 20,
		MaxFiles:      *maxFiles,
		OutDir:        *outDir,
		JavaPath:      *javaPath,
	}
	if opts.OutDir == "" {
		opts.OutDir = defaultOutDir()
	}
	if runtime.GOOS == "windows" && (*guiMode || (!*cli && len(paths) == 0)) {
		if !ui.AcquireSingleInstance() {
			applog.Write("ui: another instance is already running")
			ui.ShowError("SBSC", "Сканер уже запущен. Закрой старое окно (или заверши SBSC.exe в диспетчере задач) и запусти снова.")
			return
		}
		if err := ui.Run(opts, paths); err != nil {
			applog.Write("ui.Run error: %v", err)
			fmt.Fprintln(os.Stderr, "Ошибка GUI:", err)
			ui.ShowError("SBSC — ошибка запуска", fmt.Sprintf("%v\n\nЛог: %s", err, applog.Path()))
			os.Exit(1)
		}
		applog.Write("ui.Run finished normally")
		return
	}
	if len(paths) == 0 {
		usage()
		os.Exit(2)
	}
	runCLI(opts, paths, *jsonPath, *htmlPath)
}

func runCLI(opts engine.Options, paths []string, jsonPath, htmlPath string) {
	start := time.Now()
	auto := opts.Workers == 0
	fmt.Printf("SBSC %s\n", engine.Version)
	fmt.Printf("Цели: %s\n\n", strings.Join(paths, ", "))
	eng, err := engine.New(opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Ошибка загрузки правил:", err)
		os.Exit(1)
	}
	if auto {
		t := eng.Tuning()
		fmt.Printf("Авто: %d потоков", t.Workers)
		if t.MemoryLimitMB > 0 {
			fmt.Printf(", лимит памяти %d МБ", t.MemoryLimitMB)
		}
		if t.TotalMemoryMB > 0 {
			fmt.Printf(" (RAM %d МБ, доступно %d МБ)", t.TotalMemoryMB, t.AvailableMemoryMB)
		}
		fmt.Println()
	}
	collecting := false
	results, err := eng.ScanPaths(paths, func(p engine.Progress) {
		switch p.Stage {
		case "collect":
			if p.Message != "" {
				collecting = true
				fmt.Printf("\r%s", truncate(p.Message, 120))
			}
		case "scan":
			if collecting {
				fmt.Println()
				collecting = false
			}
			fmt.Printf("[%d/%d] %s ...\n", p.Index+1, p.Total, filepath.Base(p.Path))
		case "warning":
			fmt.Printf("! %s\n", p.Message)
		case "done":
			if p.Result != nil {
				fmt.Printf("      %s · риск %d/100 · код %d · контекст %d · доказательство: %s · %s\n", p.Result.Verdict, p.Result.Risk, p.Result.CodeScore, p.Result.ContextScore, proofRU(p.Result.Proof), duration(p.Result.DurationMS))
				for _, m := range p.Result.Modules {
					if m.QoL && m.Weight < 6 {
						continue
					}
					fmt.Printf("      • %s (%s, вес %d)\n", m.NameRU, m.Category, m.Weight)
					if len(m.Evidence) > 0 {
						fmt.Printf("        %s\n", truncate(strings.Join(m.Evidence, "; "), 160))
					}
				}
				for _, f := range p.Result.Findings {
					if f.Source == "known" && f.Weight < 20 {
						continue
					}
					if f.Source == "jar" && f.Weight < 10 {
						continue
					}
					tag := f.Source
					if tag == "" {
						tag = "rule"
					}
					fmt.Printf("      ! [%s] %s (%s, вес %d)\n", tag, f.Title, f.Category, f.Weight)
					if f.File != "" {
						fmt.Printf("        %s:%d\n", f.File, f.Line)
					}
					if f.Snippet != "" {
						fmt.Printf("        %s\n", truncate(strings.ReplaceAll(f.Snippet, "\n", " "), 240))
					}
					for _, e := range f.Evidence {
						fmt.Printf("        %s\n", truncate(e, 160))
					}
				}
				if p.Result.DecompiledDir != "" {
					fmt.Printf("      исходники: %s\n", p.Result.DecompiledDir)
				}
				if p.Result.Error != "" {
					fmt.Printf("      ОШИБКА: %s\n", p.Result.Error)
				}
			}
		}
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Ошибка сканирования:", err)
		if strings.Contains(err.Error(), "не найдено файлов") {
			fmt.Fprintln(os.Stderr, "Подсказка: системные папки Windows/Java и обычные Java-библиотеки пропускаются; используйте --include-system / --scan-libraries, если это действительно нужно.")
		}
		os.Exit(1)
	}
	rep := engine.BuildReport(paths, eng.Options(), results, start)
	if jsonPath == "" || htmlPath == "" {
		dir := filepath.Join(opts.OutDir, "reports")
		jp, hp, werr := engine.WriteReports(rep, dir)
		if werr != nil {
			fmt.Fprintln(os.Stderr, "Не удалось записать отчёт:", werr)
		} else {
			if jsonPath == "" {
				jsonPath = jp
			}
			if htmlPath == "" {
				htmlPath = hp
			}
		}
	}
	if jsonPath != "" {
		if err := engine.WriteJSON(jsonPath, rep); err != nil {
			fmt.Fprintln(os.Stderr, "JSON:", err)
		}
	}
	if htmlPath != "" {
		if err := engine.WriteHTML(htmlPath, rep); err != nil {
			fmt.Fprintln(os.Stderr, "HTML:", err)
		}
	}
	s := rep.Summary
	fmt.Printf("\n=== ИТОГ ===\n")
	fmt.Printf("Всего: %d | чисто: %d | возможны читы: %d | подозрительно: %d | читы: %d | ошибки: %d\n",
		s.Total, s.Clean, s.Possible, s.Suspicious, s.Cheat, s.Errors)
	if htmlPath != "" {
		fmt.Printf("HTML-отчёт: %s\n", htmlPath)
	}
	if jsonPath != "" {
		fmt.Printf("JSON-отчёт: %s\n", jsonPath)
	}
}

func proofRU(p string) string {
	switch p {
	case "confirmed":
		return "подтверждено"
	case "likely":
		return "вероятно"
	case "possible":
		return "возможно"
	case "insufficient":
		return "недостаточно данных"
	case "clean":
		return "чисто"
	}
	return p
}

func duration(ms int64) string {
	if ms < 1000 {
		return fmt.Sprintf("%d мс", ms)
	}
	return fmt.Sprintf("%.1f с", float64(ms)/1000)
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func defaultOutDir() string {
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Join(filepath.Dir(exe), "SBSC-data")
		if err := os.MkdirAll(dir, 0o755); err == nil {
			return dir
		}
	}
	if local := os.Getenv("LOCALAPPDATA"); local != "" {
		return filepath.Join(local, "SBSC")
	}
	wd, _ := os.Getwd()
	return filepath.Join(wd, "SBSC-data")
}

func usage() {
	fmt.Fprintf(os.Stderr, `SBSC %s — поиск читов, хитбоксов и ghost-клиентов в Minecraft-модах.

Использование:
  SBSC.exe                         запустить GUI (Windows)
  SBSC.exe --cli <путь...>         консольный скан
  SBSC.exe --cli mods\               скан папки
  SBSC.exe --cli C:\                 скан всего диска (Windows)
  SBSC.exe --cli /                    скан корня (Linux/Wine)
  SBSC.exe --cli mod.jar --html report.html

Флаги:
  --cli              консольный режим
  --gui              запустить GUI (можно передать файлы)
  --no-decompile     не декомпилировать и не анализировать исходники
  --no-deep          отключить глубокий анализ кода
  --deep-all         глубоко анализировать все jar
  --no-native        не анализировать DLL/EXE
  --all-dll          анализировать DLL из белого списка
  --include-system   сканировать Windows/Java runtime (по умолчанию пропускаются)
  --scan-libraries   сканировать обычные Java-библиотеки
  --all-files        искать JAR/PE/class по сигнатуре даже с чужим расширением
  --workers <n>      параллельных файлов (0 — авто по CPU и RAM)
  --out <dir>        папка данных (по умолчанию рядом с exe)
  --java <path>      путь к java
  --json <file>      JSON-отчёт
  --html <file>      HTML-отчёт
  --max-mb <n>       лимит размера файла (по умолчанию 512)
  --max-files <n>    лимит количества файлов (0 — без лимита)
  --version          версия
`, engine.Version)
}
