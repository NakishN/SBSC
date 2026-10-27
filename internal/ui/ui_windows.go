//go:build windows

package ui

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"golang.org/x/sys/windows"

	"sbsc/internal/applog"
	"sbsc/internal/engine"
)

type resultsModel struct {
	walk.TableModelBase
	walk.SorterBase
	all   []*engine.ScanResult
	items []*engine.ScanResult
}

func (m *resultsModel) RowCount() int { return len(m.items) }

func (m *resultsModel) Items() []*engine.ScanResult {
	return m.items
}

func (m *resultsModel) Item(row int) *engine.ScanResult {
	if row < 0 || row >= len(m.items) {
		return nil
	}
	return m.items[row]
}

func (m *resultsModel) rebuild() {
	m.items = append(m.items[:0], m.all...)
	m.PublishRowsReset()
}

func (m *resultsModel) Value(row, col int) interface{} {
	if row < 0 || row >= len(m.items) {
		return ""
	}
	r := m.items[row]
	switch col {
	case 0:
		return row + 1
	case 1:
		return r.Name
	case 2:
		return r.Verdict
	case 3:
		return r.Risk
	case 4:
		return resultCategories(r)
	case 5:
		return resultModules(r)
	case 6:
		return strings.ToUpper(r.Kind)
	case 7:
		return humanSize(r.Size)
	case 8:
		return fmt.Sprintf("%d мс", r.DurationMS)
	}
	return ""
}

func (m *resultsModel) ColumnSortable(col int) bool {
	return col > 0
}

func (m *resultsModel) Sort(col int, order walk.SortOrder) error {
	if col >= 0 {
		sort.SliceStable(m.all, func(i, j int) bool {
			c := compareResults(m.all[i], m.all[j], col)
			if order == walk.SortDescending {
				return c > 0
			}
			return c < 0
		})
		m.rebuild()
	}
	return m.SorterBase.Sort(col, order)
}

func resultCategories(r *engine.ScanResult) string {
	var parts []string
	for _, c := range r.Categories {
		if c.Score >= 8 {
			parts = append(parts, fmt.Sprintf("%s %d", c.Label, c.Score))
		}
	}
	return strings.Join(parts, " · ")
}

func resultModules(r *engine.ScanResult) string {
	var names []string
	for _, m := range r.Modules {
		if m.Weight < 6 {
			continue
		}
		names = append(names, m.Name)
		if len(names) >= 8 {
			break
		}
	}
	return strings.Join(names, ", ")
}

func compareResults(a, b *engine.ScanResult, col int) int {
	switch col {
	case 1:
		return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
	case 2:
		return strings.Compare(a.Verdict, b.Verdict)
	case 3:
		return cmpInt(a.Risk, b.Risk)
	case 4:
		return strings.Compare(resultCategories(a), resultCategories(b))
	case 5:
		return strings.Compare(resultModules(a), resultModules(b))
	case 6:
		return strings.Compare(a.Kind, b.Kind)
	case 7:
		return cmpInt64(a.Size, b.Size)
	case 8:
		return cmpInt64(a.DurationMS, b.DurationMS)
	}
	return 0
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func cmpInt64(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func (m *resultsModel) Clear() {
	m.all = nil
	m.items = nil
	m.PublishRowsReset()
}

func (m *resultsModel) Add(r *engine.ScanResult) {
	m.all = append(m.all, r)
	i := len(m.items)
	m.items = append(m.items, r)
	m.PublishRowsInserted(i, i)
}

type app struct {
	mw       *walk.MainWindow
	table    *walk.TableView
	details  *walk.TextEdit
	status   *walk.Label
	progress *walk.ProgressBar

	chkDeep   *walk.CheckBox
	chkAll    *walk.CheckBox
	chkNative *walk.CheckBox

	btnAddJar  *walk.PushButton
	btnAddDir  *walk.PushButton
	btnAddDisk *walk.PushButton
	btnAddDll  *walk.PushButton
	btnScan    *walk.PushButton
	btnClear   *walk.PushButton
	btnSources *walk.PushButton
	btnHTML    *walk.PushButton
	btnJSON    *walk.PushButton

	model   *resultsModel
	results []*engine.ScanResult
	paths   []string
	opts    engine.Options

	reportHTML string
	reportJSON string
	scanning   bool
}

// Run starts the Windows GUI.
func Run(opts engine.Options, initial []string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			applog.Write("UI PANIC: %v\n%s", r, debug.Stack())
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	if opts.OutDir == "" {
		opts.OutDir = defaultOutDir()
	}
	applog.Write("ui: create start")
	a := &app{model: &resultsModel{}, opts: opts}
	if len(initial) > 0 {
		a.addPaths(initial)
	}
	if err := a.create(); err != nil {
		applog.Write("ui: create error: %v", err)
		return err
	}
	applog.Write("ui: create ok")
	a.mw.Run()
	applog.Write("ui: message loop ended")
	return nil
}

var singleInstanceHandle windows.Handle

// AcquireSingleInstance prevents a pile of scanner windows when the exe is
// launched repeatedly. The mutex is released by Windows when the process exits.
func AcquireSingleInstance() bool {
	name, err := windows.UTF16PtrFromString("Local\\SBSC_SingleInstance")
	if err != nil {
		return true
	}
	if existing, _ := windows.OpenMutex(windows.SYNCHRONIZE, false, name); existing != 0 {
		windows.CloseHandle(existing)
		return false
	}
	h, err := windows.CreateMutex(nil, false, name)
	if err != nil {
		return true
	}
	singleInstanceHandle = h
	applog.Write("ui: single-instance mutex acquired")
	return true
}

// ShowError displays a fatal startup error. The GUI build has no console, so
// this is the only way the user can see why the program did not start.
func ShowError(title, msg string) {
	defer func() { _ = recover() }()
	walk.MsgBox(nil, title, msg, walk.MsgBoxIconError)
}

func (a *app) create() error {
	if err := (MainWindow{
		AssignTo: &a.mw,
		Title:    "SBSC " + engine.Version + " сканер читов",
		Size:     Size{Width: 1100, Height: 700},
		MinSize:  Size{Width: 1000, Height: 680},
		Layout:   VBox{},
		Children: []Widget{
			Composite{
				Layout: HBox{MarginsZero: true},
				Children: []Widget{
					PushButton{AssignTo: &a.btnAddJar, Text: "+ JAR/ZIP", OnClicked: a.addJarDialog},
					PushButton{AssignTo: &a.btnAddDir, Text: "+ Папка mods", OnClicked: a.addDirDialog},
					PushButton{AssignTo: &a.btnAddDisk, Text: "+ Диск", OnClicked: a.addDiskDialog},
					PushButton{AssignTo: &a.btnAddDll, Text: "+ DLL/EXE", OnClicked: a.addDllDialog},
					PushButton{AssignTo: &a.btnScan, Text: "▶ Сканировать", OnClicked: a.scan},
					PushButton{AssignTo: &a.btnClear, Text: "Очистить", OnClicked: a.clear},
					HSpacer{},
					PushButton{AssignTo: &a.btnHTML, Text: "HTML-отчёт", OnClicked: a.openHTML},
					PushButton{AssignTo: &a.btnJSON, Text: "JSON", OnClicked: a.openJSON},
				},
			},
			Composite{
				Layout: HBox{MarginsZero: true},
				Children: []Widget{
					CheckBox{AssignTo: &a.chkDeep, Text: "Глубокий анализ кода (декомпиляция + Java)", Checked: true, MinSize: Size{Width: 320}},
					CheckBox{AssignTo: &a.chkAll, Text: "Все JAR (медленно)", Checked: false, MinSize: Size{Width: 130}},
					CheckBox{AssignTo: &a.chkNative, Text: "Анализ DLL/EXE", Checked: true, MinSize: Size{Width: 140}},
					HSpacer{},
				},
			},
			Label{AssignTo: &a.status, Text: "Готов к сканированию. Перетащите jar/dll в окно."},
			TableView{
				AssignTo:         &a.table,
				AlternatingRowBG: true,
				StretchFactor:    3,
				MinSize:          Size{Height: 260},
				Columns: []TableViewColumn{
					{Title: "#", Width: 36},
					{Title: "Файл", Width: 250},
					{Title: "Вердикт", Width: 115},
					{Title: "Риск", Width: 48},
					{Title: "Категории", Width: 145},
					{Title: "Модули", Width: 165},
					{Title: "Тип", Width: 56},
					{Title: "Размер", Width: 72},
					{Title: "Время", Width: 73},
				},
				Model: a.model,
				OnCurrentIndexChanged: func() {
					a.showDetails(a.table.CurrentIndex())
				},
			},
			TextEdit{
				AssignTo:      &a.details,
				ReadOnly:      true,
				VScroll:       true,
				StretchFactor: 2,
				MinSize:       Size{Height: 180},
				Text:          "Выберите файл в таблице, чтобы увидеть находки, доказательства и фрагменты декомпилированного кода.",
			},
			Composite{
				Layout: HBox{MarginsZero: true},
				Children: []Widget{
					ProgressBar{AssignTo: &a.progress, MinValue: 0, MaxValue: 100, StretchFactor: 1},
					PushButton{AssignTo: &a.btnSources, Text: "Открыть исходники", MinSize: Size{Width: 160}, OnClicked: a.openSources},
				},
			},
		},
	}).Create(); err != nil {
		return err
	}
	a.mw.DropFiles().Attach(func(files []string) {
		if len(files) == 1 && isDirPath(files[0]) {
			a.paths = nil
		}
		a.addPaths(files)
	})
	a.setBusy(false)
	if len(a.paths) > 0 && a.status != nil {
		a.status.SetText(fmt.Sprintf("Целей: %d. Нажмите «Сканировать».", len(a.paths)))
	}
	if os.Getenv("SBSC_AUTOSCAN") == "1" && len(a.paths) > 0 {
		go func() {
			time.Sleep(700 * time.Millisecond)
			a.mw.Synchronize(func() { a.scan() })
		}()
	}
	return nil
}

func (a *app) addJarDialog() {
	dlg := walk.FileDialog{
		Title:  "Выберите Minecraft-моды",
		Filter: "Minecraft моды (*.jar;*.zip)|*.jar;*.zip|Все файлы (*.*)|*.*",
	}
	if ok, err := dlg.ShowOpenMultiple(a.mw); err == nil && ok {
		a.addPaths(dlg.FilePaths)
	}
}

func (a *app) addDirDialog() {
	dlg := walk.FileDialog{Title: "Выберите папку с модами или корень диска (например, C:\\)"}
	if ok, err := dlg.ShowBrowseFolder(a.mw); err == nil && ok {
		// A folder selection replaces previous folder targets: otherwise an
		// accidentally selected home/drive would stay in the list and trigger
		// the file limit even after choosing mods.
		a.paths = nil
		a.addPaths([]string{dlg.FilePath})
	}
}

func (a *app) addDiskDialog() {
	drives := listDrives()
	if len(drives) == 0 {
		walk.MsgBox(a.mw, "Диски не найдены", "Не удалось получить список дисков. Выбери корень диска через «+ Папка».", walk.MsgBoxIconWarning)
		return
	}
	text := "Найдены диски:\n\n" + strings.Join(drives, "\n") +
		"\n\nСканировать все? Если нужен только один диск — нажми «+ Папка» и выбери его корень."
	if walk.MsgBox(a.mw, "Сканировать диски", text, walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) != walk.DlgCmdYes {
		return
	}
	a.paths = nil
	a.addPaths(drives)
}

func listDrives() []string {
	mask, err := windows.GetLogicalDrives()
	if err != nil {
		return nil
	}
	var out []string
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		root := string(rune('A'+i)) + ":\\"
		p, err := windows.UTF16PtrFromString(root)
		if err != nil {
			continue
		}
		switch windows.GetDriveType(p) {
		case windows.DRIVE_FIXED, windows.DRIVE_REMOVABLE:
			if isDirPath(root) {
				out = append(out, root)
			}
		}
	}
	return out
}

func (a *app) addDllDialog() {
	dlg := walk.FileDialog{
		Title:  "Выберите нативные файлы",
		Filter: "DLL/EXE (*.dll;*.exe)|*.dll;*.exe|Все файлы (*.*)|*.*",
	}
	if ok, err := dlg.ShowOpenMultiple(a.mw); err == nil && ok {
		a.addPaths(dlg.FilePaths)
	}
}

func (a *app) addPaths(paths []string) {
	seen := make(map[string]bool)
	for _, p := range a.paths {
		seen[strings.ToLower(p)] = true
	}
	added := 0
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		key := strings.ToLower(p)
		if seen[key] {
			continue
		}
		st, err := os.Stat(p)
		if err != nil {
			continue
		}
		if st.IsDir() {
			p = normalizeSelectedDir(p)
			st, err = os.Stat(p)
			if err != nil || !st.IsDir() {
				continue
			}
		}
		if !st.IsDir() {
			ext := strings.ToLower(filepath.Ext(p))
			if ext != ".jar" && ext != ".zip" && ext != ".dll" && ext != ".exe" && ext != ".class" {
				continue
			}
		}
		seen[key] = true
		a.paths = append(a.paths, p)
		added++
	}
	if a.status != nil {
		if hasRootPath(a.paths) {
			a.status.SetText(fmt.Sprintf("Добавлен диск (%d целей). Скан может занять долго; для скорости снимите «Глубокий анализ кода».", len(a.paths)))
		} else if len(a.paths) > 1 {
			a.status.SetText(fmt.Sprintf("Добавлено: %d. Всего целей: %d. Старые цели остаются — нажми «Очистить», чтобы начать заново.", added, len(a.paths)))
		} else {
			a.status.SetText(fmt.Sprintf("Добавлено: %d. Целей: %d.", added, len(a.paths)))
		}
	}
}

func hasRootPath(paths []string) bool {
	for _, p := range paths {
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
	}
	return false
}

func isDirPath(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

func normalizeSelectedDir(p string) string {
	base := strings.ToLower(filepath.Base(p))
	if base == "mods" {
		return p
	}
	if base == ".minecraft" {
		if m := filepath.Join(p, "mods"); isDirPath(m) {
			return m
		}
	}
	if m := filepath.Join(p, "mods"); isDirPath(m) {
		if isDirPath(filepath.Join(p, "versions")) || isDirPath(filepath.Join(p, "libraries")) || isDirPath(filepath.Join(p, ".fabric")) {
			return m
		}
	}
	return p
}

func (a *app) clear() {
	if a.scanning {
		return
	}
	a.paths = nil
	a.results = nil
	a.model.Clear()
	a.details.SetText("")
	a.reportHTML = ""
	a.reportJSON = ""
	a.status.SetText("Список очищен.")
	a.progress.SetValue(0)
}

func (a *app) currentOptions() engine.Options {
	deep := a.chkDeep.Checked()
	return engine.Options{
		Decompile:   deep,
		Deep:        deep,
		DeepAll:     a.chkAll.Checked(),
		ScanNatives: a.chkNative.Checked(),
		MaxFileSize: 512 << 20,
		MaxFiles:    0,
		OutDir:      a.opts.OutDir,
		JavaPath:    a.opts.JavaPath,
	}
}

func (a *app) scan() {
	if a.scanning {
		return
	}
	if len(a.paths) == 0 {
		walk.MsgBox(a.mw, "Нет файлов", "Добавьте jar/dll или перетащите их в окно.", walk.MsgBoxIconInformation)
		return
	}
	if hasRootPath(a.paths) {
		msg := "Будут проверены .jar/.zip/.dll/.exe/.class по всему выбранному диску.\n\n" +
			"Системные папки Windows, Java runtime и кеши пропускаются.\n" +
			"Это может занять много времени; для быстрого скана снимите галочку «Глубокий анализ кода».\n\nПродолжить?"
		if walk.MsgBox(a.mw, "Сканировать весь диск?", msg, walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) != walk.DlgCmdYes {
			return
		}
	}
	opts := a.currentOptions()
	eng, err := engine.New(opts)
	if err != nil {
		walk.MsgBox(a.mw, "Ошибка правил", err.Error(), walk.MsgBoxIconError)
		return
	}
	paths := append([]string{}, a.paths...)
	a.results = nil
	a.model.Clear()
	a.reportHTML = ""
	a.reportJSON = ""
	a.scanning = true
	a.setBusy(true)
	a.status.SetText("Сканирование...")
	a.progress.SetRange(0, len(paths))
	a.progress.SetValue(0)
	start := time.Now()

	go func() {
		results, scanErr := eng.ScanPaths(paths, func(p engine.Progress) {
			a.mw.Synchronize(func() {
				if p.Total > 0 {
					a.progress.SetRange(0, p.Total)
				}
				a.progress.SetValue(p.Index)
				if p.Stage == "warning" {
					a.status.SetText(p.Message)
					return
				}
				if p.Stage == "scan" {
					a.status.SetText(fmt.Sprintf("[%d/%d] %s", p.Index+1, p.Total, filepath.Base(p.Path)))
					return
				}
				if p.Stage == "done" && p.Result != nil {
					a.results = append(a.results, p.Result)
					a.model.Add(p.Result)
					if a.model.RowCount() > 0 {
						idx := a.model.RowCount() - 1
						a.table.SetCurrentIndex(idx)
						a.showDetails(idx)
					}
					a.status.SetText(fmt.Sprintf("[%d/%d] %s — %s (риск %d)", p.Index, p.Total, p.Result.Name, p.Result.Verdict, p.Result.Risk))
				}
			})
		})
		if scanErr != nil {
			a.mw.Synchronize(func() {
				a.scanning = false
				a.setBusy(false)
				a.status.SetText("Ошибка сканирования")
				msg := scanErr.Error()
				if strings.Contains(msg, "не найдено") {
					msg += "\n\nВыбери папку ...\\.minecraft\\mods или корень диска. Если в списке уже есть старые цели — нажми «Очистить»."
				}
				walk.MsgBox(a.mw, "Ошибка", msg, walk.MsgBoxIconError)
			})
			return
		}
		rep := engine.BuildReport(paths, eng.Options(), results, start)
		jsonPath, htmlPath, werr := engine.WriteReports(rep, filepath.Join(opts.OutDir, "reports"))
		a.mw.Synchronize(func() {
			a.scanning = false
			a.setBusy(false)
			if werr != nil {
				a.status.SetText("Сканирование завершено, но отчёт не записан: " + werr.Error())
				return
			}
			a.reportHTML = htmlPath
			a.reportJSON = jsonPath
			s := rep.Summary
			a.status.SetText(fmt.Sprintf("Готово: %d файлов · чисто %d · возможны читы %d · подозрительно %d · читы %d",
				s.Total, s.Clean, s.Possible, s.Suspicious, s.Cheat))
			a.progress.SetRange(0, len(results))
			a.progress.SetValue(len(results))
		})
	}()
}

func (a *app) setBusy(busy bool) {
	for _, w := range []walk.Widget{a.btnAddJar, a.btnAddDir, a.btnAddDisk, a.btnAddDll, a.btnScan, a.btnClear, a.chkDeep, a.chkAll, a.chkNative} {
		if w != nil {
			w.SetEnabled(!busy)
		}
	}
	if a.btnSources != nil {
		a.btnSources.SetEnabled(!busy)
	}
}

func (a *app) showDetails(idx int) {
	r := a.model.Item(idx)
	if r == nil {
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", r.Name)
	fmt.Fprintf(&b, "Вердикт: %s   риск: %d/100   код: %d/100   контекст: %d/100\n", r.Verdict, r.Risk, r.CodeScore, r.ContextScore)
	fmt.Fprintf(&b, "Доказательство: %s   уверенность: %d%%\n", proofRU(r.Proof), r.Confidence)
	fmt.Fprintf(&b, "Тип: %s   размер: %s   классов: %d\n", strings.ToUpper(r.Kind), humanSize(r.Size), r.ClassCount)
	fmt.Fprintf(&b, "SHA-256: %s\n", r.SHA256)
	if r.MCVersion != "" || r.Loader != "" || r.Mappings != "" {
		fmt.Fprintf(&b, "Minecraft: %s   загрузчик: %s   маппинги: %s\n", dash(r.MCVersion), dash(r.Loader), dash(r.Mappings))
	}
	if r.Signed {
		b.WriteString("JAR подписан (подпись не гарантирует безопасность)\n")
	}
	if r.Obfuscation > 0 {
		fmt.Fprintf(&b, "Обфускация: %d/25\n", r.Obfuscation)
	}
	if len(r.Categories) > 0 {
		b.WriteString("\nКатегории:\n")
		for _, c := range r.Categories {
			fmt.Fprintf(&b, "  • %s — %d\n", c.Label, c.Score)
		}
	}
	if len(r.Modules) > 0 {
		b.WriteString("\nМодули:\n")
		for _, m := range r.Modules {
			if m.Weight < 5 {
				continue
			}
			fmt.Fprintf(&b, "  • %s [%s, вес %d]", m.NameRU, m.Category, m.Weight)
			if m.QoL {
				b.WriteString(" (QoL)")
			}
			b.WriteString("\n")
			if len(m.Evidence) > 0 {
				fmt.Fprintf(&b, "      %s\n", truncate(strings.Join(m.Evidence, "; "), 220))
			}
		}
	}
	if len(r.Findings) > 0 {
		b.WriteString("\nНаходки:\n")
		for i, f := range r.Findings {
			if i >= 30 {
				b.WriteString("  ...\n")
				break
			}
			fmt.Fprintf(&b, "  [%s] %s (%s, вес %d)\n", f.Source, f.Title, f.Category, f.Weight)
			if f.File != "" {
				fmt.Fprintf(&b, "      %s:%d\n", f.File, f.Line)
			}
			if f.Snippet != "" {
				fmt.Fprintf(&b, "      %s\n", truncate(strings.ReplaceAll(f.Snippet, "\n", " "), 500))
			}
			if len(f.Evidence) > 0 {
				fmt.Fprintf(&b, "      %s\n", truncate(strings.Join(f.Evidence, "; "), 300))
			}
		}
	}
	if len(r.Natives) > 0 {
		b.WriteString("\nНативные библиотеки:\n")
		for _, n := range r.Natives {
			fmt.Fprintf(&b, "  • %s — %s (риск %d, %s)\n", n.Name, n.Verdict, n.Risk, n.Machine)
			if len(n.Findings) > 0 {
				for _, f := range n.Findings {
					fmt.Fprintf(&b, "      %s (вес %d)\n", f.Title, f.Weight)
				}
			}
		}
	}
	if len(r.Notes) > 0 {
		b.WriteString("\nЗаметки:\n")
		for _, n := range r.Notes {
			if n == "" {
				continue
			}
			fmt.Fprintf(&b, "  • %s\n", truncate(n, 300))
		}
	}
	if r.DecompileError != "" {
		fmt.Fprintf(&b, "\nДекомпиляция: %s\n", r.DecompileError)
	}
	if r.DecompiledDir != "" {
		fmt.Fprintf(&b, "\nИсходники: %s\n", r.DecompiledDir)
	}
	if r.Error != "" {
		fmt.Fprintf(&b, "\nОШИБКА: %s\n", r.Error)
	}
	a.details.SetText(b.String())
}

func (a *app) openSources() {
	idx := a.table.CurrentIndex()
	r := a.model.Item(idx)
	if r == nil {
		return
	}
	dir := r.DecompiledDir
	if dir == "" {
		walk.MsgBox(a.mw, "Нет исходников", "Для этого файла декомпиляция не выполнялась или не удалась.", walk.MsgBoxIconInformation)
		return
	}
	_ = exec.Command("explorer", dir).Start()
}

func (a *app) openHTML() {
	if a.reportHTML == "" {
		walk.MsgBox(a.mw, "Нет отчёта", "Сначала выполните сканирование.", walk.MsgBoxIconInformation)
		return
	}
	_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", a.reportHTML).Start()
}

func (a *app) openJSON() {
	if a.reportJSON == "" {
		walk.MsgBox(a.mw, "Нет отчёта", "Сначала выполните сканирование.", walk.MsgBoxIconInformation)
		return
	}
	_ = exec.Command("explorer", "/select,", a.reportJSON).Start()
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

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

func dash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
