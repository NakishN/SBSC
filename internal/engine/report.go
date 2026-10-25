package engine

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func BuildReport(roots []string, opts Options, results []*ScanResult, started time.Time) Report {
	return Report{
		Tool:       "SBSC",
		Version:    Version,
		StartedAt:  started,
		FinishedAt: time.Now(),
		Roots:      roots,
		Options:    opts,
		Results:    results,
		Summary:    summarize(results),
	}
}

func WriteJSON(path string, rep Report) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return err
	}
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

type htmlRow struct {
	Index        int
	Name         string
	Path         string
	Kind         string
	Verdict      string
	Proof        string
	Risk         int
	CodeScore    int
	ContextScore int
	Confidence   int
	Size         string
	Categories   string
	Modules      string
	ClassCount   int
	MCVersion    string
	Loader       string
	Hash         string
	Duration     string
	Notes        []string
	Findings     []Finding
	ModuleList   []ModuleHit
	Natives      []NativeInfo
	Decompiled   string
	Error        string
}

type htmlView struct {
	Report
	Generated string
	Rows      []htmlRow
	CheatPct  int
	CleanPct  int
}

func WriteHTML(path string, rep Report) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return err
	}
	rows := make([]htmlRow, 0, len(rep.Results))
	for _, r := range rep.Results {
		if r == nil {
			continue
		}
		var cats []string
		for _, c := range r.Categories {
			cats = append(cats, fmt.Sprintf("%s %d", c.Label, c.Score))
		}
		var mods []string
		for _, m := range r.Modules {
			if m.QoL && m.Weight < 6 {
				continue
			}
			mods = append(mods, m.Name)
			if len(mods) >= 12 {
				break
			}
		}
		rows = append(rows, htmlRow{
			Index: len(rows) + 1, Name: r.Name, Path: r.Path, Kind: r.Kind, Verdict: r.Verdict, Proof: r.Proof,
			Risk: r.Risk, Confidence: r.Confidence, Size: humanSize(r.Size),
			Categories: strings.Join(cats, " · "), Modules: strings.Join(mods, ", "),
			ClassCount: r.ClassCount, MCVersion: r.MCVersion, Loader: r.Loader,
			Hash: r.SHA256, Duration: fmt.Sprintf("%d мс", r.DurationMS),
			Notes: r.Notes, Findings: r.Findings, ModuleList: r.Modules,
			Natives: r.Natives, Decompiled: r.DecompiledDir, Error: r.Error,
		})
	}
	cheat := rep.Summary.Cheat
	view := htmlView{Report: rep, Generated: time.Now().Format("2006-01-02 15:04:05"), Rows: rows}
	if rep.Summary.Total > 0 {
		view.CheatPct = cheat * 100 / rep.Summary.Total
		view.CleanPct = rep.Summary.Clean * 100 / rep.Summary.Total
	}
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"riskClass": riskClass,
		"sev":       func(n int) string { return SeverityRU[n] },
		"cat":       categoryLabel,
		"proof":     ProofRU,
		"join":      strings.Join,
	}).Parse(htmlTemplate)
	if err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return tmpl.Execute(f, view)
}

func riskClass(risk int) string {
	switch {
	case risk >= 70:
		return "critical"
	case risk >= 45:
		return "high"
	case risk >= 25:
		return "medium"
	default:
		return "low"
	}
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

// WriteReports writes report.json and report.html into dir.
func WriteReports(rep Report, dir string) (string, string, error) {
	if dir == "" {
		dir = "reports"
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", err
	}
	stamp := time.Now().Format("20060102-150405")
	jsonPath := filepath.Join(dir, "report-"+stamp+".json")
	htmlPath := filepath.Join(dir, "report-"+stamp+".html")
	if err := WriteJSON(jsonPath, rep); err != nil {
		return "", "", err
	}
	if err := WriteHTML(htmlPath, rep); err != nil {
		return "", "", err
	}
	return jsonPath, htmlPath, nil
}

func SortResults(results []*ScanResult) {
	sort.SliceStable(results, func(i, j int) bool {
		a, b := results[i], results[j]
		if a == nil || b == nil {
			return a != nil
		}
		if a.Risk != b.Risk {
			return a.Risk > b.Risk
		}
		return a.Name < b.Name
	})
}
