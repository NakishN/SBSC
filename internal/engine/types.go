package engine

import "time"

// Options controls a scan.
type Options struct {
	// Decompile suspicious classes with the bundled CFR decompiler.
	Decompile bool
	// Deep enables source-level analysis of decompiled Java code.
	Deep bool
	// DeepAll decompiles/analyses every jar, not only suspicious ones.
	DeepAll bool
	// ScanNatives enables PE analysis for DLL/EXE files.
	ScanNatives bool
	// AllDLL scans DLLs even if their name is in the trusted allowlist.
	AllDLL bool
	// IncludeSystem also scans Windows/Java runtime directories. System files
	// are normally skipped and/or marked trusted to avoid false positives.
	IncludeSystem bool
	// ScanLibraries also scans plain Java libraries (Maven/module-info jars)
	// that normally cannot be Minecraft cheat clients.
	ScanLibraries bool
	// MaxFileSize skips files larger than this (bytes). Zero means 512 MiB.
	MaxFileSize int64
	// MaxFiles caps how many supported files are collected from a directory.
	// Zero (or negative) means no limit.
	MaxFiles int
	// OutDir is where reports and decompiled sources are written.
	OutDir string
	// JavaPath overrides Java auto-detection.
	JavaPath string
}

func (o Options) maxSize() int64 {
	if o.MaxFileSize <= 0 {
		return 512 << 20
	}
	return o.MaxFileSize
}

func (o Options) maxFiles() int {
	if o.MaxFiles <= 0 {
		return 0
	}
	return o.MaxFiles
}

// Finding is a single matched rule.
type Finding struct {
	RuleID      string   `json:"rule_id"`
	Title       string   `json:"title"`
	Category    string   `json:"category"`
	Severity    int      `json:"severity"`
	Weight      int      `json:"weight"`
	Description string   `json:"description,omitempty"`
	Evidence    []string `json:"evidence,omitempty"`
	Source      string   `json:"source,omitempty"` // jar | dll | exe | source | known
	Class       string   `json:"class,omitempty"`
	File        string   `json:"file,omitempty"`
	Line        int      `json:"line,omitempty"`
	Snippet     string   `json:"snippet,omitempty"`
}

// ModuleHit is a detected cheat/QoL module.
type ModuleHit struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	NameRU   string   `json:"name_ru"`
	Category string   `json:"category"`
	Severity int      `json:"severity"`
	Weight   int      `json:"weight"`
	QoL      bool     `json:"qol"`
	Context  bool     `json:"context"`
	Evidence []string `json:"evidence,omitempty"`
}

// CategoryScore is the aggregated risk for one category.
type CategoryScore struct {
	Category string `json:"category"`
	Label    string `json:"label"`
	Score    int    `json:"score"`
}

// SectionInfo describes a PE section.
type SectionInfo struct {
	Name    string  `json:"name"`
	Size    uint32  `json:"size"`
	Entropy float64 `json:"entropy"`
}

// NativeInfo describes an analysed DLL/EXE.
type NativeInfo struct {
	Path         string        `json:"path"`
	Name         string        `json:"name"`
	Size         int64         `json:"size"`
	SHA256       string        `json:"sha256"`
	Machine      string        `json:"machine,omitempty"`
	Signed       bool          `json:"signed"`
	Entropy      float64       `json:"entropy"`
	Imports      []string      `json:"imports,omitempty"`
	Exports      []string      `json:"exports,omitempty"`
	Strings      []string      `json:"-"`
	Sections     []SectionInfo `json:"sections,omitempty"`
	Risk         int           `json:"risk"`
	Proof        string        `json:"proof"`
	CodeScore    int           `json:"code_score"`
	ContextScore int           `json:"context_score"`
	Verdict      string        `json:"verdict"`
	Notes        []string      `json:"notes,omitempty"`
	Findings     []Finding     `json:"findings,omitempty"`
	Trusted      bool          `json:"trusted"`
	Embedded     bool          `json:"embedded"`
	System       bool          `json:"system"`
}

// ScanResult is the result for one file.
type ScanResult struct {
	Path           string          `json:"path"`
	Name           string          `json:"name"`
	Kind           string          `json:"kind"` // jar | dll | exe | zip | class
	SHA256         string          `json:"sha256"`
	Size           int64           `json:"size"`
	MCVersion      string          `json:"mc_version,omitempty"`
	Loader         string          `json:"loader,omitempty"`
	Mappings       string          `json:"mappings,omitempty"`
	Signed         bool            `json:"signed"`
	Verdict        string          `json:"verdict"`
	Proof          string          `json:"proof"`
	HashMatch      bool            `json:"hash_match"`
	KnownName      string          `json:"known_name,omitempty"`
	Risk           int             `json:"risk"`
	CodeScore      int             `json:"code_score"`
	ContextScore   int             `json:"context_score"`
	Confidence     int             `json:"confidence"`
	Obfuscation    int             `json:"obfuscation"`
	ClassCount     int             `json:"class_count"`
	Categories     []CategoryScore `json:"categories,omitempty"`
	Findings       []Finding       `json:"findings,omitempty"`
	Modules        []ModuleHit     `json:"modules,omitempty"`
	Natives        []NativeInfo    `json:"natives,omitempty"`
	Notes          []string        `json:"notes,omitempty"`
	DecompiledDir  string          `json:"decompiled_dir,omitempty"`
	DecompileError string          `json:"decompile_error,omitempty"`
	Error          string          `json:"error,omitempty"`
	DurationMS     int64           `json:"duration_ms"`
	ScannedAt      time.Time       `json:"scanned_at"`
}

// Progress is emitted while scanning.
type Progress struct {
	Index   int
	Total   int
	Path    string
	Stage   string
	Result  *ScanResult
	Message string
}

// Report is the top-level JSON report.
type Report struct {
	Tool       string        `json:"tool"`
	Version    string        `json:"version"`
	StartedAt  time.Time     `json:"started_at"`
	FinishedAt time.Time     `json:"finished_at"`
	Roots      []string      `json:"roots"`
	Options    Options       `json:"options"`
	Results    []*ScanResult `json:"results"`
	Summary    Summary       `json:"summary"`
}

// Summary aggregates the scan.
type Summary struct {
	Total      int `json:"total"`
	Clean      int `json:"clean"`
	Possible   int `json:"possible"`
	Suspicious int `json:"suspicious"`
	Cheat      int `json:"cheat"`
	Errors     int `json:"errors"`
}

var CategoryNames = map[string]string{
	"combat":      "Combat",
	"movement":    "Movement",
	"world":       "World",
	"render":      "Render",
	"player":      "Player",
	"misc":        "Misc",
	"exploit":     "Exploit",
	"client":      "Client",
	"hitbox":      "Hitbox",
	"ghost":       "Ghost",
	"autobuy":     "AutoBuy",
	"native":      "Native",
	"obfuscation": "Obfuscation",
	"mixin":       "Mixin",
	"utility":     "Utility",
	"trusted":     "Trusted",
}

var SeverityRU = map[int]string{
	1: "инфо",
	2: "низкий",
	3: "средний",
	4: "высокий",
	5: "критический",
}

func categoryLabel(c string) string {
	if s, ok := CategoryNames[c]; ok {
		return s
	}
	return c
}

// ProofRU returns a Russian label for a proof level.
func ProofRU(p string) string {
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
