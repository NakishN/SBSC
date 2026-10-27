package engine

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"math"
	"path/filepath"
	"strings"
)

type KnownEntry struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Category  string    `json:"category"`
	Severity  int       `json:"severity"`
	Weight    int       `json:"weight"`
	Kind      string    `json:"kind"`
	Aliases   []string  `json:"aliases"`
	SizesKB   []float64 `json:"sizes_kb"`
	SizeMinKB float64   `json:"size_min_kb"`
	SizeMaxKB float64   `json:"size_max_kb"`
	Versions  string    `json:"versions"`
	Comment   string    `json:"comment"`
	Proof     string    `json:"proof"`
	Paths     []string  `json:"paths"`
	Pseudo    bool      `json:"pseudo"`
}

type KnownDB struct {
	Entries []*KnownEntry
}

func LoadKnown(fsys fs.FS) (*KnownDB, error) {
	var doc struct {
		Entries []*KnownEntry `json:"entries"`
	}
	b, err := fs.ReadFile(fsys, "rules/known.json")
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("known.json: %w", err)
	}
	for _, e := range doc.Entries {
		if e == nil {
			continue
		}
		for i := range e.Aliases {
			e.Aliases[i] = normalizeToken(e.Aliases[i])
		}
		for i := range e.Paths {
			e.Paths[i] = strings.ToLower(strings.ReplaceAll(e.Paths[i], "\\", "/"))
		}
	}
	return &KnownDB{Entries: doc.Entries}, nil
}

func aliasMatchStrong(base string, aliases []string) (bool, bool) {
	match, strong := false, false
	for _, a := range aliases {
		if !aliasMatch(base, []string{a}) {
			continue
		}
		match = true
		if a == base || len(a) >= 8 {
			strong = true
		}
	}
	return match, strong
}

func aliasMatch(base string, aliases []string) bool {
	for _, a := range aliases {
		if a == "" {
			continue
		}
		if len(a) <= 3 {
			if base == a {
				return true
			}
			if strings.HasPrefix(base, a) && len(base) > len(a) && base[len(a)] >= '0' && base[len(a)] <= '9' {
				return true
			}
			continue
		}
		if strings.Contains(base, a) {
			return true
		}
	}
	return false
}

func knownSizeMatch(e *KnownEntry, kb float64) bool {
	tol := math.Max(8, math.Min(200, kb*0.02))
	if kb < 20 {
		tol = math.Max(2, kb*0.08)
	}
	for _, s := range e.SizesKB {
		if math.Abs(kb-s) <= tol {
			return true
		}
	}
	if e.SizeMinKB > 0 && e.SizeMaxKB >= e.SizeMinKB {
		if kb >= e.SizeMinKB-tol && kb <= e.SizeMaxKB+tol {
			return true
		}
	}
	return false
}

func strongKnownPath(p string) bool {
	// Only package-like internal paths are strong evidence. Bare .class names
	// (render.class, clientplayerinteractionmanagermixin.class) occur in many
	// unrelated mods and are not enough.
	return strings.Contains(p, "/") && len(p) >= 8
}

func knownPathMatch(e *KnownEntry, haystack []string) (bool, bool, string) {
	paths := make([]string, 0, len(e.Paths))
	for _, p := range e.Paths {
		p = strings.ToLower(p)
		if p == "" || !strongKnownPath(p) {
			continue
		}
		paths = append(paths, p)
	}
	if len(paths) == 0 {
		return false, false, ""
	}
	for _, h := range haystack {
		for _, p := range paths {
			if strings.Contains(h, p) {
				return true, true, p
			}
		}
	}
	return false, false, ""
}

func (e *Engine) matchKnownJar(ja *jarAnalysis) []Finding {
	if e.rules.Known == nil {
		return nil
	}
	base := normalizeToken(strings.TrimSuffix(ja.Name, filepath.Ext(ja.Name)))
	kb := float64(ja.Size) / 1024.0
	haystack := make([]string, 0, len(ja.Paths)+len(ja.Tokens.Classes)+len(ja.Tokens.ClassSimple))
	haystack = append(haystack, ja.Paths...)
	haystack = append(haystack, ja.Tokens.Classes...)
	haystack = append(haystack, ja.Tokens.ClassSimple...)
	haystack = append(haystack, ja.Tokens.Meta...)
	for i, h := range haystack {
		haystack[i] = strings.ToLower(h)
	}

	type hit struct {
		f Finding
		e *KnownEntry
	}
	var hits []hit
	for _, ke := range e.rules.Known.Entries {
		if ke.Kind != "" && ke.Kind != "jar" && ke.Kind != "any" {
			continue
		}
		nameMatch, strongName := aliasMatchStrong(base, ke.Aliases)
		sizeMatch := knownSizeMatch(ke, kb)
		pathMatch, strongPath, matchedPath := knownPathMatch(ke, haystack)
		// Size alone is never enough: identical sizes are common.
		if !nameMatch && !pathMatch {
			continue
		}
		if ke.Pseudo && !strongPath && !sizeMatch {
			// Pseudo entries require at least the expected size; otherwise a
			// clean version with the same name (IAS etc.) would be flagged.
			continue
		}
		score := 0
		if strongPath {
			score = ke.Weight
		}
		if nameMatch && sizeMatch {
			cap := 35
			if strongName {
				cap = 70
			}
			score = maxInt(score, minInt(ke.Weight, cap))
		}
		if nameMatch && !sizeMatch {
			score = maxInt(score, minInt(30, int(float64(ke.Weight)*0.35)))
		}
		if nameMatch {
			score += 5
		}
		if score > 100 {
			score = 100
		}
		if ke.Pseudo && !strongPath {
			score = minInt(score, 30)
		}
		if !ke.Pseudo && nameMatch && !sizeMatch && !strongPath {
			score = minInt(score, 60)
		}
		if score < 8 {
			continue
		}
		var ev []string
		ev = append(ev, "файл: "+ja.Name)
		if nameMatch {
			ev = append(ev, "имя совпало")
		}
		if sizeMatch {
			ev = append(ev, fmt.Sprintf("размер: %.1f KB (совпал)", kb))
		} else if len(ke.SizesKB) > 0 || ke.SizeMinKB > 0 {
			ev = append(ev, fmt.Sprintf("размер: %.1f KB (не совпал, ожидалось %s)", kb, knownSizesText(ke)))
		}
		if matchedPath != "" {
			ev = append(ev, "внутренний путь: "+matchedPath)
		}
		if ke.Versions != "" {
			ev = append(ev, "версии: "+ke.Versions)
		}
		if ke.Proof != "" {
			ev = append(ev, "доказательство: "+truncate(ke.Proof, 200))
		}
		if ke.Comment != "" {
			ev = append(ev, "комментарий: "+ke.Comment)
		}
		title := "Известный чит: " + ke.Name
		if ke.Pseudo {
			title = "Pseudo-мод: " + ke.Name
		} else if ke.Category == "utility" || ke.Category == "exploit" {
			title = "Известный мод (проверить): " + ke.Name
		}
		f := Finding{
			RuleID:      ke.ID,
			Title:       title,
			Category:    ke.Category,
			Severity:    ke.Severity,
			Weight:      score,
			Description: knownDescription(ke, score, sizeMatch),
			Evidence:    dedupeStrings(ev, 8),
			Source:      "known",
		}
		hits = append(hits, hit{f: f, e: ke})
	}
	// Keep the strongest hit per entry name.
	best := make(map[string]Finding)
	for _, h := range hits {
		key := h.e.Name + "|" + h.e.Category
		if old, ok := best[key]; !ok || h.f.Weight > old.Weight {
			best[key] = h.f
		}
	}
	out := make([]Finding, 0, len(best))
	for _, f := range best {
		out = append(out, f)
	}
	sortFindings(out)
	if len(out) > 4 {
		out = out[:4]
	}
	return out
}

func (e *Engine) matchKnownNative(ni *NativeInfo) []Finding {
	if e.rules.Known == nil {
		return nil
	}
	base := normalizeToken(strings.TrimSuffix(ni.Name, filepath.Ext(ni.Name)))
	kb := float64(ni.Size) / 1024.0
	haystack := append([]string{}, ni.Imports...)
	haystack = append(haystack, ni.Exports...)
	haystack = append(haystack, ni.Strings...)
	haystack = append(haystack, ni.Name, ni.Path)
	for i, h := range haystack {
		haystack[i] = strings.ToLower(h)
	}
	var out []Finding
	for _, ke := range e.rules.Known.Entries {
		if ke.Kind == "jar" {
			continue
		}
		if ke.Kind != "" && ke.Kind != "dll" && ke.Kind != "exe" && ke.Kind != "any" {
			continue
		}
		nameMatch, strongName := aliasMatchStrong(base, ke.Aliases)
		sizeMatch := knownSizeMatch(ke, kb)
		pathMatch, strongPath, matchedPath := knownPathMatch(ke, haystack)
		if !nameMatch && !pathMatch {
			continue
		}
		score := 0
		if strongPath {
			score = ke.Weight
		}
		if nameMatch && sizeMatch {
			cap := 45
			if strongName {
				cap = 70
			}
			score = maxInt(score, minInt(ke.Weight, cap))
		}
		if nameMatch && !sizeMatch {
			score = maxInt(score, minInt(35, int(float64(ke.Weight)*0.4)))
		}
		if nameMatch {
			score += 5
		}
		if score > 100 {
			score = 100
		}
		if score < 8 {
			continue
		}
		ev := []string{"файл: " + ni.Name}
		if nameMatch {
			ev = append(ev, "имя совпало")
		}
		if sizeMatch {
			ev = append(ev, fmt.Sprintf("размер: %.1f KB (совпал)", kb))
		}
		if matchedPath != "" {
			ev = append(ev, "строка/путь: "+matchedPath)
		}
		if ke.Versions != "" {
			ev = append(ev, "версии: "+ke.Versions)
		}
		if ke.Comment != "" {
			ev = append(ev, "комментарий: "+ke.Comment)
		}
		out = append(out, Finding{
			RuleID: ke.ID, Title: "Известный нативный чит: " + ke.Name, Category: ke.Category,
			Severity: ke.Severity, Weight: score, Description: knownDescription(ke, score, sizeMatch),
			Evidence: dedupeStrings(ev, 8), Source: "known",
		})
	}
	sortFindings(out)
	// keep one per name
	best := make(map[string]Finding)
	for _, f := range out {
		key := f.Title
		if old, ok := best[key]; !ok || f.Weight > old.Weight {
			best[key] = f
		}
	}
	out = out[:0]
	for _, f := range best {
		out = append(out, f)
	}
	sortFindings(out)
	if len(out) > 3 {
		out = out[:3]
	}
	return out
}

func knownSizesText(e *KnownEntry) string {
	var parts []string
	for _, s := range e.SizesKB {
		parts = append(parts, fmt.Sprintf("%.1f", s))
	}
	if e.SizeMinKB > 0 {
		parts = append(parts, fmt.Sprintf("%.1f-%.1f", e.SizeMinKB, e.SizeMaxKB))
	}
	return strings.Join(parts, " | ") + " KB"
}

func applyNativeVerdict(ni *NativeInfo) {
	switch {
	case ni.Risk >= 70:
		ni.Verdict = "ЧИТ-КЛИЕНТ"
	case ni.Risk >= 45:
		ni.Verdict = "ПОДОЗРИТЕЛЬНЫЙ"
	case ni.Risk >= 25:
		ni.Verdict = "ВОЗМОЖНО ЧИТ"
	default:
		ni.Verdict = "ЧИСТО"
	}
}

func knownDescription(e *KnownEntry, score int, sizeMatch bool) string {
	d := fmt.Sprintf("Совпадение с базой известных читов/модов (%s). Это контекст, а не доказательство: вердикт подтверждается находками в коде.", e.Name)
	if e.Pseudo {
		d += " Это pseudo-мод: в легитимный мод внедрены чит-классы; проверьте внутренности."
	}
	if e.Comment != "" {
		d += " " + e.Comment
	}
	if e.Versions != "" {
		d += " Версии: " + e.Versions + "."
	}
	if !sizeMatch && len(e.SizesKB) > 0 {
		d += " Размер не совпал — возможно, другая версия или перепаковка."
	}
	d += fmt.Sprintf(" Оценка совпадения: %d/100.", score)
	return d
}

func sortFindings(fs []Finding) {
	for i := 1; i < len(fs); i++ {
		for j := i; j > 0 && fs[j].Weight > fs[j-1].Weight; j-- {
			fs[j], fs[j-1] = fs[j-1], fs[j]
		}
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
