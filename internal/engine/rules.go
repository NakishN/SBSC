package engine

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"
)

type Condition struct {
	Type  string `json:"type"`
	Regex string `json:"regex"`
}

type Rule struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Category    string      `json:"category"`
	Severity    int         `json:"severity"`
	Weight      int         `json:"weight"`
	All         []Condition `json:"all"`
	Any         []Condition `json:"any"`
	None        []Condition `json:"none"`
}

type compiledCond struct {
	typ string
	re  *regexp.Regexp
}

type CompiledRule struct {
	Rule
	all  []compiledCond
	any  []compiledCond
	none []compiledCond
}

type ModuleDef struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	NameRU      string   `json:"name_ru"`
	Category    string   `json:"category"`
	Aliases     []string `json:"aliases"`
	Severity    int      `json:"severity"`
	Weight      int      `json:"weight"`
	QoL         bool     `json:"qol"`
	Description string   `json:"description"`
}

type ModuleIndex struct {
	byAlias map[string][]*ModuleDef
	all     []*ModuleDef
}

func (m *ModuleIndex) Lookup(token string) []*ModuleDef {
	if token == "" {
		return nil
	}
	return m.byAlias[token]
}

func (m *ModuleIndex) All() []*ModuleDef { return m.all }

type RuleSet struct {
	Clients   []*CompiledRule
	Behaviors []*CompiledRule
	Native    []*CompiledRule
	Modules   *ModuleIndex
	Known     *KnownDB
	Hashes    *HashDB
}

func loadJSON(fsys fs.FS, name string, dst any) error {
	b, err := fs.ReadFile(fsys, name)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, dst); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

func compileRule(r Rule) (*CompiledRule, error) {
	cr := &CompiledRule{Rule: r}
	for _, group := range []struct {
		src []Condition
		dst *[]compiledCond
	}{{r.All, &cr.all}, {r.Any, &cr.any}, {r.None, &cr.none}} {
		for _, c := range group.src {
			re, err := regexp.Compile(c.Regex)
			if err != nil {
				return nil, fmt.Errorf("rule %s: invalid regex %q: %w", r.ID, c.Regex, err)
			}
			*group.dst = append(*group.dst, compiledCond{typ: strings.ToLower(c.Type), re: re})
		}
	}
	return cr, nil
}

func compileRules(rules []Rule) ([]*CompiledRule, error) {
	out := make([]*CompiledRule, 0, len(rules))
	for _, r := range rules {
		cr, err := compileRule(r)
		if err != nil {
			return nil, err
		}
		out = append(out, cr)
	}
	return out, nil
}

func loadRuleFile(fsys fs.FS, name string) ([]Rule, error) {
	var doc struct {
		Rules []Rule `json:"rules"`
	}
	if err := loadJSON(fsys, name, &doc); err != nil {
		return nil, err
	}
	return doc.Rules, nil
}

func LoadRules(fsys fs.FS) (*RuleSet, error) {
	rs := &RuleSet{}
	var err error
	if rs.Clients, err = loadCompiled(fsys, "rules/clients.json"); err != nil {
		return nil, err
	}
	if rs.Behaviors, err = loadCompiled(fsys, "rules/behaviors.json"); err != nil {
		return nil, err
	}
	if rs.Native, err = loadCompiled(fsys, "rules/native.json"); err != nil {
		return nil, err
	}

	var modDoc struct {
		Modules []*ModuleDef `json:"modules"`
	}
	if err := loadJSON(fsys, "rules/modules.json", &modDoc); err != nil {
		return nil, err
	}
	idx := &ModuleIndex{byAlias: make(map[string][]*ModuleDef)}
	for _, m := range modDoc.Modules {
		if m == nil || m.ID == "" {
			continue
		}
		idx.all = append(idx.all, m)
		seen := map[string]bool{}
		for _, a := range append([]string{m.ID}, m.Aliases...) {
			a = normalizeToken(a)
			if len(a) < 3 || seen[a] {
				continue
			}
			seen[a] = true
			idx.byAlias[a] = append(idx.byAlias[a], m)
		}
	}
	rs.Modules = idx
	if rs.Known, err = LoadKnown(fsys); err != nil {
		return nil, err
	}
	if rs.Hashes, err = LoadHashes(fsys); err != nil {
		return nil, err
	}
	return rs, nil
}

func loadCompiled(fsys fs.FS, name string) ([]*CompiledRule, error) {
	rules, err := loadRuleFile(fsys, name)
	if err != nil {
		return nil, err
	}
	return compileRules(rules)
}

// normalizeToken lowercases and strips everything except a-z0-9.
func normalizeToken(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

var moduleSuffixes = []string{"module", "hack", "feature", "cheat", "mod"}
var modulePrefixes = []string{"module", "hack", "feature"}

// normalizeClassToken normalizes a class simple name and removes common module
// suffixes/prefixes, so KillAuraHack, KillAuraModule and KillAura all match.
func normalizeClassToken(s string) string {
	n := normalizeToken(s)
	for _, p := range modulePrefixes {
		if strings.HasPrefix(n, p) && len(n) > len(p)+2 {
			n = strings.TrimPrefix(n, p)
			break
		}
	}
	for _, suf := range moduleSuffixes {
		if strings.HasSuffix(n, suf) && len(n) > len(suf)+2 {
			n = strings.TrimSuffix(n, suf)
			break
		}
	}
	return n
}

// normalizeMethodToken strips common accessor/event prefixes.
func normalizeMethodToken(s string) string {
	n := normalizeToken(s)
	for _, p := range []string{"on", "handle", "update", "render", "toggle", "enable", "disable", "do", "get", "set", "is", "has", "can"} {
		if strings.HasPrefix(n, p) && len(n) > len(p)+3 {
			n = strings.TrimPrefix(n, p)
			break
		}
	}
	return n
}

type TokenSet struct {
	Classes     []string
	ClassSimple []string
	Strings     []string
	Methods     []string
	Fields      []string
	Refs        []string
	Paths       []string
	Meta        []string
	Imports     []string
	Exports     []string
	DLLStrings  []string
	All         []string
}

func (t *TokenSet) buildAll() {
	seen := make(map[string]struct{}, len(t.Classes)+len(t.Strings)+len(t.Refs))
	t.All = t.All[:0]
	add := func(xs ...[]string) {
		for _, xs := range xs {
			for _, x := range xs {
				if x == "" {
					continue
				}
				if _, ok := seen[x]; ok {
					continue
				}
				seen[x] = struct{}{}
				t.All = append(t.All, x)
			}
		}
	}
	add(t.Classes, t.ClassSimple, t.Strings, t.Methods, t.Fields, t.Refs, t.Paths, t.Meta, t.Imports, t.Exports, t.DLLStrings)
}

func tokensFor(condType string, t *TokenSet) []string {
	switch condType {
	case "class":
		return t.Classes
	case "class_simple", "simple_class":
		return t.ClassSimple
	case "string":
		return t.Strings
	case "method":
		return t.Methods
	case "field":
		return t.Fields
	case "ref":
		return t.Refs
	case "path":
		return t.Paths
	case "meta":
		return t.Meta
	case "import":
		return t.Imports
	case "export":
		return t.Exports
	case "dll_string", "native_string":
		return t.DLLStrings
	case "any", "":
		return t.All
	default:
		return t.All
	}
}

func matchCond(c compiledCond, t *TokenSet) []string {
	tokens := tokensFor(c.typ, t)
	var ev []string
	for _, tok := range tokens {
		if c.re.MatchString(tok) {
			ev = append(ev, truncate(tok, 240))
			if len(ev) >= 6 {
				break
			}
		}
	}
	return ev
}

func matchRule(r *CompiledRule, t *TokenSet) (Finding, bool) {
	var evidence []string
	for _, c := range r.none {
		if ev := matchCond(c, t); len(ev) > 0 {
			return Finding{}, false
		}
	}
	for _, c := range r.all {
		ev := matchCond(c, t)
		if len(ev) == 0 {
			return Finding{}, false
		}
		evidence = append(evidence, ev...)
	}
	if len(r.any) > 0 {
		var anyEv []string
		for _, c := range r.any {
			if ev := matchCond(c, t); len(ev) > 0 {
				anyEv = append(anyEv, ev...)
				if len(anyEv) >= 8 {
					break
				}
			}
		}
		if len(anyEv) == 0 {
			return Finding{}, false
		}
		evidence = append(evidence, anyEv...)
	}
	if len(r.all) == 0 && len(r.any) == 0 {
		return Finding{}, false
	}
	return Finding{
		RuleID:      r.ID,
		Title:       r.Name,
		Category:    r.Category,
		Severity:    r.Severity,
		Weight:      r.Weight,
		Description: r.Description,
		Evidence:    dedupeStrings(evidence, 8),
	}, true
}

func dedupeStrings(in []string, limit int) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
