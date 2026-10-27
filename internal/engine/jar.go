package engine

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
)

type jarAnalysis struct {
	Path         string
	Name         string
	Size         int64
	SHA256       string
	Classes      []*ClassFile
	Tokens       TokenSet
	Meta         []string
	RootMeta     []string
	Paths        []string
	RootPaths    []string
	Natives      []NativeInfo
	Findings     []Finding
	Modules      []ModuleHit
	Signed       bool
	MCVersion    string
	Loader       string
	Mappings     string
	Obfuscation  int
	CodeScore    int
	ContextScore int
	Proof        string
	Notes        []string
	ClassCount   int
	Suspects     []string
	ClientName   string
	NativeFlag   bool
	NestedJars   int
	ParseErrors  int
}

type tokenCollector struct {
	seen  map[string]struct{}
	limit int
	out   []string
}

func newTokenCollector(limit int) *tokenCollector {
	return &tokenCollector{seen: make(map[string]struct{}), limit: limit}
}

func (c *tokenCollector) add(s string) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 500 {
		return
	}
	if c.limit > 0 && len(c.out) >= c.limit {
		return
	}
	if _, ok := c.seen[s]; ok {
		return
	}
	c.seen[s] = struct{}{}
	c.out = append(c.out, s)
}

func (c *tokenCollector) addAll(xs ...string) {
	for _, x := range xs {
		c.add(x)
	}
}

func (c *tokenCollector) list() []string { return c.out }

func (e *Engine) analyzeJar(filePath string, data []byte, depth int) (*jarAnalysis, error) {
	sum := sha256.Sum256(data)
	ja := &jarAnalysis{
		Path:   filePath,
		Name:   path.Base(strings.ReplaceAll(filePath, "\\", "/")),
		Size:   int64(len(data)),
		SHA256: hex.EncodeToString(sum[:]),
	}
	if err := e.analyzeJarInto(ja, data, depth); err != nil {
		return ja, err
	}
	e.finishJar(ja)
	return ja, nil
}

func (e *Engine) analyzeJarInto(ja *jarAnalysis, data []byte, depth int) error {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		// Some repacked jars have zero padding after the ZIP EOCD.
		if trimmed := stripZipPadding(data); len(trimmed) != len(data) {
			if zr2, err2 := zip.NewReader(bytes.NewReader(trimmed), int64(len(trimmed))); err2 == nil {
				zr, err = zr2, nil
			}
		}
	}
	if err != nil {
		return fmt.Errorf("zip: %w", err)
	}
	classTok := newTokenCollector(200000)
	simpleTok := newTokenCollector(100000)
	stringTok := newTokenCollector(300000)
	methodTok := newTokenCollector(200000)
	fieldTok := newTokenCollector(100000)
	refTok := newTokenCollector(400000)
	pathTok := newTokenCollector(50000)
	metaTok := newTokenCollector(50000)
	dllStringTok := newTokenCollector(50000)

	var totalUncompressed int64
	for _, f := range zr.File {
		name := strings.ReplaceAll(f.Name, "\\", "/")
		if name == "" || strings.HasSuffix(name, "/") {
			continue
		}
		pathTok.add(name)
		if depth == 0 {
			ja.RootPaths = append(ja.RootPaths, name)
		}
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "meta-inf/") {
			base := strings.ToLower(path.Base(lower))
			if strings.HasSuffix(base, ".sf") || strings.HasSuffix(base, ".rsa") || strings.HasSuffix(base, ".dsa") || strings.HasSuffix(base, ".ec") {
				ja.Signed = true
			}
			if strings.Contains(lower, "services/java.lang.instrument.instrumentation") {
				metaTok.add("META-INF/services/java.lang.instrument.Instrumentation")
			}
		}

		size := int64(f.UncompressedSize64)
		if size < 0 || size > e.opts.maxSize() {
			ja.Notes = append(ja.Notes, fmt.Sprintf("пропущен большой файл: %s (%d байт)", name, size))
			continue
		}
		totalUncompressed += size
		if totalUncompressed > 800<<20 {
			ja.Notes = append(ja.Notes, "распаковка остановлена: суммарный размер > 800 МБ")
			break
		}

		switch {
		case strings.HasSuffix(lower, ".class"):
			b, err := readZipFile(f, 20<<20)
			if err != nil {
				ja.ParseErrors++
				continue
			}
			cf, err := parseClassFile(name, b)
			if err != nil {
				ja.ParseErrors++
				continue
			}
			ja.Classes = append(ja.Classes, cf)
			classTok.addAll(cf.Name, cf.Super)
			classTok.addAll(cf.Interfaces...)
			classTok.addAll(cf.ClassRefs...)
			simpleTok.add(simpleClassName(cf.Name))
			stringTok.addAll(cf.Strings...)
			for _, m := range cf.Methods {
				methodTok.add(m.Name)
			}
			for _, fld := range cf.Fields {
				fieldTok.add(fld.Name)
			}
			refTok.addAll(cf.MethodRefs...)
			refTok.addAll(cf.FieldRefs...)
			refTok.addAll(cf.ClassRefs...)

		case strings.HasSuffix(lower, ".jar"):
			if depth >= 2 {
				continue
			}
			b, err := readZipFile(f, 128<<20)
			if err != nil {
				continue
			}
			ja.NestedJars++
			nested, err := e.analyzeJar(ja.Path+"!/"+name, b, depth+1)
			if err != nil {
				ja.Notes = append(ja.Notes, fmt.Sprintf("вложенный jar %s: %v", name, err))
				continue
			}
			mergeJarAnalysis(ja, nested, classTok, simpleTok, stringTok, methodTok, fieldTok, refTok, pathTok, metaTok, dllStringTok)
			ja.Notes = append(ja.Notes, fmt.Sprintf("вложенный jar: %s", name))

		case strings.HasSuffix(lower, ".so") || strings.HasSuffix(lower, ".dylib"):
			// PE analysis does not apply to ELF/Mach-O; record the native
			// library as a note instead of producing a parse error.
			ni := NativeInfo{Path: name, Name: path.Base(name), Size: int64(f.UncompressedSize64), Embedded: true, Verdict: "Не PE (ELF/Mach-O)"}
			ja.Natives = append(ja.Natives, ni)
			ja.Notes = append(ja.Notes, "нативная библиотека (не PE): "+name)

		case strings.HasSuffix(lower, ".dll") || strings.HasSuffix(lower, ".exe"):
			b, err := readZipFile(f, 64<<20)
			if err != nil {
				continue
			}
			ni := analyzePE(name, b, true, e.rules, true)
			if ni != nil {
				ja.Natives = append(ja.Natives, *ni)
				dllStringTok.addAll(ni.Imports...)
				dllStringTok.addAll(ni.Exports...)
				dllStringTok.addAll(ni.Notes...)
				if !ni.Trusted && ni.Risk >= 60 {
					ja.NativeFlag = true
				}
			}

		case isTextEntry(lower):
			b, err := readZipFile(f, 3<<20)
			if err != nil {
				continue
			}
			toks := extractTextTokens(name, b)
			metaTok.addAll(toks...)
			if depth == 0 {
				ja.RootMeta = append(ja.RootMeta, toks...)
			}
			if strings.HasSuffix(lower, ".json") {
				js := jsonStrings(b)
				metaTok.addAll(js...)
				if depth == 0 {
					ja.RootMeta = append(ja.RootMeta, js...)
				}
			}
		}
	}

	ja.Tokens.Classes = append(ja.Tokens.Classes, classTok.list()...)
	ja.Tokens.ClassSimple = append(ja.Tokens.ClassSimple, simpleTok.list()...)
	ja.Tokens.Strings = append(ja.Tokens.Strings, stringTok.list()...)
	ja.Tokens.Methods = append(ja.Tokens.Methods, methodTok.list()...)
	ja.Tokens.Fields = append(ja.Tokens.Fields, fieldTok.list()...)
	ja.Tokens.Refs = append(ja.Tokens.Refs, refTok.list()...)
	ja.Tokens.Paths = append(ja.Tokens.Paths, pathTok.list()...)
	ja.Tokens.Meta = append(ja.Tokens.Meta, metaTok.list()...)
	ja.Tokens.DLLStrings = append(ja.Tokens.DLLStrings, dllStringTok.list()...)
	ja.Tokens.buildAll()
	ja.Meta = metaTok.list()
	ja.Paths = pathTok.list()
	ja.ClassCount = len(ja.Classes)
	return nil
}

func stripZipPadding(data []byte) []byte {
	idx := bytes.LastIndex(data, []byte("PK\x05\x06"))
	if idx < 0 || idx+22 > len(data) {
		return data
	}
	commentLen := int(data[idx+20]) | int(data[idx+21])<<8
	end := idx + 22 + commentLen
	if end > 0 && end < len(data) {
		return data[:end]
	}
	return data
}

func mergeJarAnalysis(dst, src *jarAnalysis, classTok, simpleTok, stringTok, methodTok, fieldTok, refTok, pathTok, metaTok, dllStringTok *tokenCollector) {
	dst.Classes = append(dst.Classes, src.Classes...)
	dst.Natives = append(dst.Natives, src.Natives...)
	dst.Signed = dst.Signed || src.Signed
	if src.ClientName != "" && dst.ClientName == "" {
		dst.ClientName = src.ClientName
	}
	classTok.addAll(src.Tokens.Classes...)
	simpleTok.addAll(src.Tokens.ClassSimple...)
	stringTok.addAll(src.Tokens.Strings...)
	methodTok.addAll(src.Tokens.Methods...)
	fieldTok.addAll(src.Tokens.Fields...)
	refTok.addAll(src.Tokens.Refs...)
	pathTok.addAll(src.Tokens.Paths...)
	metaTok.addAll(src.Tokens.Meta...)
	dllStringTok.addAll(src.Tokens.DLLStrings...)
	dst.ParseErrors += src.ParseErrors
	dst.NestedJars += src.NestedJars
	dst.Notes = append(dst.Notes, src.Notes...)
}

func (e *Engine) finishJar(ja *jarAnalysis) {
	ja.Tokens.buildAll()
	ja.MCVersion = detectMCVersion(ja)
	ja.Loader = detectLoader(ja)
	ja.Mappings = detectMappings(ja)
	ja.Obfuscation = computeObfuscation(ja.Classes, ja.Tokens.Strings)
	ja.Findings, ja.Modules, ja.ClientName = e.matchJarRules(ja)
	if ja.NativeFlag {
		ja.Notes = append(ja.Notes, "обнаружены признаки нативного загрузчика")
	}
	for _, n := range ja.Natives {
		if !n.Trusted && n.Risk >= 60 {
			ja.NativeFlag = true
			break
		}
	}
	ja.Suspects = collectSuspects(ja)
	if ja.Obfuscation >= 15 {
		ja.Notes = append(ja.Notes, fmt.Sprintf("высокая обфускация (оценка %d/25)", ja.Obfuscation))
	}
	if ja.ParseErrors > 0 {
		ja.Notes = append(ja.Notes, fmt.Sprintf("не удалось разобрать классов: %d", ja.ParseErrors))
	}
	if ja.Signed {
		ja.Notes = append(ja.Notes, "jar содержит цифровую подпись (не гарантирует безопасность)")
	}
}

func (e *Engine) matchJarRules(ja *jarAnalysis) (findings []Finding, modules []ModuleHit, clientName string) {
	t := &ja.Tokens
	// Client fingerprints.
	var clientFindings []Finding
	for _, r := range e.rules.Clients {
		if f, ok := matchRule(r, t); ok {
			f.Source = "jar"
			clientFindings = append(clientFindings, f)
		}
	}
	sort.Slice(clientFindings, func(i, j int) bool { return clientFindings[i].Weight > clientFindings[j].Weight })
	if len(clientFindings) > 0 {
		clientName = clientFindings[0].Title
		if len(clientFindings) > 3 {
			clientFindings = clientFindings[:3]
		}
		findings = append(findings, clientFindings...)
	}
	hasClient := len(clientFindings) > 0

	// Behaviour rules are evaluated per class. This is critical: matching
	// conditions across a whole 1000-class mod produces nonsense.
	beh := e.matchRuntimeRules(ja, e.rules.Behaviors)
	findings = append(findings, beh...)

	// Known-cheat database: exact file names, sizes and internal paths.
	known := e.matchKnownJar(ja)
	findings = append(findings, known...)
	for _, f := range known {
		if (f.Category == "client" || f.Category == "ghost") && clientName == "" {
			clientName = f.Title
		}
		if f.Category == "native" && f.Weight >= 70 {
			ja.NativeFlag = true
		}
	}

	if ai := aiModelFindings(ja); len(ai) > 0 {
		findings = append(findings, ai...)
	}
	modules = matchModules(ja, e.rules.Modules, hasClient)
	if len(modules) > 0 {
		for i := range modules {
			if modules[i].Weight >= 8 && !modules[i].QoL {
				ja.Suspects = append(ja.Suspects, modules[i].Evidence...)
			}
		}
	}
	// This build is a cheat scanner: never expose or score malware findings.
	out := findings[:0]
	for _, f := range findings {
		if f.Category == "malware" {
			continue
		}
		out = append(out, f)
	}
	return out, modules, clientName
}

func ruleMetaOnly(r *CompiledRule) bool {
	groups := [][]compiledCond{r.all, r.any, r.none}
	for _, g := range groups {
		for _, c := range g {
			switch c.typ {
			case "meta", "path", "string":
			default:
				return false
			}
		}
	}
	return true
}

func classTokenSet(cf *ClassFile) *TokenSet {
	t := &TokenSet{}
	t.Classes = append(t.Classes, cf.Name, cf.Super)
	t.Classes = append(t.Classes, cf.Interfaces...)
	t.Classes = append(t.Classes, cf.ClassRefs...)
	t.ClassSimple = append(t.ClassSimple, simpleClassName(cf.Name))
	t.Strings = append(t.Strings, cf.Strings...)
	t.Methods = append(t.Methods, cf.MethodRefs...)
	for _, m := range cf.Methods {
		t.Methods = append(t.Methods, m.Name)
	}
	t.Fields = append(t.Fields, cf.FieldRefs...)
	for _, f := range cf.Fields {
		t.Fields = append(t.Fields, f.Name)
	}
	t.Refs = append(t.Refs, cf.ClassRefs...)
	t.Refs = append(t.Refs, cf.MethodRefs...)
	t.Refs = append(t.Refs, cf.FieldRefs...)
	t.Paths = append(t.Paths, cf.Path)
	t.buildAll()
	return t
}

func (e *Engine) matchRuntimeRules(ja *jarAnalysis, rules []*CompiledRule) []Finding {
	if len(rules) == 0 {
		return nil
	}
	best := make(map[string]Finding)
	merge := func(f Finding) {
		old, ok := best[f.RuleID]
		if !ok {
			best[f.RuleID] = f
			return
		}
		if f.Weight > old.Weight {
			old.Weight = f.Weight
			old.Class = f.Class
			old.Description = f.Description
		}
		old.Evidence = dedupeStrings(append(old.Evidence, f.Evidence...), 8)
		best[f.RuleID] = old
	}

	// JAR-wide rules are cheap. Class rules are evaluated once per class
	// below: building a TokenSet for every (rule, class) pair was the dominant
	// cost on large jars (tens of seconds on a 50 MB client).
	var classRules []*CompiledRule
	for _, r := range rules {
		if ruleMetaOnly(r) {
			if f, ok := matchRule(r, &ja.Tokens); ok {
				f.Source = "jar"
				merge(f)
			}
			continue
		}
		classRules = append(classRules, r)
	}
	if len(classRules) == 0 || len(ja.Classes) == 0 {
		out := make([]Finding, 0, len(best))
		for _, f := range best {
			out = append(out, f)
		}
		sortFindings(out)
		return out
	}

	// Split rules into ones with a required literal hint and ones without.
	// A class that contains none of the hints cannot match a hinted rule, so
	// most ordinary Minecraft/library classes skip the regexp engine entirely.
	var hintedRules, alwaysRules []*CompiledRule
	hintSeen := make(map[string]struct{})
	var hints []string
	for _, r := range classRules {
		hasHint := false
		groups := [][]compiledCond{r.all, r.any}
		for _, g := range groups {
			for _, c := range g {
				if len(c.hints) == 0 {
					continue
				}
				hasHint = true
				for _, h := range c.hints {
					if _, ok := hintSeen[h]; ok {
						continue
					}
					hintSeen[h] = struct{}{}
					hints = append(hints, h)
				}
			}
		}
		if hasHint {
			hintedRules = append(hintedRules, r)
		} else {
			alwaysRules = append(alwaysRules, r)
		}
	}

	var matcher *hintMatcher
	if len(hintedRules) > 0 && len(hints) > 0 {
		matcher = newHintMatcher(hints)
	}
	hasAnyHint := func(ts *TokenSet) bool {
		if len(hintedRules) == 0 || matcher == nil {
			return false
		}
		return matcher.Match(ts.joinedLowerFor("any"))
	}
	runClass := func(cf *ClassFile, emit func(Finding)) {
		ts := classTokenSet(cf)
		run := func(rules []*CompiledRule) {
			for _, r := range rules {
				if f, ok := matchRule(r, ts); ok {
					f.Source = "jar"
					f.Class = cf.Name
					emit(f)
				}
			}
		}
		run(alwaysRules)
		if hasAnyHint(ts) {
			run(hintedRules)
		}
	}

	if len(ja.Classes) < 32 || len(classRules) < 4 {
		for _, cf := range ja.Classes {
			runClass(cf, merge)
		}
	} else {
		workers := e.classWorkers()
		if workers > len(ja.Classes) {
			workers = len(ja.Classes)
		}
		jobs := make(chan *ClassFile)
		results := make(chan Finding)
		var wg sync.WaitGroup
		wg.Add(workers)
		for i := 0; i < workers; i++ {
			go func() {
				defer wg.Done()
				for cf := range jobs {
					runClass(cf, func(f Finding) { results <- f })
				}
			}()
		}
		go func() {
			for _, cf := range ja.Classes {
				jobs <- cf
			}
			close(jobs)
			wg.Wait()
			close(results)
		}()
		for f := range results {
			merge(f)
		}
	}

	out := make([]Finding, 0, len(best))
	for _, f := range best {
		out = append(out, f)
	}
	sortFindings(out)
	return out
}

func aiModelFindings(ja *jarAnalysis) []Finding {
	var ev []string
	for _, p := range ja.Paths {
		l := strings.ToLower(p)
		hit := false
		switch {
		case strings.HasSuffix(l, ".onnx"):
			hit = true
		case strings.HasSuffix(l, ".cbm"), strings.HasSuffix(l, ".model"), strings.HasSuffix(l, ".pt"), strings.HasSuffix(l, ".pth"):
			hit = strings.Contains(l, "aim") || strings.Contains(l, "yaw") || strings.Contains(l, "pitch") || strings.Contains(l, "rotation") || strings.Contains(l, "aura")
		case strings.Contains(l, "/neuro/") || strings.Contains(l, "neuro/profile") || strings.Contains(l, "rotation_predictor"):
			hit = true
		}
		if hit {
			ev = append(ev, p)
			if len(ev) >= 6 {
				break
			}
		}
	}
	if len(ev) == 0 {
		for _, s := range ja.Tokens.Strings {
			l := strings.ToLower(s)
			if strings.Contains(l, "onnxruntime") || strings.Contains(l, "catboost") || strings.Contains(l, "neuromodel") || strings.Contains(l, "rotation_predictor") || strings.Contains(l, "train_aura") || (strings.Contains(l, "gru") && strings.Contains(l, "yaw")) {
				ev = append(ev, s)
				if len(ev) >= 4 {
					break
				}
			}
		}
	}
	if len(ev) == 0 {
		return nil
	}
	return []Finding{{
		RuleID: "ai_aim_model", Title: "AI/ML модель для аима", Category: "combat",
		Severity: 5, Weight: 24, Source: "jar",
		Description: "В jar найдены ONNX/CatBoost/GRU-модели или код инференса для расчёта yaw/pitch — нейросетевой аимбот.",
		Evidence:    dedupeStrings(ev, 6),
	}}
}

func matchModules(ja *jarAnalysis, idx *ModuleIndex, hasClient bool) []ModuleHit {
	type acc struct {
		def      *ModuleDef
		weight   int
		context  bool
		evidence []string
	}
	hits := make(map[string]*acc)
	addHit := func(def *ModuleDef, token string, context bool, source string) {
		if def == nil {
			return
		}
		// Strings/methods/metadata are far too noisy in legitimate mods.
		// Only trust them when the jar looks like a module-based client or
		// the class itself is in a modules/hacks package.
		if source != "class" && !context && !hasClient {
			return
		}
		// A bare class named Timer/Step/Speed in a standard library is not a
		// cheat. For class-only matches without module context, only accept
		// highly specific module names.
		if source == "class" && !context && !hasClient {
			// Short/generic class names (Aim, Bed, ESP, Fly, Reach, Nuker…)
			// occur in ordinary libraries. Require a module package or a
			// specific, longer module name.
			if !specificModuleIDs[def.ID] || len(def.ID) < 6 {
				return
			}
		}
		a := hits[def.ID]
		if a == nil {
			a = &acc{def: def, context: context}
			hits[def.ID] = a
		}
		if context {
			a.context = true
		}
		w := def.Weight
		if !context && !hasClient {
			w = w / 3
			if w < 2 {
				w = 2
			}
		}
		if def.QoL && !context && !hasClient {
			w = 2
		}
		if w > a.weight {
			a.weight = w
		}
		if len(a.evidence) < 5 {
			a.evidence = append(a.evidence, token)
		}
	}

	for _, cf := range ja.Classes {
		context := hasClient || classModuleContext(cf)
		sn := simpleClassName(cf.Name)
		for _, def := range idx.Lookup(normalizeClassToken(sn)) {
			addHit(def, cf.Name, context, "class")
		}
		// Some clients name classes like KillAuraFeature$1; simpleClassName handles $.
		for _, s := range cf.Strings {
			if len(s) > 64 {
				continue
			}
			n := normalizeClassToken(s)
			if len(n) < 4 {
				continue
			}
			for _, def := range idx.Lookup(n) {
				addHit(def, cf.Name+" -> "+s, context, "string")
			}
		}
	}
	// Metadata / lang files / module registries.
	for _, s := range ja.Meta {
		if len(s) > 80 {
			continue
		}
		n := normalizeClassToken(s)
		if len(n) < 4 {
			continue
		}
		for _, def := range idx.Lookup(n) {
			addHit(def, "meta: "+truncate(s, 100), hasClient, "meta")
		}
	}

	out := make([]ModuleHit, 0, len(hits))
	for _, a := range hits {
		out = append(out, ModuleHit{
			ID: a.def.ID, Name: a.def.Name, NameRU: a.def.NameRU,
			Category: a.def.Category, Severity: a.def.Severity, Weight: a.weight,
			QoL: a.def.QoL, Context: a.context, Evidence: dedupeStrings(a.evidence, 5),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Weight != out[j].Weight {
			return out[i].Weight > out[j].Weight
		}
		return out[i].Name < out[j].Name
	})
	return out
}

var specificModuleIDs = map[string]bool{
	"killaura": true, "aimbot": true, "aimassist": true, "silentaim": true,
	"reach": true, "velocity": true, "antiknockback": true, "criticals": true, "autototem": true,
	"autocrystal": true, "crystalaura": true, "anchoraura": true, "bedaura": true, "bowaimbot": true,
	"triggerbot": true, "autoclicker": true, "antiaim": true, "spinbot": true, "backtrack": true,
	"fakelag": true, "tickbase": true, "timerange": true, "superknockback": true, "hitselect": true,
	"targetlock": true, "targetstrafe": true, "surround": true, "burrow": true, "holefiller": true,
	"selftrap": true, "selfweb": true, "autoweb": true, "blockin": true, "blocktrap": true,
	"offhand": true, "autobow": true, "autoprojectile": true, "projectileaimbot": true,
	"autoshoot": true, "autorod": true, "autododge": true, "fightbot": true, "antibot": true,
	"regen": true, "autolog": true, "keepsprint": true, "autoblock": true, "chestaura": true,
	"multiaura": true, "clickaura": true, "tpauras": true, "infiniteaura": true, "disabler": true,
	"nuker": true, "scaffold": true, "cheststealer": true, "speedmine": true, "godmode": true,
	"servercrasher": true, "crashexploit": true, "packetexploit": true, "forceop": true, "backdoor": true,
	"packetfly": true, "coordtp": true, "itemteleport": true, "clicktp": true, "ghosthand": true,
	"liquidinteract": true, "xray": true, "tracers": true, "chams": true, "wallhack": true,
	"storageesp": true, "holeesp": true, "nofall": true, "esp": true,
}

func classModuleContext(cf *ClassFile) bool {
	p := strings.ToLower(cf.Path)
	for _, seg := range []string{"/module/", "/modules/", "/hack/", "/hacks/", "/feature/", "/features/", "/cheat/", "/cheats/", "/impl/module/"} {
		if strings.Contains(p, seg) {
			return true
		}
	}
	sn := strings.ToLower(simpleClassName(cf.Name))
	for _, suf := range []string{"hack", "module", "feature", "cheat"} {
		if strings.HasSuffix(sn, suf) {
			return true
		}
	}
	for _, parent := range append([]string{cf.Super}, cf.Interfaces...) {
		low := strings.ToLower(parent)
		if strings.Contains(low, "module") || strings.Contains(low, "hack") || strings.Contains(low, "feature") || strings.Contains(low, "cheat") {
			return true
		}
	}
	return false
}

func collectSuspects(ja *jarAnalysis) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(s string) {
		if s == "" {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	for _, m := range ja.Modules {
		if m.Weight >= 8 && !m.QoL {
			for _, e := range m.Evidence {
				if i := strings.Index(e, " -> "); i >= 0 {
					e = e[:i]
				}
				if i := strings.Index(e, "#"); i >= 0 {
					e = e[:i]
				}
				add(e)
			}
		}
	}
	for _, cf := range ja.Classes {
		p := strings.ToLower(cf.Path)
		if strings.Contains(p, "mixin") || strings.Contains(p, "module") || strings.Contains(p, "hack") {
			add(cf.Name)
		}
		if len(out) >= 100 {
			break
		}
	}
	return out
}

func detectMCVersion(ja *jarAnalysis) string {
	re := regexp.MustCompile(`(?i)\b1\.(7|8|9|10|11|12|13|14|15|16|17|18|19|20|21)(?:\.(\d{1,2}))?`)
	counts := make(map[string]int)
	consider := func(s string) {
		for _, m := range re.FindAllString(s, -1) {
			counts[m]++
		}
	}
	for _, s := range ja.Tokens.Meta {
		consider(s)
	}
	for _, s := range ja.Tokens.Strings {
		if len(s) < 80 {
			consider(s)
		}
	}
	if len(counts) == 0 {
		return ""
	}
	type kv struct {
		k string
		n int
	}
	var arr []kv
	for k, n := range counts {
		arr = append(arr, kv{k, n})
	}
	sort.Slice(arr, func(i, j int) bool {
		if arr[i].n != arr[j].n {
			return arr[i].n > arr[j].n
		}
		return arr[i].k > arr[j].k
	})
	return arr[0].k
}

func detectLoader(ja *jarAnalysis) string {
	meta := strings.ToLower(strings.Join(ja.Meta, "\n"))
	paths := strings.ToLower(strings.Join(ja.Paths, "\n"))
	switch {
	case strings.Contains(paths, "quilt.mod.json"):
		return "Quilt"
	case strings.Contains(paths, "fabric.mod.json") || strings.Contains(meta, "fabricloader") || strings.Contains(meta, "fabric-loader"):
		return "Fabric"
	case strings.Contains(paths, "neoforge.mods.toml"):
		return "NeoForge"
	case strings.Contains(paths, "mods.toml") || strings.Contains(meta, "fmlcoreplugin") || strings.Contains(meta, "forge"):
		return "Forge"
	case strings.Contains(paths, "mcmod.info"):
		return "Forge/LiteLoader"
	default:
		return ""
	}
}

func detectMappings(ja *jarAnalysis) string {
	classes := strings.Join(ja.Tokens.Classes, "\n")
	refs := strings.Join(ja.Tokens.Refs, "\n")
	all := classes + "\n" + refs
	switch {
	case strings.Contains(all, "net/minecraft/class_"):
		return "Intermediary"
	case strings.Contains(all, "net/minecraft/client/MinecraftClient"):
		return "Yarn"
	case strings.Contains(all, "net/minecraft/client/entity/player/ClientPlayerEntity"):
		return "MCP"
	case strings.Contains(all, "net/minecraft/client/Minecraft"):
		return "Mojang/MCP"
	case strings.Contains(all, "net/minecraft/client/network/ClientPlayerEntity"):
		return "Yarn"
	default:
		return ""
	}
}

func computeObfuscation(classes []*ClassFile, stringsList []string) int {
	if len(classes) == 0 {
		return 0
	}
	shortRe := regexp.MustCompile(`^[a-z]{1,3}$`)
	short, defaultPkg := 0, 0
	for _, cf := range classes {
		sn := simpleClassName(cf.Name)
		if shortRe.MatchString(sn) {
			short++
		}
		if !strings.Contains(cf.Name, "/") {
			defaultPkg++
		}
	}
	score := 0
	sr := float64(short) / float64(len(classes))
	if sr > 0.65 {
		score += 16
	} else if sr > 0.35 {
		score += 9
	} else if sr > 0.15 {
		score += 4
	}
	dr := float64(defaultPkg) / float64(len(classes))
	if dr > 0.5 {
		score += 6
	} else if dr > 0.2 {
		score += 3
	}
	b64 := 0
	b64Re := regexp.MustCompile(`^[A-Za-z0-9+/]{24,}={0,2}$`)
	for _, s := range stringsList {
		if b64Re.MatchString(s) {
			b64++
		}
	}
	if b64 > 100 {
		score += 6
	} else if b64 > 20 {
		score += 3
	}
	if score > 25 {
		score = 25
	}
	return score
}

func isTextEntry(lower string) bool {
	for _, ext := range []string{".json", ".toml", ".properties", ".yml", ".yaml", ".txt", ".lang", ".mcmeta", ".cfg", ".conf", ".xml", ".md", ".mf"} {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

func extractTextTokens(name string, b []byte) []string {
	text := string(b)
	if len(text) > 2<<20 {
		text = text[:2<<20]
	}
	out := []string{name}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || len(line) > 500 {
			continue
		}
		if strings.HasPrefix(line, "//") || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

func jsonStrings(b []byte) []string {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil
	}
	var out []string
	var walk func(any, int)
	walk = func(x any, depth int) {
		if depth > 8 || len(out) > 5000 {
			return
		}
		switch t := x.(type) {
		case string:
			if len(t) <= 500 {
				out = append(out, t)
			}
		case []any:
			for _, e := range t {
				walk(e, depth+1)
			}
		case map[string]any:
			for k, e := range t {
				if len(k) <= 200 {
					out = append(out, k)
				}
				walk(e, depth+1)
			}
		}
	}
	walk(v, 0)
	return out
}

func readZipFile(f *zip.File, limit int64) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	var buf bytes.Buffer
	_, err = io.Copy(&buf, io.LimitReader(rc, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(buf.Len()) > limit {
		return nil, fmt.Errorf("entry too large")
	}
	return buf.Bytes(), nil
}
