package engine

import (
	"sort"
	"strings"
)

// scoreJar is code-first: file names, internal paths, known-database hits and
// module names are context, not proof. The verdict is driven by what the code
// actually does (decompiled source detectors + per-class bytecode behaviour).
func scoreJar(ja *jarAnalysis) (risk, confidence int, verdict string, cats []CategoryScore) {
	catScore := make(map[string]int)
	contextCats := make(map[string]int)

	// Context: client fingerprint, module names, known database, obfuscation.
	clientWeight := 0
	for _, f := range ja.Findings {
		if f.Category == "client" && strings.HasPrefix(f.RuleID, "client_") && f.Weight > clientWeight {
			clientWeight = f.Weight
		}
	}
	knownScore := 0
	knownCat := ""
	for _, f := range ja.Findings {
		if f.Source == "known" && f.Weight > knownScore {
			knownScore = f.Weight
			knownCat = f.Category
		}
	}
	nonQoL := 0
	for _, m := range ja.Modules {
		if m.QoL {
			continue
		}
		nonQoL++
	}
	context := 0
	if clientWeight > 0 {
		context = 20
		contextCats["client"] = 20
	}
	if nonQoL > 0 {
		c := 5 + nonQoL*3
		if c > 20 {
			c = 20
		}
		if c > context {
			context = c
		}
	}
	if knownScore > 0 {
		if context < 20 {
			context = 20
		}
		contextCats[knownCat] = maxInt(contextCats[knownCat], 20)
	}
	obf := ja.Obfuscation
	if obf > 20 {
		obf = 20
	}
	if obf >= 12 {
		context += 5
		contextCats["obfuscation"] = obf
	}
	if context > 25 {
		context = 25
	}

	// Code evidence: per-class bytecode rules + decompiled Java detectors.
	beh := 0
	behCount := 0
	for _, f := range ja.Findings {
		if f.Source == "source" || f.Source == "known" || f.Category == "client" || f.Category == "malware" {
			continue
		}
		beh += f.Weight
		behCount++
		catScore[f.Category] += f.Weight
	}
	if beh > 35 {
		beh = 35
	}

	src := 0
	for _, f := range ja.Findings {
		if f.Source != "source" || f.Category == "malware" {
			continue
		}
		src += f.Weight
		catScore[f.Category] += f.Weight
	}
	if src > 60 {
		src = 60
	}

	// Embedded native code: a real injection is code evidence, not a name match.
	nativeRisk := 0
	for _, n := range ja.Natives {
		if n.Risk > nativeRisk {
			nativeRisk = n.Risk
		}
	}
	if nativeRisk > 60 {
		nativeRisk = 60
	}
	if nativeRisk > 0 {
		catScore["native"] += nativeRisk
	}

	code := beh + src
	if nativeRisk > 0 {
		code += minInt(25, nativeRisk)
	}
	if code > 75 {
		code = 75
	}
	ja.CodeScore = code
	ja.ContextScore = context

	risk = code + context
	if ja.NativeFlag || nativeRisk >= 60 {
		if risk < 70 {
			risk = 70
		}
		catScore["native"] += 30
	}
	if risk > 100 {
		risk = 100
	}

	switch {
	case ja.NativeFlag || nativeRisk >= 60:
		verdict = "ЧИТ-КЛИЕНТ"
	case code >= 20 && context > 0:
		verdict = "ЧИТ-КЛИЕНТ"
	case code >= 45:
		verdict = "ЧИТ-КЛИЕНТ"
	case code >= 25:
		verdict = "ПОДОЗРИТЕЛЬНО"
	case code >= 15:
		verdict = "ВОЗМОЖНЫ ЧИТЫ"
	case context >= 20:
		verdict = "ВОЗМОЖНЫ ЧИТЫ"
	case risk >= 25:
		verdict = "ВОЗМОЖНЫ ЧИТЫ"
	default:
		verdict = "ЧИСТО"
	}
	// An archive that resists analysis is itself evidence. Obfuscated code
	// without readable strings is exactly where a hidden client sits; do not
	// report it as clean just because the blacklist found nothing.
	if verdict == "ЧИСТО" && ja.Obfuscation >= 18 {
		verdict = "ПОДОЗРИТЕЛЬНО"
		if risk < 30 {
			risk = 30
		}
	}

	// Proof level: exact hash or multiple independent code findings.
	strong := 0
	strongRules := map[string]bool{
		"src_killaura": true, "src_aimbot": true, "src_hitbox_expand": true,
		"src_hitbox_module": true, "src_hitbox_mixin": true, "src_reach": true,
		"src_reach_module": true, "src_scaffold": true, "src_nuker": true,
		"src_disabler": true, "src_autototem": true, "src_crystalaura": true,
		"src_surround": true, "src_ai_aim": true,
		"ai_aim_model": true, "behavior_hitbox_size": true, "behavior_ai_aim": true,
		"behavior_manual": true,
	}
	for _, f := range ja.Findings {
		if strongRules[f.RuleID] {
			strong++
		}
	}
	switch {
	case ja.NativeFlag:
		ja.Proof = "confirmed"
	case strong >= 2 && code >= 20:
		ja.Proof = "confirmed"
	case strong >= 1 && code >= 25:
		ja.Proof = "likely"
	case code >= 20:
		ja.Proof = "possible"
	case context >= 20:
		ja.Proof = "possible"
	case ja.Obfuscation >= 18:
		ja.Proof = "insufficient"
	default:
		ja.Proof = "clean"
	}

	sources := 0
	if code >= 15 {
		sources += 2
	} else if code > 0 {
		sources++
	}
	if context >= 20 {
		sources++
	}
	if nativeRisk > 0 {
		sources++
	}
	confidence = 40 + sources*10 + risk/8
	if code > 0 {
		confidence += 8
	}
	if risk < 25 {
		confidence = 86 + (25-risk)/3
		if context >= 20 && code == 0 {
			confidence = 55
		}
	}
	if confidence > 99 {
		confidence = 99
	}

	for cat, sc := range contextCats {
		if sc > 20 {
			sc = 20
		}
		if sc > catScore[cat] {
			catScore[cat] = sc
		}
	}
	for cat, sc := range catScore {
		if sc <= 0 {
			continue
		}
		if sc > 100 {
			sc = 100
		}
		cats = append(cats, CategoryScore{Category: cat, Label: categoryLabel(cat), Score: sc})
	}
	sort.Slice(cats, func(i, j int) bool {
		if cats[i].Score != cats[j].Score {
			return cats[i].Score > cats[j].Score
		}
		return cats[i].Category < cats[j].Category
	})
	return
}

func hasContextModules(mods []ModuleHit) bool {
	for _, m := range mods {
		if m.Context && !m.QoL {
			return true
		}
	}
	return false
}

// scoreNative also distinguishes code evidence (imports/exports/strings) from
// name/size matches in the known database.
func scoreNative(ni *NativeInfo) (risk, confidence int, verdict string, cats []CategoryScore) {
	if ni.Trusted {
		ni.CodeScore = 0
		ni.ContextScore = 20
		return 0, 90, "Доверенная библиотека", []CategoryScore{{Category: "trusted", Label: categoryLabel("trusted"), Score: 0}}
	}
	code := 0
	known := 0
	seen := make(map[string]int)
	for _, f := range ni.Findings {
		if f.Source == "known" {
			if f.Weight > known {
				known = f.Weight
			}
			continue
		}
		code += f.Weight
		seen[f.Category] += f.Weight
	}
	if code > 80 {
		code = 80
	}
	context := 0
	if known > 0 {
		context = 20
		seen["native"] = maxInt(seen["native"], 20)
	}
	ni.CodeScore = code
	ni.ContextScore = context
	switch {
	case ni.Trusted:
		ni.Proof = "clean"
	case code >= 60:
		ni.Proof = "confirmed"
	case code >= 35:
		ni.Proof = "likely"
	case context > 0:
		ni.Proof = "possible"
	default:
		ni.Proof = "clean"
	}
	risk = code + context
	if risk > 100 {
		risk = 100
	}
	switch {
	case code >= 60:
		verdict = "ЧИТ-КЛИЕНТ"
	case code >= 35:
		verdict = "ПОДОЗРИТЕЛЬНЫЙ"
	case code >= 20:
		verdict = "ВОЗМОЖНО ЧИТ"
	case context > 0:
		verdict = "ВОЗМОЖНО ЧИТ"
	default:
		verdict = "ЧИСТО"
	}
	confidence = 45
	if code > 0 {
		confidence = 65 + code/3
	}
	if known > 0 && code == 0 {
		confidence = 45
	}
	if confidence > 99 {
		confidence = 99
	}
	for cat, sc := range seen {
		if sc > 100 {
			sc = 100
		}
		cats = append(cats, CategoryScore{Category: cat, Label: categoryLabel(cat), Score: sc})
	}
	sort.Slice(cats, func(i, j int) bool { return cats[i].Score > cats[j].Score })
	return
}

func summarize(results []*ScanResult) Summary {
	s := Summary{Total: len(results)}
	for _, r := range results {
		if r == nil {
			continue
		}
		if r.Error != "" {
			s.Errors++
			continue
		}
		switch {
		case strings.HasPrefix(r.Verdict, "ЧИТ-КЛИЕНТ"):
			s.Cheat++
		case strings.HasPrefix(r.Verdict, "ПОДОЗРИТЕЛЬН"):
			s.Suspicious++
		case strings.HasPrefix(r.Verdict, "ВОЗМОЖНЫ") || strings.HasPrefix(r.Verdict, "ВОЗМОЖНО"):
			s.Possible++
		default:
			s.Clean++
		}
	}
	return s
}
