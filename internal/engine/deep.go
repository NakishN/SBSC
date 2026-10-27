package engine

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Source-level detectors work on CFR-decompiled Java. They are intentionally
// conservative: each detector requires a combination of calls/loops/strings
// inside one method or class, not just a class name.

type srcDetector struct {
	ID          string
	Name        string
	Category    string
	Description string
	Severity    int
	Weight      int
	ClassOnly   bool
	Fn          func(c *SourceClass, m *SourceMethod) (bool, string)
}

func analyzeDecompiledSources(root string) ([]Finding, []string) {
	var files []string
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() && strings.HasSuffix(strings.ToLower(p), ".java") {
			files = append(files, p)
			if len(files) >= 6000 {
				return filepath.SkipAll
			}
		}
		return nil
	})
	if len(files) == 0 {
		return nil, []string{"декомпилированные .java не найдены"}
	}
	sort.Strings(files)
	best := make(map[string]Finding)
	var notes []string
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil || len(b) > 4<<20 {
			continue
		}
		classes, err := parseJavaSource(f, string(b))
		if err != nil {
			continue
		}
		for _, c := range classes {
			for _, d := range srcDetectors {
				if d.Category == "malware" {
					continue
				}
				if d.ClassOnly {
					if ok, ev := d.Fn(c, nil); ok {
						addSourceFinding(best, d, c, nil, ev, root)
					}
					continue
				}
				for _, m := range c.Methods {
					if ok, ev := d.Fn(c, m); ok {
						addSourceFinding(best, d, c, m, ev, root)
					}
				}
			}
		}
	}
	out := make([]Finding, 0, len(best))
	for _, f := range best {
		out = append(out, f)
	}
	sortFindings(out)
	if len(out) > 40 {
		out = out[:40]
	}
	if len(files) > 0 {
		notes = append(notes, fmt.Sprintf("глубокий анализ: %d .java файлов", len(files)))
	}
	return out, notes
}

func addSourceFinding(best map[string]Finding, d srcDetector, c *SourceClass, m *SourceMethod, ev, root string) {
	key := d.ID + "|" + c.Package + "." + c.Name
	line := c.StartLine
	file := c.File
	if m != nil {
		line = m.StartLine
	}
	rel, err := filepath.Rel(root, file)
	if err == nil {
		file = rel
	}
	evidence := fmt.Sprintf("%s:%d", filepath.ToSlash(file), line)
	snippet := ""
	if m != nil {
		snippet = m.Body
	} else {
		snippet = strings.Join(c.Annotations, " ")
	}
	f := Finding{
		RuleID: d.ID, Title: d.Name, Category: d.Category, Severity: d.Severity,
		Weight: d.Weight, Description: d.Description, Source: "source",
		Class: c.Package + "." + c.Name, File: filepath.ToSlash(file), Line: line,
		Snippet:  truncateSnippet(snippet, 700),
		Evidence: []string{evidence, truncateSnippet(ev, 200)},
	}
	if old, ok := best[key]; ok {
		if f.Weight > old.Weight {
			best[key] = f
		} else {
			old.Evidence = dedupeStrings(append(old.Evidence, evidence), 6)
			best[key] = old
		}
		return
	}
	best[key] = f
}

func truncateSnippet(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ---------- helpers ----------

func hasCall(m *SourceMethod, names ...string) bool {
	if m == nil {
		return false
	}
	for _, c := range m.Calls {
		for _, n := range names {
			if strings.EqualFold(c.Name, n) {
				return true
			}
		}
	}
	return false
}

func hasChain(m *SourceMethod, substrings ...string) bool {
	if m == nil {
		return false
	}
	for _, c := range m.Calls {
		l := strings.ToLower(c.Chain + " " + c.Args)
		for _, s := range substrings {
			if strings.Contains(l, strings.ToLower(s)) {
				return true
			}
		}
	}
	return false
}

func hasString(m *SourceMethod, substrings ...string) bool {
	if m == nil {
		return false
	}
	for _, s := range m.Strings {
		l := strings.ToLower(s)
		for _, q := range substrings {
			if strings.Contains(l, strings.ToLower(q)) {
				return true
			}
		}
	}
	return false
}

func classHasString(c *SourceClass, substrings ...string) bool {
	if c == nil {
		return false
	}
	for _, s := range append(append([]string{}, c.Strings...), c.Annotations...) {
		l := strings.ToLower(s)
		for _, q := range substrings {
			if strings.Contains(l, strings.ToLower(q)) {
				return true
			}
		}
	}
	return false
}

func classText(c *SourceClass) string {
	if c == nil {
		return ""
	}
	parts := []string{c.Name, c.Extends, strings.Join(c.Implements, " "), strings.Join(c.Annotations, " "), strings.Join(c.Imports, " ")}
	for _, m := range c.Methods {
		parts = append(parts, m.Name)
	}
	return strings.ToLower(strings.Join(parts, " "))
}

func hasNumGT(m *SourceMethod, v float64) bool {
	if m == nil {
		return false
	}
	for _, n := range m.Numbers {
		if n > v {
			return true
		}
	}
	return false
}

func hasAssign(m *SourceMethod, substrings ...string) bool {
	if m == nil {
		return false
	}
	for _, a := range m.Assignments {
		l := strings.ToLower(a)
		for _, q := range substrings {
			if strings.Contains(l, strings.ToLower(q)) {
				return true
			}
		}
	}
	return false
}

func assignValueZero(m *SourceMethod, field string) bool {
	if m == nil {
		return false
	}
	for _, a := range m.Assignments {
		l := strings.ToLower(strings.ReplaceAll(a, " ", ""))
		f := strings.ToLower(field) + "="
		if strings.Contains(l, f) {
			v := l[strings.Index(l, f)+len(f):]
			if strings.HasPrefix(v, "0") || strings.Contains(v, "0.0") || strings.Contains(v, "newvector3d(0") {
				return true
			}
		}
	}
	return false
}

func isRenderMethod(m *SourceMethod) bool {
	if m == nil {
		return false
	}
	n := strings.ToLower(m.Name)
	return strings.Contains(n, "render") || strings.Contains(n, "draw") || strings.Contains(n, "display") || strings.Contains(n, "onrender")
}

func classNameHas(c *SourceClass, subs ...string) bool {
	n := strings.ToLower(c.Name)
	for _, s := range subs {
		if strings.Contains(n, strings.ToLower(s)) {
			return true
		}
	}
	return false
}

func annHas(anns []string, subs ...string) bool {
	for _, a := range anns {
		l := strings.ToLower(a)
		for _, s := range subs {
			if strings.Contains(l, strings.ToLower(s)) {
				return true
			}
		}
	}
	return false
}

var cheatModuleWords = []string{
	"killaura", "aimbot", "hitbox", "reach", "velocity", "scaffold", "nuker",
	"esp", "xray", "tracer", "chams", "fly", "nofall", "disabler", "antiaim",
	"backtrack", "crystalaura", "autototem", "cheststealer", "fastplace",
}

func cheatWordCount(c *SourceClass) int {
	seen := map[string]bool{}
	for _, s := range c.Strings {
		l := normalizeToken(s)
		for _, w := range cheatModuleWords {
			if strings.Contains(l, w) {
				seen[w] = true
			}
		}
	}
	for _, m := range c.Methods {
		l := normalizeToken(m.Name)
		for _, w := range cheatModuleWords {
			if strings.Contains(l, w) {
				seen[w] = true
			}
		}
	}
	return len(seen)
}

// ---------- detectors ----------

var srcDetectors = []srcDetector{
	{
		ID: "src_killaura", Name: "KillAura: цикл атаки по сущностям", Category: "combat",
		Description: "В одном методе есть цикл, перебор сущностей и вызов атаки — типичная аура.",
		Severity:    5, Weight: 32,
		Fn: func(c *SourceClass, m *SourceMethod) (bool, string) {
			if !m.HasLoop || !hasCall(m, "attackEntity", "attackTarget", "swingHand") {
				return false, ""
			}
			if hasCall(m, "getEntities", "getPlayers", "getEntitiesWithinAABB", "getNearestEntity", "getPlayers", "playerList") || hasChain(m, "world.getplayers", "world.getentities") {
				return true, "loop + entity iteration + attack in " + m.Name + "()"
			}
			return false, ""
		},
	},
	{
		ID: "src_aimbot", Name: "Aimbot: расчёт углов и принудительный поворот", Category: "combat",
		Description: "Метод вычисляет угол до цели (atan2/toDegrees) и устанавливает yaw/pitch.",
		Severity:    5, Weight: 30,
		Fn: func(c *SourceClass, m *SourceMethod) (bool, string) {
			if !(hasCall(m, "setYaw", "setPitch") || hasAssign(m, ".yaw", ".pitch", "yaw =", "pitch =")) {
				return false, ""
			}
			if !hasCall(m, "atan2", "toDegrees", "wrapDegrees", "lookAt") && !hasChain(m, "math.atan2", "mathhelper") {
				return false, ""
			}
			if hasCall(m, "getNearestEntity", "getPlayers", "getEntities", "getEntitiesWithinAABB") || classNameHas(c, "aim", "aura", "combat", "rotat") || hasString(m, "aim", "aura", "target") {
				return true, "rotation math + target selection in " + m.Name + "()"
			}
			return false, ""
		},
	},
	{
		ID: "src_hitbox_expand", Name: "HitBox: расширение bounding box", Category: "combat",
		Description: "Код получает bounding box сущности и вызывает expand/grow/inflate или меняет его размер.",
		Severity:    5, Weight: 28,
		Fn: func(c *SourceClass, m *SourceMethod) (bool, string) {
			// Rendering a debug box is not a cheat. Require an actual mutation
			// (setBoundingBox / returned expanded box in a mixin), not just a
			// local Box.expand() used to draw an outline.
			if isRenderMethod(m) {
				return false, ""
			}
			if !hasCall(m, "getEntityBoundingBox", "getBoundingBox") {
				return false, ""
			}
			mutates := hasCall(m, "setBoundingBox", "setEntityBoundingBox") || hasAssign(m, "boundingbox")
			if !mutates && annHas(c.Annotations, "mixin") && (strings.Contains(strings.ToLower(m.Name), "boundingbox") || strings.Contains(strings.ToLower(m.Name), "entitysize")) {
				mutates = true
			}
			if !mutates {
				return false, ""
			}
			if classNameHas(c, "hitbox", "reach", "aura") || hasString(m, "hitbox", "reach", "expand") {
				return true, "bounding box mutation in " + m.Name + "()"
			}
			return false, ""
		},
	},
	{
		ID: "src_hitbox_module", Name: "HitBox: модуль изменения размера", Category: "combat",
		Description: "Класс/метод HitBox вычисляет дополнительный размер хитбокса или меняет его через Mixin.",
		Severity:    5, Weight: 24,
		Fn: func(c *SourceClass, m *SourceMethod) (bool, string) {
			if isRenderMethod(m) {
				return false, ""
			}
			if !classNameHas(c, "hitbox") && !hasString(m, "expand the hitbox", "hitbox size", "extra hitbox") {
				return false, ""
			}
			if hasCall(m, "determineSize", "getEntityValue", "getSize", "getHitbox", "getEntityBoundingBox", "getBoundingBox", "setBoundingBox") ||
				strings.Contains(strings.ToLower(m.Name), "determinesize") ||
				strings.Contains(strings.ToLower(m.Name), "getentityvalue") ||
				hasString(m, "expand the hitbox", "hitbox size", "extra hitbox", "expands an entity") {
				return true, "hitbox size logic in " + m.Name + "()"
			}
			return false, ""
		},
	},
	{
		ID: "src_hitbox_mixin", Name: "HitBox Mixin: подмена размера сущности", Category: "combat",
		Description: "Mixin в Entity/Player меняет размер/хитбокс через модуль HitBox (determineSize/getEntityValue).",
		Severity:    5, Weight: 26,
		Fn: func(c *SourceClass, m *SourceMethod) (bool, string) {
			if !annHas(c.Annotations, "mixin") || isRenderMethod(m) {
				return false, ""
			}
			if !hasChain(m, "hitbox") && !hasString(m, "hitbox", "expand the hitbox") {
				return false, ""
			}
			if hasCall(m, "determineSize", "getEntityValue", "getHitbox", "setBoundingBox", "setEntityBoundingBox") ||
				strings.Contains(strings.ToLower(m.Name), "collisionborder") ||
				hasChain(m, "hitbox") {
				return true, "hitbox mixin in " + c.Name + "." + m.Name + "()"
			}
			return false, ""
		},
	},
	{
		ID: "src_reach_module", Name: "Reach: модуль дистанции", Category: "combat",
		Description: "Класс Reach/ReachHack хранит дистанцию > 4 блоков.",
		Severity:    4, Weight: 20,
		Fn: func(c *SourceClass, m *SourceMethod) (bool, string) {
			if !classNameHas(c, "reach") {
				return false, ""
			}
			if !strings.Contains(strings.ToLower(c.Extends), "hack") && !strings.Contains(strings.ToLower(c.Extends), "module") && !hasString(m, "reach further", "reach distance", "range") {
				return false, ""
			}
			if hasNumGT(m, 4.0) || hasString(m, "reach further", "reach distance") {
				return true, "reach distance setting in " + m.Name + "()"
			}
			return false, ""
		},
	},
	{
		ID: "src_reach", Name: "Reach: атака вне ванильной дистанции", Category: "combat",
		Description: "Атака сопровождается проверкой дистанции и константой > 4 блоков или строкой reach/range.",
		Severity:    5, Weight: 22,
		Fn: func(c *SourceClass, m *SourceMethod) (bool, string) {
			if !hasCall(m, "attackEntity", "attackTarget") {
				return false, ""
			}
			if !hasCall(m, "distanceTo", "getDistance", "distanceSq", "canEntityBeSeen") {
				return false, ""
			}
			if hasNumGT(m, 4.0) || hasString(m, "reach", "range") || classNameHas(c, "reach") {
				return true, "attack + distance check + large constant/string in " + m.Name + "()"
			}
			return false, ""
		},
	},
	{
		ID: "src_velocity", Name: "Velocity: отмена отбрасывания", Category: "movement",
		Description: "Обнуление motionX/Y/Z или setVelocity(0,0,0) в связке с velocity/knockback.",
		Severity:    5, Weight: 20,
		Fn: func(c *SourceClass, m *SourceMethod) (bool, string) {
			if !hasAssign(m, "motionx", "motiony", "motionz", "velocity") && !hasCall(m, "setVelocity") {
				return false, ""
			}
			if !(assignValueZero(m, "motionX") || assignValueZero(m, "motionY") || assignValueZero(m, "motionZ") || hasChain(m, "setvelocity(0", "setvelocity(0.0")) {
				return false, ""
			}
			if classNameHas(c, "velocity", "knockback") || hasString(m, "velocity", "knockback", "antiknockback") {
				return true, "velocity reset in " + m.Name + "()"
			}
			return false, ""
		},
	},
	{
		ID: "src_fly", Name: "Fly: изменение полёта", Category: "movement",
		Description: "Установка flying/capabilities или motionY в связке с fly/flight/glide.",
		Severity:    5, Weight: 24,
		Fn: func(c *SourceClass, m *SourceMethod) (bool, string) {
			if !hasAssign(m, "flying", "capabilities", "motiony") {
				return false, ""
			}
			if classNameHas(c, "flightpath", "trajectory", "projectile", "render") {
				return false, ""
			}
			if classNameHas(c, "fly", "flight", "glide", "jetpack") || hasString(m, "fly", "flight", "glide", "jetpack") {
				if hasAssign(m, "motiony", "flying", "capabilities") {
					return true, "flight state/motion mutation in " + m.Name + "()"
				}
			}
			return false, ""
		},
	},
	{
		ID: "src_nofall", Name: "NoFall: обнуление урона от падения", Category: "movement",
		Description: "fallDistance = 0 или обработчик падения в связке с nofall.",
		Severity:    4, Weight: 18,
		Fn: func(c *SourceClass, m *SourceMethod) (bool, string) {
			if hasAssign(m, "falldistance") || hasCall(m, "onFall", "fall") {
				if classNameHas(c, "nofall", "fall") || hasString(m, "nofall", "fall damage", "falldistance") {
					return true, "fall damage reset in " + m.Name + "()"
				}
			}
			return false, ""
		},
	},
	{
		ID: "src_scaffold", Name: "Scaffold: авто-установка блоков", Category: "world",
		Description: "Цикл + placeBlock/interactBlock + BlockPos/block state — авто-мост.",
		Severity:    5, Weight: 24,
		Fn: func(c *SourceClass, m *SourceMethod) (bool, string) {
			if !m.HasLoop || !hasCall(m, "placeBlock", "interactBlock", "rightClick", "processRightClickBlock") {
				return false, ""
			}
			if hasCall(m, "getBlockState", "getBlock", "BlockPos") || hasChain(m, "blockpos", "blockstate") || classNameHas(c, "scaffold", "tower", "bridge") {
				if classNameHas(c, "scaffold", "tower", "bridge") || hasString(m, "scaffold", "tower", "bridge") {
					return true, "loop + block placement in " + m.Name + "()"
				}
			}
			return false, ""
		},
	},
	{
		ID: "src_nuker", Name: "Nuker: массовое разрушение блоков", Category: "world",
		Description: "Цикл + breakBlock/attackBlock + перебор BlockPos — массовое разрушение.",
		Severity:    5, Weight: 26,
		Fn: func(c *SourceClass, m *SourceMethod) (bool, string) {
			if !m.HasLoop || !hasCall(m, "breakBlock", "attackBlock", "onPlayerDamageBlock", "clickBlock") {
				return false, ""
			}
			if hasCall(m, "getBlockState", "getBlock", "BlockPos") || hasChain(m, "blockpos") {
				if classNameHas(c, "nuker", "excavator", "veinminer", "autofarm") || hasString(m, "nuker", "excavator", "veinminer") {
					return true, "loop + block breaking in " + m.Name + "()"
				}
			}
			return false, ""
		},
	},
	{
		ID: "src_esp", Name: "ESP/рендер сквозь стены", Category: "render",
		Description: "Render-метод рисует боксы/линии через RenderSystem/BufferBuilder в связке с ESP.",
		Severity:    4, Weight: 20,
		Fn: func(c *SourceClass, m *SourceMethod) (bool, string) {
			if !isRenderMethod(m) || !hasCall(m, "drawBox", "drawLine", "drawOutline", "renderBox", "drawRect", "buffer", "vertex") {
				return false, ""
			}
			if hasCall(m, "RenderSystem", "BufferBuilder", "Tessellator", "GL11", "GlStateManager") || hasChain(m, "rendersystem", "bufferbuilder", "tessellator", "gl11") {
				if classNameHas(c, "esp", "tracer", "chams", "wallhack", "outline") || hasString(m, "esp", "tracer", "chams", "wallhack") {
					return true, "render pipeline + box/line drawing in " + m.Name + "()"
				}
			}
			return false, ""
		},
	},
	{
		ID: "src_xray", Name: "X-Ray: перехват отрисовки блоков", Category: "render",
		Description: "shouldDrawSide/isOpaque + список блоков в связке с X-Ray.",
		Severity:    4, Weight: 22,
		Fn: func(c *SourceClass, m *SourceMethod) (bool, string) {
			// A block-search helper (e.g. Lithium's countBlocksInBoxInSection)
			// calls getBlockState/getBlock for optimisation, not to reveal ores.
			// Require a render/visibility hook as well as a block lookup.
			if !hasCall(m, "getBlockState", "getBlock") {
				return false, ""
			}
			if !hasCall(m, "shouldDrawSide") && !hasCall(m, "isOpaque") {
				return false, ""
			}
			// "search" is a very common package/class word in optimisations.
			if classNameHas(c, "xray", "x-ray", "blockesp") || hasString(m, "xray", "x-ray", "blockesp") {
				return true, "block visibility override in " + m.Name + "()"
			}
			return false, ""
		},
	},
	{
		ID: "src_autoclicker", Name: "AutoClicker/TriggerBot", Category: "combat",
		Description: "Цикл/поток + attack/swing/click + CPS/autoclicker/triggerbot.",
		Severity:    5, Weight: 22,
		Fn: func(c *SourceClass, m *SourceMethod) (bool, string) {
			if !(m.HasLoop || hasString(m, "thread", "sleep")) || !hasCall(m, "attackEntity", "swingHand", "click", "mouse") {
				return false, ""
			}
			if classNameHas(c, "autoclicker", "triggerbot", "clicker") || hasString(m, "cps", "autoclicker", "triggerbot", "clicker") {
				return true, "loop/thread + attack/click in " + m.Name + "()"
			}
			return false, ""
		},
	},
	{
		ID: "src_cheststeal", Name: "ChestStealer: перебор слотов", Category: "world",
		Description: "Цикл по слотам + clickWindow/quickMove + chest/steal.",
		Severity:    4, Weight: 18,
		Fn: func(c *SourceClass, m *SourceMethod) (bool, string) {
			if !m.HasLoop || !hasCall(m, "clickWindow", "quickMoveStack", "moveItemStackTo", "shiftClick") {
				return false, ""
			}
			if classNameHas(c, "chest", "steal", "cleaner") || hasString(m, "chest", "steal", "cleaner") {
				return true, "slot loop + container click in " + m.Name + "()"
			}
			return false, ""
		},
	},
	{
		ID: "src_backtrack", Name: "Backtrack/FakeLag", Category: "combat",
		Description: "Очередь позиций/пакетов + attack/sendPacket в связке с backtrack/lag.",
		Severity:    4, Weight: 18,
		Fn: func(c *SourceClass, m *SourceMethod) (bool, string) {
			if !hasCall(m, "add", "offer", "push", "poll") || !hasCall(m, "attackEntity", "sendPacket") {
				return false, ""
			}
			if classNameHas(c, "backtrack", "lag") || hasString(m, "backtrack", "fakelag", "lag range") {
				return true, "position/packet queue + attack in " + m.Name + "()"
			}
			return false, ""
		},
	},
	{
		ID: "src_disabler", Name: "Disabler: AC scan", Category: "misc",
		Description: "Названия AC + отправка/отмена пакетов или bypass/disabler.",
		Severity:    5, Weight: 26,
		Fn: func(c *SourceClass, m *SourceMethod) (bool, string) {
			if !hasString(m, "verus", "intave", "grim", "matrix", "polar", "vulcan", "spartan", "nocheatplus", "ncp", "aac", "watchdog", "hypixel") {
				return false, ""
			}
			if !classNameHas(c, "disabler") && !hasString(m, "disabler") {
				return false, ""
			}
			if hasCall(m, "sendPacket", "cancel", "setCancelled", "setTimer", "setSpeed") || hasString(m, "bypass", "flag", "exploit") {
				return true, "AC name + packet/timer manipulation in " + m.Name + "()"
			}
			return false, ""
		},
	},
	{
		ID: "src_packet_exploit", Name: "Пакетный эксплойт", Category: "exploit",
		Description: "sendPacket + crafted packet (ClickWindow/ConfirmTransaction/PacketFly/ForceOp).",
		Severity:    5, Weight: 20,
		Fn: func(c *SourceClass, m *SourceMethod) (bool, string) {
			if !hasCall(m, "sendPacket", "send", "write") {
				return false, ""
			}
			if hasString(m, "C0EPacketClickWindow", "C0FPacketConfirmTransaction", "C00PacketKeepAlive", "C03PacketPlayer", "C04PacketPlayerPosition", "PacketFly", "ServerCrasher", "ForceOp") || classNameHas(c, "packet", "exploit", "crasher") {
				return true, "crafted packet in " + m.Name + "()"
			}
			return false, ""
		},
	},
	{
		ID: "src_antiaim", Name: "AntiAim/SpinBot", Category: "combat",
		Description: "Случайные/циклические yaw/pitch в связке с antiaim/spinbot/derp.",
		Severity:    4, Weight: 18,
		Fn: func(c *SourceClass, m *SourceMethod) (bool, string) {
			if !(hasAssign(m, "yaw", "pitch") || hasCall(m, "setYaw", "setPitch")) {
				return false, ""
			}
			if classNameHas(c, "antiaim", "spinbot", "derp") || hasString(m, "antiaim", "spinbot", "derp", "random") {
				return true, "yaw/pitch manipulation in " + m.Name + "()"
			}
			return false, ""
		},
	},
	{
		ID: "src_timer", Name: "Timer: ускорение тиков", Category: "movement",
		Description: "Изменение таймера/скорости тиков в связке с timer/speed.",
		Severity:    4, Weight: 16,
		Fn: func(c *SourceClass, m *SourceMethod) (bool, string) {
			if !hasCall(m, "setTimer", "setSpeed") && !hasAssign(m, "tickspeed", "timer.speed") {
				return false, ""
			}
			if hasNumGT(m, 1.0) || classNameHas(c, "timer") || hasString(m, "tickspeed", "game speed", "timer speed", "speedhack") {
				return true, "timer/speed mutation in " + m.Name + "()"
			}
			return false, ""
		},
	},
	{
		ID: "src_phase", Name: "Phase/NoClip", Category: "movement",
		Description: "Изменение позиции/хитбокса в цикле в связке с phase/noclip.",
		Severity:    4, Weight: 18,
		Fn: func(c *SourceClass, m *SourceMethod) (bool, string) {
			if !hasCall(m, "setPosition", "setBoundingBox", "setNoClip") && !hasAssign(m, "position", "boundingbox") {
				return false, ""
			}
			if (m.HasLoop || hasCall(m, "setPosition")) && (classNameHas(c, "phase", "noclip", "clip") || hasString(m, "phase", "noclip", "clip")) {
				return true, "position/bounding box manipulation in " + m.Name + "()"
			}
			return false, ""
		},
	},
	{
		ID: "src_freecam", Name: "Freecam", Category: "render",
		Description: "Отдельная камера/позиция + freecam.",
		Severity:    3, Weight: 14,
		Fn: func(c *SourceClass, m *SourceMethod) (bool, string) {
			if !hasAssign(m, "camera", "position", "x", "y", "z") || !hasCall(m, "setPosition", "setCamera", "render") {
				return false, ""
			}
			if classNameHas(c, "freecam", "camera") || hasString(m, "freecam", "free cam") {
				return true, "camera/position override in " + m.Name + "()"
			}
			return false, ""
		},
	},
	{
		ID: "src_fastplace", Name: "FastPlace/быстрая установка", Category: "world",
		Description: "placeBlock/rightClick + манипуляция задержкой в связке с fastplace.",
		Severity:    3, Weight: 14,
		Fn: func(c *SourceClass, m *SourceMethod) (bool, string) {
			if !hasCall(m, "placeBlock", "rightClick", "processRightClickBlock") {
				return false, ""
			}
			if classNameHas(c, "fastplace") || hasString(m, "fastplace", "fast place", "delay") {
				return true, "block placement + delay manipulation in " + m.Name + "()"
			}
			return false, ""
		},
	},
	{
		ID: "src_entity_speed", Name: "Speed/EntitySpeed", Category: "movement",
		Description: "Изменение motionX/Z с большим множителем в связке со speed.",
		Severity:    4, Weight: 18,
		Fn: func(c *SourceClass, m *SourceMethod) (bool, string) {
			if !hasAssign(m, "motionx", "motionz") || !hasNumGT(m, 1.0) {
				return false, ""
			}
			if classNameHas(c, "speed", "entityspeed") || hasString(m, "speed", "entity speed") {
				return true, "motion/speed multiplier in " + m.Name + "()"
			}
			return false, ""
		},
	},
	{
		ID: "src_mixin_combat", Name: "Mixin в combat-классы Minecraft", Category: "combat",
		Description: "Класс @Mixin(targets=MinecraftClient/ClientPlayerEntity/PlayerController) с @Inject/@Redirect в attack/tick/look.",
		Severity:    4, Weight: 16, ClassOnly: true,
		Fn: func(c *SourceClass, _ *SourceMethod) (bool, string) {
			if !annHas(c.Annotations, "mixin") {
				return false, ""
			}
			if !classHasString(c, "minecraftclient", "clientplayerentity", "playercontroller", "clientplayerinteractionmanager", "minecraft") {
				return false, ""
			}
			hit := false
			for _, m := range c.Methods {
				if annHas(m.Annotations, "inject", "redirect", "overwrite") {
					l := strings.ToLower(m.Name + " " + m.Body)
					if strings.Contains(l, "attack") || strings.Contains(l, "sendmovement") || strings.Contains(l, "rotation") || strings.Contains(l, "look") {
						hit = true
						break
					}
				}
			}
			if hit {
				return true, "mixin combat injection in " + c.Name
			}
			return false, ""
		},
	},
	{
		ID: "src_module_registry", Name: "Реестр модулей чит-клиента", Category: "client",
		Description: "Класс регистрирует модули и содержит 3+ названия чит-модулей.",
		Severity:    4, Weight: 18, ClassOnly: true,
		Fn: func(c *SourceClass, _ *SourceMethod) (bool, string) {
			hasRegistry := false
			for _, m := range c.Methods {
				if hasCall(m, "register", "addModule", "registerModule", "loadModules") {
					hasRegistry = true
					break
				}
			}
			if hasRegistry && cheatWordCount(c) >= 3 {
				return true, fmt.Sprintf("module registry with %d cheat names", cheatWordCount(c))
			}
			return false, ""
		},
	},
	{
		ID: "src_gui_modules", Name: "Чит-GUI со списком модулей", Category: "client",
		Description: "GUI/Screen-класс содержит 4+ названия чит-модулей.",
		Severity:    4, Weight: 16, ClassOnly: true,
		Fn: func(c *SourceClass, _ *SourceMethod) (bool, string) {
			if !classNameHas(c, "gui", "screen", "clickgui", "menu") {
				return false, ""
			}
			if n := cheatWordCount(c); n >= 4 {
				return true, fmt.Sprintf("GUI with %d cheat module names", n)
			}
			return false, ""
		},
	},
	{
		ID: "src_surround", Name: "Surround/AutoTrap: обсидиан вокруг игрока", Category: "combat",
		Description: "Цикл + установка блоков + упоминание surround/autotrap/obsidian.",
		Severity:    5, Weight: 22,
		Fn: func(c *SourceClass, m *SourceMethod) (bool, string) {
			if !m.HasLoop || !hasCall(m, "placeBlock", "interactBlock", "rightClick") {
				return false, ""
			}
			if classNameHas(c, "surround", "autotrap", "selftrap") || hasString(m, "surround", "autotrap", "obsidian", "trap") {
				return true, "loop + trap block placement in " + m.Name + "()"
			}
			return false, ""
		},
	},
	{
		ID: "src_autototem", Name: "AutoTotem/Offhand", Category: "combat",
		Description: "Автоматическая экипировка тотема/предмета во вторую руку.",
		Severity:    4, Weight: 18,
		Fn: func(c *SourceClass, m *SourceMethod) (bool, string) {
			if !hasCall(m, "useItem", "swapHands", "clickSlot", "setSlot") && !classNameHas(c, "autototem") {
				return false, ""
			}
			if classNameHas(c, "totem", "offhand") || hasString(m, "totem", "offhand", "undying") {
				return true, "offhand/totem automation in " + m.Name + "()"
			}
			return false, ""
		},
	},
	{
		ID: "src_autopot", Name: "AutoPot/AutoGap", Category: "player",
		Description: "Автоматическое использование зелий/еды при низком здоровье.",
		Severity:    4, Weight: 18,
		Fn: func(c *SourceClass, m *SourceMethod) (bool, string) {
			if !hasCall(m, "useItem", "rightClick", "clickSlot") {
				return false, ""
			}
			if classNameHas(c, "autopot", "autogap", "autosoup") || hasString(m, "potion", "golden apple", "autopot", "autogap", "health") {
				return true, "automatic potion/food use in " + m.Name + "()"
			}
			return false, ""
		},
	},
	{
		ID: "src_crystalaura", Name: "CrystalAura/AutoCrystal", Category: "combat",
		Description: "Атака/установка кристаллов Энда в цикле.",
		Severity:    5, Weight: 26,
		Fn: func(c *SourceClass, m *SourceMethod) (bool, string) {
			if !hasCall(m, "attackEntity", "placeBlock", "setPosition") {
				return false, ""
			}
			if classNameHas(c, "crystal") || hasString(m, "crystal", "end_crystal", "ender crystal") {
				return true, "crystal placement/attack in " + m.Name + "()"
			}
			return false, ""
		},
	},
	{
		ID: "src_bedaura", Name: "BedAura", Category: "combat",
		Description: "Установка/взрыв кроватей рядом с целью.",
		Severity:    5, Weight: 24,
		Fn: func(c *SourceClass, m *SourceMethod) (bool, string) {
			if !hasCall(m, "attackEntity") || !hasCall(m, "placeBlock", "interactBlock") {
				return false, ""
			}
			if classNameHas(c, "bedaura") || (classNameHas(c, "bed") && hasString(m, "bed", "respawn anchor")) {
				return true, "bed/anchor placement in " + m.Name + "()"
			}
			return false, ""
		},
	},
	{
		ID: "src_fastbreak", Name: "FastBreak/SpeedMine", Category: "world",
		Description: "Ускоренное разрушение блоков/сброс задержки.",
		Severity:    4, Weight: 16,
		Fn: func(c *SourceClass, m *SourceMethod) (bool, string) {
			if !hasCall(m, "breakBlock", "onPlayerDamageBlock", "attackBlock") {
				return false, ""
			}
			if classNameHas(c, "fastbreak", "speedmine") || hasString(m, "fastbreak", "speedmine", "break delay") {
				return true, "fast block breaking in " + m.Name + "()"
			}
			return false, ""
		},
	},
	{
		ID: "src_autofarm", Name: "AutoFarm/VeinMiner", Category: "world",
		Description: "Цикл по блокам + разрушение/посадка в связке с farm/veinminer.",
		Severity:    4, Weight: 16,
		Fn: func(c *SourceClass, m *SourceMethod) (bool, string) {
			if !m.HasLoop || !hasCall(m, "breakBlock", "placeBlock", "attackBlock") {
				return false, ""
			}
			if classNameHas(c, "autofarm", "veinminer", "excavator") || hasString(m, "autofarm", "veinminer", "replant", "farm") {
				return true, "loop farming/mining in " + m.Name + "()"
			}
			return false, ""
		},
	},
	{
		ID: "src_packet_spam", Name: "PacketSpam/Exploit", Category: "exploit",
		Description: "Цикл отправки пакетов (C0x/C1x/C2x/C3x).",
		Severity:    4, Weight: 18,
		Fn: func(c *SourceClass, m *SourceMethod) (bool, string) {
			if !m.HasLoop || !hasCall(m, "sendPacket") {
				return false, ""
			}
			if hasString(m, "C0EPacketClickWindow", "C0FPacketConfirmTransaction", "C00PacketKeepAlive", "C03PacketPlayer", "C04PacketPlayerPosition", "PacketFly", "ServerCrasher", "ForceOp") || classNameHas(c, "packet", "exploit", "crasher") {
				return true, "packet spam loop in " + m.Name + "()"
			}
			return false, ""
		},
	},
	{
		ID: "src_ai_aim", Name: "Нейросетевой аим (Neuro/ONNX/CatBoost)", Category: "combat",
		Description: "Модель/инференс Neuro/ONNX/CatBoost вычисляет yaw/pitch для ауры.",
		Severity:    5, Weight: 26,
		Fn: func(c *SourceClass, m *SourceMethod) (bool, string) {
			cm := strings.ToLower(c.Name + " " + m.Name + " " + strings.Join(c.Annotations, " "))
			if !strings.Contains(cm, "neuro") && !strings.Contains(cm, "onnx") && !strings.Contains(cm, "catboost") && !strings.Contains(cm, "rotationpredict") && !strings.Contains(cm, "aimmodel") {
				return false, ""
			}
			if hasCall(m, "setYaw", "setPitch") || hasAssign(m, "yaw", "pitch", "rotation") || hasString(m, "aim", "aura", "rotation", "yaw", "pitch") {
				return true, "ML rotation model in " + c.Name + "." + m.Name + "()"
			}
			return false, ""
		},
	},
	{
		ID: "src_string_decrypt", Name: "Расшифровка строк (обфускация)", Category: "obfuscation",
		Description: "Цикл XOR/Base64-декодирования строк в связке с reflection/ClassLoader.",
		Severity:    3, Weight: 16,
		Fn: func(c *SourceClass, m *SourceMethod) (bool, string) {
			if !m.HasLoop || !(hasCall(m, "decode", "decrypt", "xor") || hasChain(m, "base64")) {
				return false, ""
			}
			if hasCall(m, "forName", "defineClass", "invoke") || hasChain(m, "class.forname", "methodhandles") {
				return true, "string decryption + reflection in " + m.Name + "()"
			}
			return false, ""
		},
	},
}
