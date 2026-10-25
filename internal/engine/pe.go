package engine

import (
	"bytes"
	"crypto/sha256"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"path"
	"sort"
	"strings"
)

func analyzePE(name string, data []byte, embedded bool, rules *RuleSet, force bool) *NativeInfo {
	ni := &NativeInfo{
		Path:     name,
		Name:     path.Base(strings.ReplaceAll(name, "\\", "/")),
		Size:     int64(len(data)),
		SHA256:   sha256Hex(data),
		Embedded: embedded,
		Trusted:  isTrustedDLL(name) || isSystemPath(name),
		System:   isSystemPath(name),
	}
	if ni.Trusted && !force {
		ni.Verdict = "Доверенная библиотека"
		ni.Proof = "clean"
		ni.Notes = append(ni.Notes, "имя в белом списке; глубокий анализ пропущен (--all-dll для принудительного)")
		return ni
	}
	f, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		ni.Verdict = "Ошибка разбора"
		ni.Notes = append(ni.Notes, "не удалось разобрать PE: "+err.Error())
		return ni
	}
	defer f.Close()

	switch f.Machine {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		ni.Machine = "x64"
	case pe.IMAGE_FILE_MACHINE_I386:
		ni.Machine = "x86"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		ni.Machine = "ARM64"
	default:
		ni.Machine = fmt.Sprintf("0x%x", f.Machine)
	}

	var dataDirs []pe.DataDirectory
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		dataDirs = oh.DataDirectory[:]
	case *pe.OptionalHeader64:
		dataDirs = oh.DataDirectory[:]
	}
	if len(dataDirs) > 4 && dataDirs[4].Size > 0 {
		ni.Signed = true
	}
	if len(dataDirs) > 14 && dataDirs[14].Size > 0 {
		ni.Notes = append(ni.Notes, ".NET assembly (CLR header)")
	}

	// Sections + entropy.
	maxEntropy := 0.0
	for _, s := range f.Sections {
		sec := SectionInfo{Name: strings.TrimRight(s.Name, "\x00"), Size: s.Size}
		if b, err := s.Data(); err == nil && len(b) > 0 {
			sec.Entropy = shannonEntropy(b)
			if sec.Entropy > maxEntropy {
				maxEntropy = sec.Entropy
			}
		}
		ni.Sections = append(ni.Sections, sec)
	}
	ni.Entropy = maxEntropy

	// Imports.
	importSet := make(map[string]struct{})
	if syms, err := f.ImportedSymbols(); err == nil {
		for _, s := range syms {
			importSet[s] = struct{}{}
			if i := strings.LastIndex(s, ":"); i >= 0 && i+1 < len(s) {
				importSet[s[i+1:]] = struct{}{}
			}
		}
	}
	if libs, err := f.ImportedLibraries(); err == nil {
		for _, l := range libs {
			importSet[l] = struct{}{}
		}
	}
	for s := range importSet {
		if len(ni.Imports) < 5000 {
			ni.Imports = append(ni.Imports, s)
		}
	}
	sortStrings(ni.Imports)

	// Exports.
	ni.Exports = parseExports(f, data, dataDirs)

	// Strings.
	strs := extractPEStrings(data)
	ni.Strings = strs
	ni.Notes = append(ni.Notes, fmt.Sprintf("строк: %d, секций: %d, макс. энтропия: %.2f", len(strs), len(ni.Sections), ni.Entropy))
	if !ni.Signed {
		ni.Notes = append(ni.Notes, "unsigned")
	}
	if maxEntropy > 7.2 {
		ni.Notes = append(ni.Notes, "высокая энтропия секции — возможна упаковка/шифрование")
		if !ni.Trusted {
			ni.Findings = append(ni.Findings, Finding{
				RuleID: "native_high_entropy", Title: "Высокая энтропия секций", Category: "native",
				Severity: 3, Weight: 12, Source: "dll",
				Description: "Секция с энтропией > 7.2 — признак упаковки, шифрования или сжатия.",
			})
			maxSec := uint32(0)
			for _, s := range ni.Sections {
				if s.Size > maxSec {
					maxSec = s.Size
				}
			}
			if maxEntropy > 7.5 && maxSec > 5<<20 {
				ni.Findings = append(ni.Findings, Finding{
					RuleID: "native_large_encrypted", Title: "Большая зашифрованная секция", Category: "native",
					Severity: 4, Weight: 25, Source: "dll",
					Description: "Секция > 5 МБ с энтропией > 7.5 — вероятный упакованный/зашифрованный payload.",
				})
			}
		}
	}

	t := &TokenSet{
		Imports:    ni.Imports,
		Exports:    ni.Exports,
		DLLStrings: strs,
		Paths:      []string{ni.Name, ni.Path},
		Meta:       ni.Notes,
	}
	t.buildAll()

	if rules != nil {
		for _, r := range rules.Native {
			if ni.Trusted && !strings.HasPrefix(r.ID, "native_cheat") && !strings.HasPrefix(r.ID, "native_packed") {
				continue
			}
			if fnd, ok := matchRule(r, t); ok {
				fnd.Source = "dll"
				ni.Findings = append(ni.Findings, fnd)
			}
		}
	}

	risk := 0
	for _, fnd := range ni.Findings {
		risk += fnd.Weight
	}
	if ni.Trusted {
		risk = risk / 5
	}
	if risk > 100 {
		risk = 100
	}
	ni.Risk = risk
	switch {
	case ni.Trusted && risk < 20:
		ni.Verdict = "Доверенная библиотека"
	case risk >= 70:
		ni.Verdict = "ЧИТ-КЛИЕНТ"
	case risk >= 45:
		ni.Verdict = "ПОДОЗРИТЕЛЬНЫЙ"
	case risk >= 25:
		ni.Verdict = "ВОЗМОЖНО ЧИТ"
	default:
		ni.Verdict = "ЧИСТО"
	}
	return ni
}

func parseExports(f *pe.File, data []byte, dirs []pe.DataDirectory) []string {
	if len(dirs) <= 1 {
		return nil
	}
	dir := dirs[0]
	if dir.VirtualAddress == 0 || dir.Size == 0 {
		return nil
	}
	off, ok := rvaToOffset(f, dir.VirtualAddress)
	if !ok || off+40 > len(data) {
		return nil
	}
	numberOfNames := binary.LittleEndian.Uint32(data[off+24 : off+28])
	addrNames := binary.LittleEndian.Uint32(data[off+32 : off+36])
	if numberOfNames == 0 || numberOfNames > 10000 {
		return nil
	}
	namesOff, ok := rvaToOffset(f, addrNames)
	if !ok {
		return nil
	}
	var out []string
	for i := uint32(0); i < numberOfNames; i++ {
		p := namesOff + int(i)*4
		if p+4 > len(data) {
			break
		}
		rva := binary.LittleEndian.Uint32(data[p : p+4])
		so, ok := rvaToOffset(f, rva)
		if !ok || so >= len(data) {
			continue
		}
		s := readCString(data[so:], 300)
		if s != "" {
			out = append(out, s)
			if len(out) >= 3000 {
				break
			}
		}
	}
	sortStrings(out)
	return out
}

func rvaToOffset(f *pe.File, rva uint32) (int, bool) {
	for _, s := range f.Sections {
		size := s.VirtualSize
		if size == 0 {
			size = s.Size
		}
		if rva >= s.VirtualAddress && rva < s.VirtualAddress+size {
			return int(s.Offset + (rva - s.VirtualAddress)), true
		}
	}
	// Headers.
	if rva < uint32(len(f.Sections))*40+0x200 {
		return int(rva), true
	}
	return 0, false
}

func readCString(b []byte, max int) string {
	n := 0
	for n < len(b) && n < max && b[n] != 0 {
		n++
	}
	return string(b[:n])
}

func extractPEStrings(data []byte) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if len(s) < 4 || len(s) > 300 {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		if len(out) < 12000 {
			out = append(out, s)
		}
	}
	// ASCII.
	var sb strings.Builder
	flush := func() {
		if sb.Len() >= 4 {
			add(sb.String())
		}
		sb.Reset()
	}
	for _, c := range data {
		if c >= 0x20 && c <= 0x7e {
			sb.WriteByte(c)
		} else {
			flush()
		}
	}
	flush()
	// UTF-16LE (ASCII range).
	sb.Reset()
	for i := 0; i+1 < len(data); i += 2 {
		lo, hi := data[i], data[i+1]
		if hi == 0 && lo >= 0x20 && lo <= 0x7e {
			sb.WriteByte(lo)
		} else {
			flush()
		}
	}
	flush()
	return out
}

func shannonEntropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	var e float64
	total := float64(len(b))
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / total
		e -= p * math.Log2(p)
	}
	return e
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func sortStrings(xs []string) {
	sort.Strings(xs)
}

var trustedDLLExact = map[string]bool{
	"lwjgl.dll": true, "lwjgl_opengl.dll": true, "lwjgl_stb.dll": true, "lwjgl_tinyfd.dll": true,
	"jinput-dx8.dll": true, "jinput-dx8_64.dll": true, "jinput-raw.dll": true, "jinput-raw_64.dll": true,
	"jvm.dll": true, "attach.dll": true, "java.dll": true, "net.dll": true, "nio.dll": true,
	"zip.dll": true, "management.dll": true, "awt.dll": true, "fontmanager.dll": true,
	"freetype.dll": true, "sunec.dll": true, "jimage.dll": true, "jli.dll": true,
	"jsvml.dll": true, "j2pcsc.dll": true, "sunmscapi.dll": true, "lcms.dll": true,
	"ucrtbase.dll": true, "msvcp140.dll": true, "vcruntime140.dll": true, "vcruntime140_1.dll": true,
	"discord_game_sdk.dll": true, "discord-rpc.dll": true, "discord_rpc.dll": true,
	"opengl32.dll": true, "d3dcompiler_47.dll": true, "d3d11.dll": true, "d3d9.dll": true, "dxgi.dll": true,
	"openal.dll": true, "openal32.dll": true, "nvoglv64.dll": true, "nvoglv32.dll": true,
	"xinput1_4.dll": true, "xinput9_1_0.dll": true, "dinput8.dll": true,
	"dwmapi.dll": true, "winmm.dll": true, "dsound.dll": true, "dbghelp.dll": true, "sapi.dll": true,
	"steam_api.dll": true, "steam_api64.dll": true, "textinputframework.dll": true,
	"tolk.dll": true, "nvdaControllerClient64.dll": true, "nvdaControllerClient32.dll": true,
	"rzchromasdk64.dll": true, "logitechledengineswrapper.dll": true, "corsairgamingaudio.dll": true,
	"libcef.dll": true, "chrome_elf.dll": true,
	"dxil.dll": true, "dxcompiler.dll": true, "onnxruntime.dll": true, "onnxruntime4j_jni.dll": true,
}

func isTrustedDLL(name string) bool {
	base := strings.ToLower(path.Base(strings.ReplaceAll(name, "\\", "/")))
	if trustedDLLExact[base] {
		return true
	}
	prefixes := []string{
		"lwjgl", "jinput", "avcodec-", "avformat-", "avutil-", "swresample-", "swscale-",
		"libcef", "cef", "api-ms-win-", "msvcp", "vcruntime", "nvapi", "nvngx", "amdvlk",
		"icudt", "icuuc", "icuin", "razerchroma", "libglesv2", "egl", "sapi",
		"libopus", "liblame", "librnnoise", "libspeex",
		"vulkan-1", "nativewindow", "jogl", "gluegen", "newt", "prism", "javafx",
		"glass", "jfx", "jansi", "winpty", "pty4j", "sqlite", "lz4", "zstd",
		"snappy", "leveldb", "rocksdb", "nvapi", "nvidia", "nvsettings",
		"libzstd", "liblz4", "libsnappy", "jnidispatch", "libjnidispatch", "jna",
		"nvdacontrollerclient", "nvda_controllerclient",
		"onnxruntime", "libonnxruntime", "dxil", "dxcompiler", "directml",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(base, p) {
			return true
		}
	}
	return false
}
