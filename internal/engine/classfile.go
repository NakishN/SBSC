package engine

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf8"
)

// ClassFile is a minimal JVM class-file model. We intentionally parse only the
// constant pool, hierarchy, members and a few attributes: that is enough for
// static cheat detection and is much faster than a full bytecode parser.
type ClassFile struct {
	Path       string
	Name       string
	Super      string
	Interfaces []string
	Access     uint16
	Major      uint16
	Minor      uint16
	SourceFile string
	Strings    []string
	ClassRefs  []string
	MethodRefs []string
	FieldRefs  []string
	Methods    []Member
	Fields     []Member
	HasCode    bool
}

type Member struct {
	Name   string
	Desc   string
	Access uint16
}

type cpEntry struct {
	tag byte
	s   string
	a   uint16
	b   uint16
}

func parseClassFile(path string, data []byte) (*ClassFile, error) {
	if len(data) < 10 {
		return nil, fmt.Errorf("class too short")
	}
	if binary.BigEndian.Uint32(data[0:4]) != 0xCAFEBABE {
		return nil, fmt.Errorf("bad class magic")
	}
	cf := &ClassFile{Path: path}
	cf.Minor = binary.BigEndian.Uint16(data[4:6])
	cf.Major = binary.BigEndian.Uint16(data[6:8])
	cpCount := int(binary.BigEndian.Uint16(data[8:10]))
	if cpCount < 1 || cpCount > 65535 {
		return nil, fmt.Errorf("bad constant pool count")
	}
	cp := make([]cpEntry, cpCount)
	pos := 10
	readU2 := func() (uint16, bool) {
		if pos+2 > len(data) {
			return 0, false
		}
		v := binary.BigEndian.Uint16(data[pos : pos+2])
		pos += 2
		return v, true
	}
	readU4 := func() (uint32, bool) {
		if pos+4 > len(data) {
			return 0, false
		}
		v := binary.BigEndian.Uint32(data[pos : pos+4])
		pos += 4
		return v, true
	}
	for i := 1; i < cpCount; i++ {
		if pos >= len(data) {
			return nil, fmt.Errorf("truncated constant pool")
		}
		tag := data[pos]
		pos++
		e := cpEntry{tag: tag}
		switch tag {
		case 1: // Utf8
			n, ok := readU2()
			if !ok || pos+int(n) > len(data) {
				return nil, fmt.Errorf("truncated utf8")
			}
			e.s = decodeModifiedUTF8(data[pos : pos+int(n)])
			pos += int(n)
		case 3, 4: // Integer, Float
			if pos+4 > len(data) {
				return nil, fmt.Errorf("truncated int/float")
			}
			pos += 4
		case 5, 6: // Long, Double (two slots)
			if pos+8 > len(data) {
				return nil, fmt.Errorf("truncated long/double")
			}
			pos += 8
			i++
		case 7, 8, 16, 19, 20: // Class, String, MethodType, Module, Package
			a, ok := readU2()
			if !ok {
				return nil, fmt.Errorf("truncated cp ref")
			}
			e.a = a
		case 9, 10, 11, 12, 17, 18: // refs, NameAndType, Dynamic, InvokeDynamic
			a, ok1 := readU2()
			b, ok2 := readU2()
			if !ok1 || !ok2 {
				return nil, fmt.Errorf("truncated cp pair")
			}
			e.a, e.b = a, b
		case 15: // MethodHandle
			if pos+3 > len(data) {
				return nil, fmt.Errorf("truncated method handle")
			}
			e.a = uint16(data[pos])
			pos++
			b, ok := readU2()
			if !ok {
				return nil, fmt.Errorf("truncated method handle ref")
			}
			e.b = b
		default:
			return nil, fmt.Errorf("unknown constant pool tag %d", tag)
		}
		cp[i] = e
	}
	utf8At := func(i uint16) string {
		if int(i) <= 0 || int(i) >= len(cp) {
			return ""
		}
		if cp[i].tag != 1 {
			return ""
		}
		return cp[i].s
	}
	classNameAt := func(i uint16) string {
		if int(i) <= 0 || int(i) >= len(cp) {
			return ""
		}
		if cp[i].tag != 7 {
			return ""
		}
		return utf8At(cp[i].a)
	}

	if pos+6 > len(data) {
		return nil, fmt.Errorf("truncated class header")
	}
	cf.Access = binary.BigEndian.Uint16(data[pos : pos+2])
	pos += 2
	thisIdx := binary.BigEndian.Uint16(data[pos : pos+2])
	pos += 2
	superIdx := binary.BigEndian.Uint16(data[pos : pos+2])
	pos += 2
	cf.Name = classNameAt(thisIdx)
	cf.Super = classNameAt(superIdx)

	ifaceCount, ok := readU2()
	if !ok {
		return nil, fmt.Errorf("truncated interfaces")
	}
	for i := 0; i < int(ifaceCount); i++ {
		idx, ok := readU2()
		if !ok {
			return nil, fmt.Errorf("truncated interface")
		}
		if n := classNameAt(idx); n != "" {
			cf.Interfaces = append(cf.Interfaces, n)
		}
	}

	readMembers := func(isMethod bool) ([]Member, error) {
		count, ok := readU2()
		if !ok {
			return nil, fmt.Errorf("truncated member count")
		}
		out := make([]Member, 0, count)
		for i := 0; i < int(count); i++ {
			if pos+6 > len(data) {
				return nil, fmt.Errorf("truncated member")
			}
			access := binary.BigEndian.Uint16(data[pos : pos+2])
			nameIdx := binary.BigEndian.Uint16(data[pos+2 : pos+4])
			descIdx := binary.BigEndian.Uint16(data[pos+4 : pos+6])
			pos += 6
			attrs, ok := readU2()
			if !ok {
				return nil, fmt.Errorf("truncated member attributes")
			}
			hasCode := false
			for j := 0; j < int(attrs); j++ {
				name, ok := readU2()
				if !ok {
					return nil, fmt.Errorf("truncated attr name")
				}
				length, ok := readU4()
				if !ok || pos+int(length) > len(data) {
					return nil, fmt.Errorf("truncated attr body")
				}
				if isMethod && utf8At(name) == "Code" {
					hasCode = true
				}
				pos += int(length)
			}
			out = append(out, Member{Name: utf8At(nameIdx), Desc: utf8At(descIdx), Access: access})
			if isMethod && hasCode {
				cf.HasCode = true
			}
		}
		return out, nil
	}
	var err error
	if cf.Fields, err = readMembers(false); err != nil {
		return nil, err
	}
	if cf.Methods, err = readMembers(true); err != nil {
		return nil, err
	}

	// Class attributes: SourceFile and Signature are useful context.
	if pos+2 <= len(data) {
		attrs := int(binary.BigEndian.Uint16(data[pos : pos+2]))
		pos += 2
		for i := 0; i < attrs && pos+6 <= len(data); i++ {
			nameIdx := binary.BigEndian.Uint16(data[pos : pos+2])
			length := binary.BigEndian.Uint32(data[pos+2 : pos+6])
			pos += 6
			if pos+int(length) > len(data) {
				break
			}
			switch utf8At(nameIdx) {
			case "SourceFile":
				if length >= 2 {
					cf.SourceFile = utf8At(binary.BigEndian.Uint16(data[pos : pos+2]))
				}
			}
			pos += int(length)
		}
	}

	// Resolve constant pool into useful token sets.
	stringSeen := make(map[string]struct{})
	classSeen := make(map[string]struct{})
	methodSeen := make(map[string]struct{})
	fieldSeen := make(map[string]struct{})
	addString := func(s string) {
		s = strings.TrimSpace(s)
		if len(s) < 3 || len(s) > 400 || !printable(s) {
			return
		}
		if _, ok := stringSeen[s]; ok {
			return
		}
		stringSeen[s] = struct{}{}
		if len(cf.Strings) < 800 {
			cf.Strings = append(cf.Strings, s)
		}
	}
	addClass := func(s string) {
		if s == "" {
			return
		}
		if _, ok := classSeen[s]; ok {
			return
		}
		classSeen[s] = struct{}{}
		if len(cf.ClassRefs) < 1500 {
			cf.ClassRefs = append(cf.ClassRefs, s)
		}
	}
	addMethod := func(s string) {
		if s == "" {
			return
		}
		if _, ok := methodSeen[s]; ok {
			return
		}
		methodSeen[s] = struct{}{}
		if len(cf.MethodRefs) < 1500 {
			cf.MethodRefs = append(cf.MethodRefs, s)
		}
	}
	addField := func(s string) {
		if s == "" {
			return
		}
		if _, ok := fieldSeen[s]; ok {
			return
		}
		fieldSeen[s] = struct{}{}
		if len(cf.FieldRefs) < 1000 {
			cf.FieldRefs = append(cf.FieldRefs, s)
		}
	}

	addClass(cf.Name)
	addClass(cf.Super)
	for _, n := range cf.Interfaces {
		addClass(n)
	}
	for _, m := range cf.Methods {
		if m.Name != "" {
			addMethod(m.Name)
		}
	}
	for _, f := range cf.Fields {
		if f.Name != "" {
			addField(f.Name)
		}
	}

	for i := 1; i < cpCount; i++ {
		e := cp[i]
		switch e.tag {
		case 1:
			addString(e.s)
		case 7:
			addClass(utf8At(e.a))
		case 8:
			addString(utf8At(e.a))
		case 9, 10, 11:
			owner := classNameAt(e.a)
			addClass(owner)
			if int(e.b) > 0 && int(e.b) < len(cp) && cp[e.b].tag == 12 {
				nt := cp[e.b]
				name := utf8At(nt.a)
				desc := utf8At(nt.b)
				if name != "" {
					addMethod(owner + "/" + name)
					addMethod(name + desc)
					addMethod(name)
				}
			}
		case 12:
			addString(utf8At(e.a))
			addString(utf8At(e.b))
		case 15:
			if int(e.b) > 0 && int(e.b) < len(cp) {
				ref := cp[e.b]
				if ref.tag == 9 || ref.tag == 10 || ref.tag == 11 {
					owner := classNameAt(ref.a)
					addClass(owner)
					if int(ref.b) > 0 && int(ref.b) < len(cp) && cp[ref.b].tag == 12 {
						nt := cp[ref.b]
						name := utf8At(nt.a)
						desc := utf8At(nt.b)
						addMethod(owner + "/" + name)
						addMethod(name + desc)
					}
				}
			}
		case 16:
			addString(utf8At(e.a))
		case 17, 18:
			if int(e.b) > 0 && int(e.b) < len(cp) && cp[e.b].tag == 12 {
				nt := cp[e.b]
				addMethod(utf8At(nt.a))
				addString(utf8At(nt.a))
				addString(utf8At(nt.b))
			}
		}
	}
	return cf, nil
}

func printable(s string) bool {
	if s == "" {
		return false
	}
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r == '\n' || r == '\r' || r == '\t' {
			continue
		}
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// decodeModifiedUTF8 handles the JVM's modified UTF-8 (NUL as C0 80 and
// surrogate pairs as two 3-byte sequences).
func decodeModifiedUTF8(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	// Fast path for plain ASCII.
	ascii := true
	for _, c := range b {
		if c >= 0x80 {
			ascii = false
			break
		}
	}
	if ascii {
		return string(b)
	}
	var sb strings.Builder
	for i := 0; i < len(b); {
		c := b[i]
		switch {
		case c&0x80 == 0:
			sb.WriteByte(c)
			i++
		case c&0xE0 == 0xC0:
			if i+1 >= len(b) {
				return sb.String()
			}
			v := rune(c&0x1F)<<6 | rune(b[i+1]&0x3F)
			sb.WriteRune(v)
			i += 2
		case c&0xF0 == 0xE0:
			if i+2 >= len(b) {
				return sb.String()
			}
			v := rune(c&0x0F)<<12 | rune(b[i+1]&0x3F)<<6 | rune(b[i+2]&0x3F)
			sb.WriteRune(v)
			i += 3
		case c&0xF8 == 0xF0:
			if i+3 >= len(b) {
				return sb.String()
			}
			v := rune(c&0x07)<<18 | rune(b[i+1]&0x3F)<<12 | rune(b[i+2]&0x3F)<<6 | rune(b[i+3]&0x3F)
			sb.WriteRune(v)
			i += 4
		default:
			i++
		}
	}
	return sb.String()
}

func simpleClassName(internal string) string {
	if i := strings.LastIndex(internal, "/"); i >= 0 {
		internal = internal[i+1:]
	}
	if i := strings.Index(internal, "$"); i >= 0 {
		internal = internal[:i]
	}
	return internal
}
