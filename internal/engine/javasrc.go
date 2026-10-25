package engine

import (
	"fmt"
	"strconv"
	"strings"
)

// This file contains a pragmatic Java source parser used for deep analysis of
// CFR output. It is not a full Java compiler front-end: it tokenizes source,
// finds classes/methods and records the calls, strings, assignments, loops and
// numeric constants that cheat detectors need.

type jkind int

const (
	jkIdent jkind = iota
	jkNumber
	jkString
	jkOp
	jkPunct
)

type jtok struct {
	kind jkind
	text string
	line int
	col  int
}

type SourceCall struct {
	Chain string // e.g. mc.playerController.attackEntity
	Name  string // attackEntity
	Line  int
	Args  string
}

type SourceMethod struct {
	Name        string
	Signature   string
	Annotations []string
	StartLine   int
	EndLine     int
	Body        string
	Calls       []SourceCall
	Strings     []string
	Numbers     []float64
	Assignments []string
	Conditions  []string
	NewTypes    []string
	HasLoop     bool
	LoopKinds   []string
	Returns     []string
}

type SourceClass struct {
	File        string
	Package     string
	Name        string
	Extends     string
	Implements  []string
	Annotations []string
	Imports     []string
	Methods     []*SourceMethod
	Strings     []string
	Calls       []SourceCall
	Fields      []string
	StartLine   int
}

type javaParser struct {
	file  string
	src   string
	lines []string
	toks  []jtok
}

func parseJavaSource(file, src string) ([]*SourceClass, error) {
	p := &javaParser{file: file, src: src, lines: strings.Split(src, "\n")}
	p.toks = lexJava(src)
	if len(p.toks) == 0 {
		return nil, fmt.Errorf("empty source")
	}
	var classes []*SourceClass
	pkg := p.parsePackage()
	imports := p.parseImports()
	p.findClasses(0, len(p.toks), pkg, imports, &classes)
	return classes, nil
}

func (p *javaParser) parsePackage() string {
	for i := 0; i < len(p.toks); i++ {
		if p.toks[i].text == "package" {
			var parts []string
			for j := i + 1; j < len(p.toks) && p.toks[j].text != ";"; j++ {
				parts = append(parts, p.toks[j].text)
			}
			return strings.Join(parts, "")
		}
	}
	return ""
}

func (p *javaParser) parseImports() []string {
	var out []string
	for i := 0; i < len(p.toks); i++ {
		if p.toks[i].text == "import" {
			var parts []string
			for j := i + 1; j < len(p.toks) && p.toks[j].text != ";"; j++ {
				parts = append(parts, p.toks[j].text)
			}
			out = append(out, strings.Join(parts, ""))
		}
	}
	return out
}

func (p *javaParser) findClasses(start, end int, pkg string, imports []string, out *[]*SourceClass) {
	for i := start; i < end; i++ {
		t := p.toks[i]
		if t.text != "class" && t.text != "interface" && t.text != "enum" && t.text != "record" {
			continue
		}
		// Ignore "Foo.class" literals.
		if i > 0 && p.toks[i-1].text == "." {
			continue
		}
		if i+1 >= end || p.toks[i+1].kind != jkIdent {
			continue
		}
		sc := &SourceClass{File: p.file, Package: pkg, Name: p.toks[i+1].text, Imports: imports, StartLine: t.line}
		// Annotations immediately before the class.
		sc.Annotations = p.annotationsBefore(i)
		j := i + 2
		for j < end && p.toks[j].text != "{" {
			if p.toks[j].text == "extends" {
				j++
				if j < end {
					sc.Extends = p.typeName(j, end)
				}
			}
			if p.toks[j].text == "implements" {
				j++
				for j < end && p.toks[j].text != "{" {
					if p.toks[j].kind == jkIdent {
						sc.Implements = append(sc.Implements, p.typeName(j, end))
					}
					j++
				}
				break
			}
			j++
		}
		if j >= end || p.toks[j].text != "{" {
			continue
		}
		bodyStart := j + 1
		bodyEnd := p.matchBrace(j, end)
		if bodyEnd < 0 {
			bodyEnd = end
		}
		p.parseClassBody(sc, bodyStart, bodyEnd)
		*out = append(*out, sc)
		// Nested classes.
		p.findClasses(bodyStart, bodyEnd, pkg, imports, out)
		i = bodyEnd
	}
}

func (p *javaParser) typeName(start, end int) string {
	var b strings.Builder
	depth := 0
	for i := start; i < end; i++ {
		t := p.toks[i].text
		if t == "<" {
			depth++
		}
		if t == ">" {
			depth--
		}
		if depth == 0 && (t == "{" || t == "implements" || t == "extends" || t == "," || t == ";") {
			break
		}
		b.WriteString(t)
	}
	return b.String()
}

func (p *javaParser) annotationsBefore(i int) []string {
	var out []string
	for j := i - 1; j >= 0; j-- {
		if p.toks[j].text == ";" || p.toks[j].text == "}" || p.toks[j].text == "{" {
			break
		}
		if p.toks[j].text == "@" && j+1 < i {
			name := p.toks[j+1].text
			args := ""
			if j+2 < i && p.toks[j+2].text == "(" {
				if k := p.matchParen(j+2, i); k > 0 {
					args = p.join(j+3, k)
				}
			}
			if args != "" {
				out = append(out, name+"("+args+")")
			} else {
				out = append(out, name)
			}
		}
		if len(out) >= 8 {
			break
		}
	}
	return out
}

func (p *javaParser) parseClassBody(sc *SourceClass, start, end int) {
	i := start
	var pendingAnn []string
	for i < end {
		t := p.toks[i]
		if t.text == "@" {
			name := ""
			if i+1 < end {
				name = p.toks[i+1].text
			}
			args := ""
			j := i + 2
			if j < end && p.toks[j].text == "(" {
				if k := p.matchParen(j, end); k > 0 {
					args = p.join(j+1, k)
					j = k + 1
				}
			}
			if args != "" {
				pendingAnn = append(pendingAnn, name+"("+args+")")
			} else if name != "" {
				pendingAnn = append(pendingAnn, name)
			}
			i = j
			continue
		}
		if t.text == "{" {
			// A member body starts here. If it is preceded by ")", this is a
			// method or constructor; otherwise it is an initializer/nested block.
			if i > start && p.toks[i-1].text == ")" {
				open := p.matchParenBack(i-1, start)
				if open > start {
					nameIdx := open - 1
					if p.toks[nameIdx].kind == jkIdent {
						name := p.toks[nameIdx].text
						if !isJavaKeyword(name) && !isControlKeyword(name) {
							bodyEnd := p.matchBrace(i, end)
							if bodyEnd > i {
								m := p.parseMethod(p.toks[nameIdx].line, p.toks[bodyEnd].line, name, i+1, bodyEnd)
								m.Annotations = pendingAnn
								pendingAnn = nil
								sc.Methods = append(sc.Methods, m)
								sc.Calls = append(sc.Calls, m.Calls...)
								sc.Strings = append(sc.Strings, m.Strings...)
								i = bodyEnd + 1
								continue
							}
						}
					}
				}
			}
			// Skip non-method block (initializer, nested type, lambda body).
			bodyEnd := p.matchBrace(i, end)
			if bodyEnd < 0 {
				break
			}
			i = bodyEnd + 1
			continue
		}
		if t.text == ";" || t.text == "}" {
			pendingAnn = nil
			i++
			continue
		}
		// Field names at class-body level.
		if t.kind == jkIdent && i+1 < end {
			nt := p.toks[i+1].text
			if nt == "=" || nt == ";" || nt == "," {
				if !isJavaKeyword(t.text) {
					sc.Fields = append(sc.Fields, t.text)
				}
			}
		}
		i++
	}
}

func (p *javaParser) parseMethod(startLine, endLine int, name string, bodyStart, bodyEnd int) *SourceMethod {
	m := &SourceMethod{Name: name, StartLine: startLine, EndLine: endLine}
	m.Calls, m.Strings, m.Numbers, m.Assignments, m.Conditions, m.NewTypes, m.LoopKinds, m.Returns = p.analyzeBody(bodyStart, bodyEnd)
	m.HasLoop = len(m.LoopKinds) > 0
	m.Body = p.snippet(startLine, endLine, 1200)
	m.Signature = name
	return m
}

func (p *javaParser) analyzeBody(start, end int) ([]SourceCall, []string, []float64, []string, []string, []string, []string, []string) {
	var calls []SourceCall
	var strs []string
	var nums []float64
	var assigns []string
	var conds []string
	var news []string
	var loops []string
	var returns []string

	for i := start; i < end; i++ {
		t := p.toks[i]
		switch t.kind {
		case jkString:
			strs = append(strs, t.text)
		case jkNumber:
			if v, err := parseJavaNumber(t.text); err == nil {
				nums = append(nums, v)
			}
		}
		switch t.text {
		case "for", "while", "do":
			loops = append(loops, t.text)
		case "if":
			if i+1 < end && p.toks[i+1].text == "(" {
				if close := p.matchParen(i+1, end); close > 0 {
					conds = append(conds, p.join(i+2, close))
				}
			}
		case "new":
			if i+1 < end {
				typ := p.typeName(i+1, end)
				if typ != "" {
					news = append(news, typ)
				}
			}
		case "return":
			var parts []string
			for j := i + 1; j < end && p.toks[j].text != ";"; j++ {
				parts = append(parts, p.toks[j].text)
			}
			returns = append(returns, strings.Join(parts, ""))
		}
		// Assignments.
		if isAssignOp(t.text) && i > start {
			lhs := p.lhs(i-1, start)
			if lhs != "" {
				assigns = append(assigns, lhs+" "+t.text+" "+p.rhs(i+1, end))
			}
		}
		// Calls.
		if t.text == "(" && i > start {
			nameIdx := i - 1
			if p.toks[nameIdx].kind == jkIdent {
				name := p.toks[nameIdx].text
				if nameIdx > start && p.toks[nameIdx-1].text == "new" {
					continue
				}
				if !isControlKeyword(name) && !isJavaKeyword(name) {
					chain := p.callChain(nameIdx, start)
					args := ""
					if close := p.matchParen(i, end); close > 0 {
						args = p.join(i+1, close)
					}
					calls = append(calls, SourceCall{Chain: chain, Name: name, Line: t.line, Args: args})
				}
			}
		}
	}
	return calls, strs, nums, assigns, conds, news, loops, returns
}

func (p *javaParser) lhs(i, min int) string {
	var parts []string
	for j := i; j >= min; j-- {
		t := p.toks[j].text
		if t == ";" || t == "{" || t == "}" || t == "(" || t == "," || t == "return" || t == "if" || t == "while" || t == "for" {
			break
		}
		parts = append([]string{t}, parts...)
		if len(parts) > 8 {
			break
		}
	}
	return strings.TrimSpace(strings.Join(parts, ""))
}

func (p *javaParser) rhs(i, end int) string {
	var parts []string
	for j := i; j < end; j++ {
		t := p.toks[j].text
		if t == ";" || t == "{" || t == "}" {
			break
		}
		parts = append(parts, t)
		if len(parts) >= 12 {
			break
		}
	}
	return strings.Join(parts, "")
}

func (p *javaParser) callChain(nameIdx, min int) string {
	var parts []string
	parts = append(parts, p.toks[nameIdx].text)
	for j := nameIdx - 1; j >= min; j-- {
		if p.toks[j].text == "." {
			if j-1 >= min && p.toks[j-1].kind == jkIdent {
				parts = append([]string{p.toks[j-1].text}, parts...)
				j--
				continue
			}
			break
		}
		if p.toks[j].text == ")" {
			// A call chain like foo().bar() — stop at the parentheses.
			break
		}
		break
	}
	return strings.Join(parts, ".")
}

func (p *javaParser) snippet(startLine, endLine, max int) string {
	if startLine < 1 {
		startLine = 1
	}
	if endLine > len(p.lines) {
		endLine = len(p.lines)
	}
	if endLine < startLine {
		endLine = startLine
	}
	var b strings.Builder
	for ln := startLine; ln <= endLine && ln <= startLine+8; ln++ {
		line := strings.TrimSpace(p.lines[ln-1])
		if line == "" {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
		if b.Len() >= max {
			break
		}
	}
	s := b.String()
	if len(s) > max {
		s = s[:max] + "…"
	}
	return s
}

func (p *javaParser) matchBrace(open, end int) int {
	depth := 0
	for i := open; i < end; i++ {
		switch p.toks[i].text {
		case "{":
			depth++
		case "}":
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func (p *javaParser) matchParen(open, end int) int {
	depth := 0
	for i := open; i < end; i++ {
		switch p.toks[i].text {
		case "(":
			depth++
		case ")":
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func (p *javaParser) matchParenBack(close, min int) int {
	depth := 0
	for i := close; i >= min; i-- {
		switch p.toks[i].text {
		case ")":
			depth++
		case "(":
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func (p *javaParser) join(start, end int) string {
	if start < 0 {
		start = 0
	}
	if end > len(p.toks) {
		end = len(p.toks)
	}
	var b strings.Builder
	for i := start; i < end; i++ {
		b.WriteString(p.toks[i].text)
	}
	return b.String()
}

func isAssignOp(s string) bool {
	switch s {
	case "=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>=":
		return true
	}
	return false
}

func isControlKeyword(s string) bool {
	switch s {
	case "if", "for", "while", "switch", "catch", "try", "synchronized", "do", "else", "return", "new", "throw", "assert":
		return true
	}
	return false
}

func isJavaKeyword(s string) bool {
	switch s {
	case "abstract", "assert", "boolean", "break", "byte", "case", "catch", "char", "class", "const", "continue",
		"default", "do", "double", "else", "enum", "extends", "final", "finally", "float", "for", "goto", "if",
		"implements", "import", "instanceof", "int", "interface", "long", "native", "new", "package", "private",
		"protected", "public", "return", "short", "static", "strictfp", "super", "switch", "synchronized", "this",
		"throw", "throws", "transient", "try", "void", "volatile", "while", "record", "var", "yield":
		return true
	}
	return false
}

func parseJavaNumber(s string) (float64, error) {
	s = strings.TrimRight(s, "fFdDlL")
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		v, err := strconv.ParseInt(s[2:], 16, 64)
		return float64(v), err
	}
	return strconv.ParseFloat(s, 64)
}

func lexJava(src string) []jtok {
	var toks []jtok
	line, col := 1, 1
	i := 0
	for i < len(src) {
		c := src[i]
		if c == '\n' {
			line++
			col = 1
			i++
			continue
		}
		if c == ' ' || c == '\t' || c == '\r' {
			col++
			i++
			continue
		}
		// Comments.
		if c == '/' && i+1 < len(src) && src[i+1] == '/' {
			for i < len(src) && src[i] != '\n' {
				i++
			}
			continue
		}
		if c == '/' && i+1 < len(src) && src[i+1] == '*' {
			i += 2
			for i+1 < len(src) {
				if src[i] == '\n' {
					line++
				}
				if src[i] == '*' && src[i+1] == '/' {
					i += 2
					break
				}
				i++
			}
			continue
		}
		// Text blocks.
		if c == '"' && i+2 < len(src) && src[i:i+3] == `"""` {
			startLine := line
			i += 3
			var b strings.Builder
			for i+2 < len(src) {
				if src[i:i+3] == `"""` {
					i += 3
					break
				}
				if src[i] == '\n' {
					line++
				}
				b.WriteByte(src[i])
				i++
			}
			toks = append(toks, jtok{kind: jkString, text: b.String(), line: startLine, col: col})
			continue
		}
		// Strings.
		if c == '"' {
			startLine := line
			i++
			var b strings.Builder
			for i < len(src) {
				ch := src[i]
				if ch == '\\' && i+1 < len(src) {
					n := src[i+1]
					switch n {
					case 'n':
						b.WriteByte('\n')
					case 'r':
						b.WriteByte('\r')
					case 't':
						b.WriteByte('\t')
					case '"':
						b.WriteByte('"')
					case '\\':
						b.WriteByte('\\')
					case 'u':
						if i+5 < len(src) {
							if v, err := strconv.ParseInt(src[i+2:i+6], 16, 32); err == nil {
								b.WriteRune(rune(v))
								i += 4
							}
						}
					default:
						b.WriteByte(n)
					}
					i += 2
					continue
				}
				if ch == '"' {
					i++
					break
				}
				if ch == '\n' {
					line++
				}
				b.WriteByte(ch)
				i++
			}
			toks = append(toks, jtok{kind: jkString, text: b.String(), line: startLine, col: col})
			continue
		}
		// Char literals (treated as strings).
		if c == '\'' {
			i++
			var b strings.Builder
			for i < len(src) && src[i] != '\'' {
				if src[i] == '\\' && i+1 < len(src) {
					b.WriteByte(src[i+1])
					i += 2
					continue
				}
				b.WriteByte(src[i])
				i++
			}
			if i < len(src) {
				i++
			}
			toks = append(toks, jtok{kind: jkString, text: b.String(), line: line, col: col})
			continue
		}
		// Identifiers.
		if isIdentStart(c) {
			start := i
			for i < len(src) && isIdentPart(src[i]) {
				i++
			}
			toks = append(toks, jtok{kind: jkIdent, text: src[start:i], line: line, col: col})
			col += i - start
			continue
		}
		// Numbers.
		if c >= '0' && c <= '9' {
			start := i
			for i < len(src) && (isIdentPart(src[i]) || src[i] == '.') {
				i++
			}
			toks = append(toks, jtok{kind: jkNumber, text: src[start:i], line: line, col: col})
			col += i - start
			continue
		}
		// Multi-char operators.
		matched := false
		for _, op := range []string{"->", "::", "==", "!=", "<=", ">=", "&&", "||", "++", "--", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>=", ">>>", "<<"} {
			if strings.HasPrefix(src[i:], op) {
				toks = append(toks, jtok{kind: jkOp, text: op, line: line, col: col})
				i += len(op)
				col += len(op)
				matched = true
				break
			}
		}
		if matched {
			continue
		}
		kind := jkPunct
		if strings.ContainsRune("+-*/%=<>!&|^~?:", rune(c)) {
			kind = jkOp
		}
		toks = append(toks, jtok{kind: kind, text: string(c), line: line, col: col})
		i++
		col++
	}
	return toks
}

func isIdentStart(c byte) bool {
	return c == '_' || c == '$' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c >= 0x80
}

func isIdentPart(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9')
}
