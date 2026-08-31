// Package expr is the versioned expression evaluator behind the seam of
// SPEC.md §9.6. It implements exactly the restricted subset of §9.3 —
// grammar, static legality, and total evaluation — and nothing more. The
// kernel depends on this package from a single seam file (§15.12).
package expr

import (
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/rfontes1987/wilanis-go/internal/value"
)

// Version is the evaluator version tag participating in graph identity (D-57).
const Version = "expr/1"

// Node is an AST node.
type Node interface{ isNode() }

// Lit is a literal (null, boolean, number, string, or array of literals).
type Lit struct{ V any }

// Ref is a reference: first segment an identifier (a bound input name), then
// string keys and integer indexes.
type Ref struct{ Segs []any }

// Builtin is present(r), absent(r), or size(r).
type Builtin struct {
	Name string
	Arg  *Ref
}

// Unary is negation.
type Unary struct{ X Node }

// Binary is a connective, comparison, membership, or arithmetic operator.
type Binary struct {
	Op   string // "||" "&&" "==" "!=" "<" "<=" ">" ">=" "in" "+" "-" "*"
	L, R Node
}

func (*Lit) isNode()     {}
func (*Ref) isNode()     {}
func (*Builtin) isNode() {}
func (*Unary) isNode()   {}
func (*Binary) isNode()  {}

// ParseError is a §9.3.1 grammar failure (diagnostic E_PRED_PARSE).
type ParseError struct{ Msg string }

func (e *ParseError) Error() string { return e.Msg }

// Parse parses an expression source string per the §9.3.1 grammar.
func Parse(source string) (Node, error) {
	p := &parser{src: source}
	n, err := p.parseExpr()
	if err != nil {
		return nil, err
	}
	p.skipWS()
	if p.pos != len(p.src) {
		return nil, &ParseError{Msg: "trailing input"}
	}
	return n, nil
}

type parser struct {
	src string
	pos int
}

func (p *parser) fail(msg string) error { return &ParseError{Msg: msg} }

func (p *parser) skipWS() {
	for p.pos < len(p.src) && (p.src[p.pos] == ' ' || p.src[p.pos] == '\t') {
		p.pos++
	}
}

func (p *parser) peek() byte {
	if p.pos < len(p.src) {
		return p.src[p.pos]
	}
	return 0
}

func (p *parser) eat(tok string) bool {
	if strings.HasPrefix(p.src[p.pos:], tok) {
		p.pos += len(tok)
		return true
	}
	return false
}

func isIdentChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-'
}

// lexIdent lexes an identifier greedily over [a-z0-9_-] (§9.3.1 lexing).
func (p *parser) lexIdent() (string, bool) {
	start := p.pos
	for p.pos < len(p.src) && isIdentChar(p.src[p.pos]) {
		p.pos++
	}
	if p.pos == start {
		return "", false
	}
	s := p.src[start:p.pos]
	if len(s) > 64 {
		return "", false
	}
	return s, true
}

func (p *parser) parseExpr() (Node, error) { return p.parseOr() }

func (p *parser) parseOr() (Node, error) {
	l, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for {
		p.skipWS()
		if p.eat("||") {
			r, err := p.parseAnd()
			if err != nil {
				return nil, err
			}
			l = &Binary{Op: "||", L: l, R: r}
		} else {
			return l, nil
		}
	}
}

func (p *parser) parseAnd() (Node, error) {
	l, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for {
		p.skipWS()
		if p.eat("&&") {
			r, err := p.parseNot()
			if err != nil {
				return nil, err
			}
			l = &Binary{Op: "&&", L: l, R: r}
		} else {
			return l, nil
		}
	}
}

func (p *parser) parseNot() (Node, error) {
	p.skipWS()
	if p.peek() == '!' && !strings.HasPrefix(p.src[p.pos:], "!=") {
		p.pos++
		x, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return &Unary{X: x}, nil
	}
	return p.parseComparison()
}

func (p *parser) parseComparison() (Node, error) {
	l, err := p.parseSum()
	if err != nil {
		return nil, err
	}
	p.skipWS()
	for _, op := range []string{"==", "!=", "<=", ">=", "<", ">"} {
		if p.eat(op) {
			r, err := p.parseSum()
			if err != nil {
				return nil, err
			}
			return &Binary{Op: op, L: l, R: r}, nil
		}
	}
	// "in" is an infix word: only if the next token is exactly `in`
	save := p.pos
	if id, ok := p.lexIdent(); ok && id == "in" {
		r, err := p.parseSum()
		if err != nil {
			return nil, err
		}
		return &Binary{Op: "in", L: l, R: r}, nil
	}
	p.pos = save
	return l, nil
}

func (p *parser) parseSum() (Node, error) {
	l, err := p.parseProduct()
	if err != nil {
		return nil, err
	}
	for {
		p.skipWS()
		c := p.peek()
		if c == '+' {
			p.pos++
			r, err := p.parseProduct()
			if err != nil {
				return nil, err
			}
			l = &Binary{Op: "+", L: l, R: r}
		} else if c == '-' {
			// a '-' directly before a digit begins a signed number literal
			// only where an operand may start; here an operand cannot start,
			// so it is subtraction (§9.3.1 lexing).
			p.pos++
			r, err := p.parseProduct()
			if err != nil {
				return nil, err
			}
			l = &Binary{Op: "-", L: l, R: r}
		} else {
			return l, nil
		}
	}
}

func (p *parser) parseProduct() (Node, error) {
	l, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}
	for {
		p.skipWS()
		if p.peek() == '*' {
			p.pos++
			r, err := p.parsePrimary()
			if err != nil {
				return nil, err
			}
			l = &Binary{Op: "*", L: l, R: r}
		} else {
			return l, nil
		}
	}
}

func (p *parser) parsePrimary() (Node, error) {
	p.skipWS()
	c := p.peek()
	switch {
	case c == '(':
		p.pos++
		n, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		p.skipWS()
		if !p.eat(")") {
			return nil, p.fail("expected ')'")
		}
		return n, nil
	case c == '"':
		s, err := p.parseString()
		if err != nil {
			return nil, err
		}
		return &Lit{V: s}, nil
	case c == '[':
		v, err := p.parseArrayLit()
		if err != nil {
			return nil, err
		}
		return &Lit{V: v}, nil
	case c == '-' || (c >= '0' && c <= '9'):
		v, err := p.parseNumber()
		if err != nil {
			return nil, err
		}
		return &Lit{V: v}, nil
	case c >= 'a' && c <= 'z' || c == '_':
		id, ok := p.lexIdent()
		if !ok {
			return nil, p.fail("bad identifier")
		}
		switch id {
		case "null":
			return &Lit{V: nil}, nil
		case "true":
			return &Lit{V: true}, nil
		case "false":
			return &Lit{V: false}, nil
		case "present", "absent", "size":
			p.skipWS()
			if p.eat("(") {
				ref, err := p.parseReference()
				if err != nil {
					return nil, err
				}
				p.skipWS()
				if !p.eat(")") {
					return nil, p.fail("expected ')'")
				}
				return &Builtin{Name: id, Arg: ref}, nil
			}
			// grammar requires "(": a builtin word not applied is a parse error
			return nil, p.fail("builtin requires '(' and a reference")
		}
		if !isIdentStart(id) {
			return nil, p.fail("bad identifier")
		}
		return p.parseReferenceTail(id)
	}
	return nil, p.fail("expected operand")
}

func isIdentStart(id string) bool {
	if id == "" {
		return false
	}
	c := id[0]
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
}

func (p *parser) parseReference() (*Ref, error) {
	p.skipWS()
	id, ok := p.lexIdent()
	if !ok || !isIdentStart(id) {
		return nil, p.fail("expected reference")
	}
	n, err := p.parseReferenceTail(id)
	if err != nil {
		return nil, err
	}
	return n.(*Ref), nil
}

// parseReferenceTail parses `{ "." ident | "[" integer "]" }` after the first
// identifier. A dot segment that is a decimal numeral with no leading zero
// addresses a sequence index (§7.3, §9.3.1).
func (p *parser) parseReferenceTail(first string) (Node, error) {
	segs := []any{first}
	for {
		if p.peek() == '.' {
			p.pos++
			id, ok := p.lexIdent()
			if !ok {
				return nil, p.fail("expected reference segment")
			}
			segs = append(segs, segmentValue(id))
		} else if p.peek() == '[' {
			p.pos++
			p.skipWS()
			start := p.pos
			for p.pos < len(p.src) && p.src[p.pos] >= '0' && p.src[p.pos] <= '9' {
				p.pos++
			}
			if p.pos == start {
				return nil, p.fail("expected index")
			}
			num := p.src[start:p.pos]
			var idx int64
			for _, ch := range num {
				idx = idx*10 + int64(ch-'0')
			}
			p.skipWS()
			if !p.eat("]") {
				return nil, p.fail("expected ']'")
			}
			segs = append(segs, idx)
		} else {
			return &Ref{Segs: segs}, nil
		}
	}
}

// segmentValue interprets a dotted segment: a decimal numeral with no leading
// zero is a sequence index; anything else is a string key.
func segmentValue(seg string) any {
	if seg == "0" {
		return int64(0)
	}
	if seg[0] >= '1' && seg[0] <= '9' {
		allDigits := true
		for i := 0; i < len(seg); i++ {
			if seg[i] < '0' || seg[i] > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			var n int64
			for _, ch := range seg {
				n = n*10 + int64(ch-'0')
			}
			return n
		}
	}
	return seg
}

// parseArrayLit parses `"[" [ literal { "," literal } ] "]"` — elements are
// literals only (§9.3.1).
func (p *parser) parseArrayLit() (any, error) {
	p.pos++ // '['
	out := []any{}
	p.skipWS()
	if p.eat("]") {
		return out, nil
	}
	for {
		v, err := p.parseLiteral()
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		p.skipWS()
		if p.eat(",") {
			p.skipWS()
			continue
		}
		if p.eat("]") {
			return out, nil
		}
		return nil, p.fail("expected ',' or ']'")
	}
}

func (p *parser) parseLiteral() (any, error) {
	p.skipWS()
	c := p.peek()
	switch {
	case c == '"':
		return p.parseString()
	case c == '[':
		return p.parseArrayLit()
	case c == '-' || (c >= '0' && c <= '9'):
		return p.parseNumber()
	case c >= 'a' && c <= 'z':
		id, ok := p.lexIdent()
		if !ok {
			return nil, p.fail("bad literal")
		}
		switch id {
		case "null":
			return nil, nil
		case "true":
			return true, nil
		case "false":
			return false, nil
		}
		return nil, p.fail("expected a literal")
	}
	return nil, p.fail("expected a literal")
}

func (p *parser) parseNumber() (any, error) {
	start := p.pos
	if p.peek() == '-' {
		p.pos++
	}
	digits := func() int {
		n := 0
		for p.pos < len(p.src) && p.src[p.pos] >= '0' && p.src[p.pos] <= '9' {
			p.pos++
			n++
		}
		return n
	}
	if digits() == 0 {
		return nil, p.fail("bad number")
	}
	if p.peek() == '.' {
		p.pos++
		if digits() == 0 {
			return nil, p.fail("bad number fraction")
		}
	}
	if p.peek() == 'e' || p.peek() == 'E' {
		p.pos++
		if p.peek() == '+' || p.peek() == '-' {
			p.pos++
		}
		if digits() == 0 {
			return nil, p.fail("bad number exponent")
		}
	}
	lit := p.src[start:p.pos]
	if len(lit) > value.MaxNumberLength {
		return nil, p.fail("numeric literal too long")
	}
	// §4.2 unification: an integral value in range is the integer; anything
	// else (including out-of-range integral forms) is a binary64. Overflow to
	// an infinity is not a value.
	if !strings.ContainsAny(lit, ".eE") {
		if n, err := strconv.ParseInt(lit, 10, 64); err == nil && n <= value.MaxSafeInteger && n >= -value.MaxSafeInteger {
			return n, nil
		}
	}
	f, err := strconv.ParseFloat(lit, 64)
	if err != nil && !strings.Contains(err.Error(), "out of range") {
		return nil, p.fail("bad numeric literal")
	}
	v, ok := value.UnifyFloat(f)
	if !ok {
		return nil, p.fail("numeric literal overflows")
	}
	return v, nil
}

func (p *parser) parseString() (string, error) {
	p.pos++ // '"'
	var b strings.Builder
	for {
		if p.pos >= len(p.src) {
			return "", p.fail("unterminated string")
		}
		c := p.src[p.pos]
		if c == '"' {
			p.pos++
			return b.String(), nil
		}
		if c == '\\' {
			p.pos++
			if p.pos >= len(p.src) {
				return "", p.fail("unterminated escape")
			}
			e := p.src[p.pos]
			p.pos++
			switch e {
			case '"':
				b.WriteByte('"')
			case '\\':
				b.WriteByte('\\')
			case '/':
				b.WriteByte('/')
			case 'b':
				b.WriteByte('\b')
			case 'f':
				b.WriteByte('\f')
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			case 'u':
				r, err := p.parseUnicodeEscape()
				if err != nil {
					return "", err
				}
				b.WriteRune(r)
			default:
				return "", p.fail("bad escape")
			}
			continue
		}
		b.WriteByte(c)
		p.pos++
	}
}

func (p *parser) parseUnicodeEscape() (rune, error) {
	u, err := p.hex4()
	if err != nil {
		return 0, err
	}
	if utf16.IsSurrogate(rune(u)) {
		if rune(u) >= 0xDC00 {
			return 0, p.fail("unpaired surrogate escape")
		}
		if strings.HasPrefix(p.src[p.pos:], "\\u") {
			p.pos += 2
			u2, err := p.hex4()
			if err != nil {
				return 0, err
			}
			r := utf16.DecodeRune(rune(u), rune(u2))
			if r == 0xFFFD {
				return 0, p.fail("unpaired surrogate escape")
			}
			return r, nil
		}
		return 0, p.fail("unpaired surrogate escape")
	}
	return rune(u), nil
}

func (p *parser) hex4() (uint32, error) {
	if p.pos+4 > len(p.src) {
		return 0, p.fail("bad \\u escape")
	}
	var u uint32
	for i := 0; i < 4; i++ {
		c := p.src[p.pos+i]
		var d uint32
		switch {
		case c >= '0' && c <= '9':
			d = uint32(c - '0')
		case c >= 'a' && c <= 'f':
			d = uint32(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = uint32(c-'A') + 10
		default:
			return 0, p.fail("bad \\u escape")
		}
		u = u<<4 | d
	}
	p.pos += 4
	return u, nil
}

// --- static legality (§9.3.2) ---

// Issue is a static-legality violation.
type Issue struct{ Code string } // E_PRED_COMPUTES or E_PRED_REF

// Check applies the §9.3.2 rules independently, one issue per violated rule
// per offending subtree. bound is the set of bound input names.
func Check(n Node, bound map[string]bool) []Issue {
	var issues []Issue
	// rule 1: boolean skeleton
	checkBooleanSkeleton(n, &issues)
	// rules 2–4 per arithmetic node; rule 3 needs comparison context
	checkArith(n, false, &issues)
	// rule 5: references bound
	checkRefs(n, bound, &issues)
	// rule 6: `in` right operand form
	checkIn(n, &issues)
	return issues
}

func isBooleanForm(n Node) bool {
	switch x := n.(type) {
	case *Binary:
		switch x.Op {
		case "==", "!=", "<", "<=", ">", ">=", "in", "||", "&&":
			return true
		}
		return false
	case *Unary:
		return true
	case *Builtin:
		return x.Name == "present" || x.Name == "absent"
	}
	return false
}

// checkBooleanSkeleton walks connectives/negations; every operand position of
// the skeleton (and the top level) must be a boolean form.
func checkBooleanSkeleton(n Node, issues *[]Issue) {
	if !isBooleanForm(n) {
		*issues = append(*issues, Issue{Code: "E_PRED_COMPUTES"})
		return
	}
	switch x := n.(type) {
	case *Binary:
		if x.Op == "||" || x.Op == "&&" {
			checkBooleanSkeleton(x.L, issues)
			checkBooleanSkeleton(x.R, issues)
		}
	case *Unary:
		checkBooleanSkeleton(x.X, issues)
	}
}

func isArithOp(op string) bool { return op == "+" || op == "-" || op == "*" }

func literalOnly(n Node) bool {
	switch x := n.(type) {
	case *Lit:
		return true
	case *Binary:
		return literalOnly(x.L) && literalOnly(x.R)
	}
	return false
}

// checkArith enforces rules 2–4 for every arithmetic node. underComparison is
// true when the traversal has passed through a comparison/membership operand.
func checkArith(n Node, underComparison bool, issues *[]Issue) {
	switch x := n.(type) {
	case *Binary:
		if isArithOp(x.Op) {
			// rule 3
			if !underComparison {
				*issues = append(*issues, Issue{Code: "E_PRED_COMPUTES"})
			}
			// rule 2
			if !literalOnly(x.L) && !literalOnly(x.R) {
				*issues = append(*issues, Issue{Code: "E_PRED_COMPUTES"})
			}
			// rule 4: a literal operand that is not a number
			for _, side := range []Node{x.L, x.R} {
				if lit, ok := side.(*Lit); ok {
					switch lit.V.(type) {
					case int64, float64:
					default:
						*issues = append(*issues, Issue{Code: "E_PRED_COMPUTES"})
					}
				}
			}
			checkArith(x.L, underComparison, issues)
			checkArith(x.R, underComparison, issues)
			return
		}
		under := underComparison
		switch x.Op {
		case "==", "!=", "<", "<=", ">", ">=", "in":
			under = true
		case "||", "&&":
			under = false
		}
		checkArith(x.L, under, issues)
		checkArith(x.R, under, issues)
	case *Unary:
		checkArith(x.X, false, issues)
	}
}

func checkRefs(n Node, bound map[string]bool, issues *[]Issue) {
	switch x := n.(type) {
	case *Ref:
		if first, ok := x.Segs[0].(string); !ok || !bound[first] {
			*issues = append(*issues, Issue{Code: "E_PRED_REF"})
		}
	case *Builtin:
		checkRefs(x.Arg, bound, issues)
	case *Unary:
		checkRefs(x.X, bound, issues)
	case *Binary:
		checkRefs(x.L, bound, issues)
		checkRefs(x.R, bound, issues)
	}
}

func checkIn(n Node, issues *[]Issue) {
	switch x := n.(type) {
	case *Binary:
		if x.Op == "in" {
			switch r := x.R.(type) {
			case *Ref:
			case *Lit:
				if _, isArr := r.V.([]any); !isArr {
					*issues = append(*issues, Issue{Code: "E_PRED_COMPUTES"})
				}
			default:
				*issues = append(*issues, Issue{Code: "E_PRED_COMPUTES"})
			}
		}
		checkIn(x.L, issues)
		checkIn(x.R, issues)
	case *Unary:
		checkIn(x.X, issues)
	}
}

// Weight computes the §9.4 predicate weight of an expression AST: leaves
// (literal, reference) weigh 1; every internal construct weighs 2 plus its
// operands' weights.
func Weight(n Node) int {
	switch x := n.(type) {
	case *Lit, *Ref:
		return 1
	case *Builtin:
		return 2 + 1
	case *Unary:
		return 2 + Weight(x.X)
	case *Binary:
		return 2 + Weight(x.L) + Weight(x.R)
	}
	return 0
}

// --- evaluation (§9.3.3) ---

// bottom is the distinguished non-value ⊥; it exists only inside evaluation.
type bottomType struct{}

var bottom = bottomType{}

// Eval evaluates a statically legal expression over the environment; it is
// total and yields a boolean.
func Eval(n Node, env map[string]any) bool {
	v := eval(n, env)
	b, ok := v.(bool)
	return ok && b
}

func eval(n Node, env map[string]any) any {
	switch x := n.(type) {
	case *Lit:
		return x.V
	case *Ref:
		return resolveRef(x, env)
	case *Builtin:
		v := resolveRef(x.Arg, env)
		switch x.Name {
		case "present":
			return v != any(bottom)
		case "absent":
			return v == any(bottom)
		case "size":
			switch s := v.(type) {
			case []any:
				return int64(len(s))
			case map[string]any:
				return int64(len(s))
			}
			return bottom
		}
	case *Unary:
		b, _ := eval(x.X, env).(bool)
		return !b
	case *Binary:
		switch x.Op {
		case "&&":
			lb, _ := eval(x.L, env).(bool)
			rb, _ := eval(x.R, env).(bool)
			return lb && rb
		case "||":
			lb, _ := eval(x.L, env).(bool)
			rb, _ := eval(x.R, env).(bool)
			return lb || rb
		}
		l := eval(x.L, env)
		r := eval(x.R, env)
		switch x.Op {
		case "+", "-", "*":
			return arith(x.Op, l, r)
		case "==":
			if l == any(bottom) || r == any(bottom) {
				return false
			}
			return value.Equal(l, r)
		case "!=":
			if l == any(bottom) || r == any(bottom) {
				return false
			}
			return !value.Equal(l, r)
		case "<", "<=", ">", ">=":
			return order(x.Op, l, r)
		case "in":
			if l == any(bottom) || r == any(bottom) {
				return false
			}
			seq, ok := r.([]any)
			if !ok {
				return false
			}
			for _, e := range seq {
				if value.Equal(l, e) {
					return true
				}
			}
			return false
		}
	}
	return bottom
}

func resolveRef(r *Ref, env map[string]any) any {
	first, _ := r.Segs[0].(string)
	cur, ok := env[first]
	if !ok {
		return bottom
	}
	for _, seg := range r.Segs[1:] {
		switch s := seg.(type) {
		case string:
			m, ok := cur.(map[string]any)
			if !ok {
				return bottom
			}
			cur, ok = m[s]
			if !ok {
				return bottom
			}
		case int64:
			sq, ok := cur.([]any)
			if !ok || s < 0 || int(s) >= len(sq) {
				return bottom
			}
			cur = sq[s]
		}
	}
	return cur
}

func numOf(v any) (float64, bool) {
	switch n := v.(type) {
	case int64:
		return float64(n), true
	case float64:
		return n, true
	}
	return 0, false
}

func arith(op string, l, r any) any {
	lf, lok := numOf(l)
	rf, rok := numOf(r)
	if !lok || !rok {
		return bottom
	}
	var f float64
	switch op {
	case "+":
		f = lf + rf
	case "-":
		f = lf - rf
	case "*":
		f = lf * rf
	}
	v, ok := value.UnifyFloat(f)
	if !ok {
		return bottom // overflow to an infinity
	}
	return v
}

func order(op string, l, r any) bool {
	if lf, lok := numOf(l); lok {
		if rf, rok := numOf(r); rok {
			switch op {
			case "<":
				return lf < rf
			case "<=":
				return lf <= rf
			case ">":
				return lf > rf
			case ">=":
				return lf >= rf
			}
		}
		return false
	}
	ls, lok := l.(string)
	rs, rok := r.(string)
	if !lok || !rok {
		return false
	}
	switch op {
	case "<":
		return ls < rs
	case "<=":
		return ls <= rs
	case ">":
		return ls > rs
	case ">=":
		return ls >= rs
	}
	return false
}
