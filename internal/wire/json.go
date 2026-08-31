// Package wire implements the packaging boundary of Appendix A: ingestion of
// JSON text into the value model with the pinned reject reasons (§4.6, A.2),
// and rendering back out (A.5 recommended, A.6 canonical).
package wire

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/rfontes1987/wilanis-go/internal/value"
)

// RejectError is an ingestion rejection carrying one of the pinned reason
// tokens: surrogate, duplicate_key, number_literal_length, integer_range,
// overflow, depth, string_length.
type RejectError struct{ Reason string }

func (e *RejectError) Error() string { return "ingestion rejected: " + e.Reason }

// ParseError is a malformed-document error (not a bounds rejection).
type ParseError struct{ Msg string }

func (e *ParseError) Error() string { return "json parse error: " + e.Msg }

// Parse ingests a JSON document into the value model.
func Parse(data []byte) (any, error) {
	p := &parser{data: data}
	p.skipWS()
	v, err := p.parseValue(0)
	if err != nil {
		return nil, err
	}
	p.skipWS()
	if p.pos != len(p.data) {
		return nil, &ParseError{Msg: "trailing data"}
	}
	return v, nil
}

type parser struct {
	data []byte
	pos  int
}

func (p *parser) skipWS() {
	for p.pos < len(p.data) {
		switch p.data[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

func (p *parser) fail(msg string) error { return &ParseError{Msg: fmt.Sprintf("%s at %d", msg, p.pos)} }

func (p *parser) parseValue(depth int) (any, error) {
	if p.pos >= len(p.data) {
		return nil, p.fail("unexpected end")
	}
	switch c := p.data[p.pos]; {
	case c == 'n':
		return nil, p.expectLit("null")
	case c == 't':
		if err := p.expectLit("true"); err != nil {
			return nil, err
		}
		return true, nil
	case c == 'f':
		if err := p.expectLit("false"); err != nil {
			return nil, err
		}
		return false, nil
	case c == '"':
		return p.parseString()
	case c == '{':
		return p.parseObject(depth)
	case c == '[':
		return p.parseArray(depth)
	case c == '-' || (c >= '0' && c <= '9'):
		return p.parseNumber()
	}
	return nil, p.fail("unexpected character")
}

func (p *parser) expectLit(lit string) error {
	if p.pos+len(lit) > len(p.data) || string(p.data[p.pos:p.pos+len(lit)]) != lit {
		return p.fail("bad literal")
	}
	p.pos += len(lit)
	return nil
}

func (p *parser) parseObject(depth int) (any, error) {
	if depth+1 > value.MaxDepth {
		return nil, &RejectError{Reason: "depth"}
	}
	p.pos++ // '{'
	m := map[string]any{}
	p.skipWS()
	if p.pos < len(p.data) && p.data[p.pos] == '}' {
		p.pos++
		return m, nil
	}
	for {
		p.skipWS()
		if p.pos >= len(p.data) || p.data[p.pos] != '"' {
			return nil, p.fail("expected object key")
		}
		k, err := p.parseString()
		if err != nil {
			return nil, err
		}
		if _, dup := m[k]; dup {
			return nil, &RejectError{Reason: "duplicate_key"}
		}
		p.skipWS()
		if p.pos >= len(p.data) || p.data[p.pos] != ':' {
			return nil, p.fail("expected ':'")
		}
		p.pos++
		p.skipWS()
		v, err := p.parseValue(depth + 1)
		if err != nil {
			return nil, err
		}
		m[k] = v
		p.skipWS()
		if p.pos >= len(p.data) {
			return nil, p.fail("unexpected end in object")
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
		case '}':
			p.pos++
			return m, nil
		default:
			return nil, p.fail("expected ',' or '}'")
		}
	}
}

func (p *parser) parseArray(depth int) (any, error) {
	if depth+1 > value.MaxDepth {
		return nil, &RejectError{Reason: "depth"}
	}
	p.pos++ // '['
	s := []any{}
	p.skipWS()
	if p.pos < len(p.data) && p.data[p.pos] == ']' {
		p.pos++
		return s, nil
	}
	for {
		p.skipWS()
		v, err := p.parseValue(depth + 1)
		if err != nil {
			return nil, err
		}
		s = append(s, v)
		p.skipWS()
		if p.pos >= len(p.data) {
			return nil, p.fail("unexpected end in array")
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
		case ']':
			p.pos++
			return s, nil
		default:
			return nil, p.fail("expected ',' or ']'")
		}
	}
}

func (p *parser) parseString() (string, error) {
	p.pos++ // '"'
	var b strings.Builder
	for {
		if p.pos >= len(p.data) {
			return "", p.fail("unterminated string")
		}
		c := p.data[p.pos]
		if c == '"' {
			p.pos++
			s := b.String()
			if len(s) > value.MaxStringBytes {
				return "", &RejectError{Reason: "string_length"}
			}
			return s, nil
		}
		if c == '\\' {
			p.pos++
			if p.pos >= len(p.data) {
				return "", p.fail("unterminated escape")
			}
			e := p.data[p.pos]
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
		if c < 0x20 {
			return "", p.fail("control character in string")
		}
		// copy one UTF-8 rune verbatim
		r, size := utf8.DecodeRune(p.data[p.pos:])
		if r == utf8.RuneError && size == 1 {
			return "", p.fail("invalid UTF-8")
		}
		b.Write(p.data[p.pos : p.pos+size])
		p.pos += size
	}
}

func (p *parser) parseUnicodeEscape() (rune, error) {
	u, err := p.hex4()
	if err != nil {
		return 0, err
	}
	if utf16.IsSurrogate(rune(u)) {
		if rune(u) >= 0xDC00 { // lone low surrogate
			return 0, &RejectError{Reason: "surrogate"}
		}
		// need a following \uXXXX low surrogate
		if p.pos+1 < len(p.data) && p.data[p.pos] == '\\' && p.data[p.pos+1] == 'u' {
			save := p.pos
			p.pos += 2
			u2, err := p.hex4()
			if err != nil {
				return 0, err
			}
			r := utf16.DecodeRune(rune(u), rune(u2))
			if r == utf8.RuneError {
				return 0, &RejectError{Reason: "surrogate"}
			}
			_ = save
			return r, nil
		}
		return 0, &RejectError{Reason: "surrogate"}
	}
	return rune(u), nil
}

func (p *parser) hex4() (uint32, error) {
	if p.pos+4 > len(p.data) {
		return 0, p.fail("bad \\u escape")
	}
	var u uint32
	for i := 0; i < 4; i++ {
		c := p.data[p.pos+i]
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

func (p *parser) parseNumber() (any, error) {
	start := p.pos
	if p.pos < len(p.data) && p.data[p.pos] == '-' {
		p.pos++
	}
	digits := func() int {
		n := 0
		for p.pos < len(p.data) && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
			p.pos++
			n++
		}
		return n
	}
	if digits() == 0 {
		return nil, p.fail("bad number")
	}
	if p.pos < len(p.data) && p.data[p.pos] == '.' {
		p.pos++
		if digits() == 0 {
			return nil, p.fail("bad number fraction")
		}
	}
	if p.pos < len(p.data) && (p.data[p.pos] == 'e' || p.data[p.pos] == 'E') {
		p.pos++
		if p.pos < len(p.data) && (p.data[p.pos] == '+' || p.data[p.pos] == '-') {
			p.pos++
		}
		if digits() == 0 {
			return nil, p.fail("bad number exponent")
		}
	}
	lit := string(p.data[start:p.pos])
	return IngestNumberLiteral(lit)
}

// IngestNumberLiteral converts a decimal numeric literal to a model number,
// applying the §4.6 literal-length bound and the A.2 rules.
func IngestNumberLiteral(lit string) (any, error) {
	if len(lit) > value.MaxNumberLength {
		return nil, &RejectError{Reason: "number_literal_length"}
	}
	integerForm := !strings.ContainsAny(lit, ".eE")
	if integerForm {
		n, err := strconv.ParseInt(lit, 10, 64)
		if err != nil || n > value.MaxSafeInteger || n < -value.MaxSafeInteger {
			return nil, &RejectError{Reason: "integer_range"}
		}
		return n, nil
	}
	f, err := strconv.ParseFloat(lit, 64)
	if err != nil {
		// ParseFloat returns ±Inf with ErrRange on overflow
		if strings.Contains(err.Error(), "out of range") {
			if f != 0 { // overflowed to infinity
				return nil, &RejectError{Reason: "overflow"}
			}
			// underflow to zero: keep the zero
		} else {
			return nil, &ParseError{Msg: "bad numeric literal"}
		}
	}
	v, ok := value.UnifyFloat(f)
	if !ok {
		return nil, &RejectError{Reason: "overflow"}
	}
	return v, nil
}
