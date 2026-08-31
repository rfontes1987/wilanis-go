package wire

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/rfontes1987/wilanis-go/internal/value"
)

// RenderCanonical renders a value byte-canonically per Appendix A.6: UTF-8, no
// insignificant whitespace, object keys sorted by UTF-8 bytes, integers in
// minimal decimal form, strings with the shortest escape (escaping only `"`,
// `\`, and control characters, lowercase hex escapes).
func RenderCanonical(v any) []byte {
	var b strings.Builder
	renderTo(&b, v)
	return []byte(b.String())
}

func renderTo(b *strings.Builder, v any) {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case int64:
		b.WriteString(strconv.FormatInt(x, 10))
	case float64:
		// shortest round-trip rendering; a double is never integral in range,
		// but ensure a distinguishing form for integral out-of-range doubles
		s := strconv.FormatFloat(x, 'g', -1, 64)
		if !strings.ContainsAny(s, ".eE") {
			s += ".0"
		}
		b.WriteString(s)
	case string:
		renderString(b, x)
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			renderTo(b, e)
		}
		b.WriteByte(']')
	case map[string]any:
		b.WriteByte('{')
		for i, k := range value.SortedKeys(x) {
			if i > 0 {
				b.WriteByte(',')
			}
			renderString(b, k)
			b.WriteByte(':')
			renderTo(b, x[k])
		}
		b.WriteByte('}')
	default:
		panic(fmt.Sprintf("wire: not a model value: %T", v))
	}
}

func renderString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}
