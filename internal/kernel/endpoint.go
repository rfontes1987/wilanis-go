package kernel

import "strings"

// endpoint is a parsed endpoint string (§7.3): `node`, `node.path`, or
// `$input.name`.
type endpoint struct {
	IsInput bool
	Input   string // when IsInput
	Node    string // when !IsInput
	Path    []any  // string keys and int64 indexes
}

// identOK checks the identifier grammar of §5.2: [a-z0-9][a-z0-9_-]{0,63}.
func identOK(s string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case (c == '_' || c == '-') && i > 0:
		default:
			return false
		}
	}
	return true
}

// versionedRefOK checks the §8.7 grammar `ident(/ident)*@version`.
func versionedRefOK(s string) bool {
	at := strings.LastIndexByte(s, '@')
	if at < 0 {
		return false
	}
	ref, ver := s[:at], s[at+1:]
	if len(ver) < 1 || len(ver) > 32 {
		return false
	}
	for i := 0; i < len(ver); i++ {
		c := ver[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case (c == '_' || c == '.' || c == '-') && i > 0:
		default:
			return false
		}
	}
	for _, seg := range strings.Split(ref, "/") {
		if !identOK(seg) {
			return false
		}
	}
	return true
}

// pathSegment interprets one dotted path segment: a decimal numeral with no
// leading zero addresses a sequence index; anything else is a string key
// (§7.3).
func pathSegment(seg string) any {
	if seg == "0" {
		return int64(0)
	}
	if len(seg) > 0 && seg[0] >= '1' && seg[0] <= '9' {
		all := true
		for i := 0; i < len(seg); i++ {
			if seg[i] < '0' || seg[i] > '9' {
				all = false
				break
			}
		}
		if all {
			var n int64
			for i := 0; i < len(seg); i++ {
				n = n*10 + int64(seg[i]-'0')
			}
			return n
		}
	}
	return seg
}

// parseEndpoint parses an endpoint string; ok=false means E_ENDPOINT_PARSE.
func parseEndpoint(s string) (endpoint, bool) {
	if strings.HasPrefix(s, "$input.") {
		name := s[len("$input."):]
		if !identOK(name) {
			return endpoint{}, false
		}
		return endpoint{IsInput: true, Input: name}, true
	}
	if strings.HasPrefix(s, "$") {
		return endpoint{}, false
	}
	segs := strings.Split(s, ".")
	if !identOK(segs[0]) {
		return endpoint{}, false
	}
	ep := endpoint{Node: segs[0]}
	for _, seg := range segs[1:] {
		if !identOK(seg) {
			return endpoint{}, false
		}
		ep.Path = append(ep.Path, pathSegment(seg))
	}
	return ep, true
}

// pathValue renders a parsed path as a value (sequence of keys/indexes).
func pathValue(path []any) []any {
	out := make([]any, len(path))
	copy(out, path)
	return out
}

// pathSortKey renders a path for canonical tie-breaking, in its string
// spelling (dot-joined as authored).
func pathSortKey(s string) string {
	if i := strings.IndexByte(s, '.'); i >= 0 {
		return s[i+1:]
	}
	return ""
}
