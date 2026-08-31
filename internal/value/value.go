// Package value implements the abstract data model of SPEC.md §4 and the
// structural hash of §6. A value is represented as one of:
//
//	nil, bool, int64, float64, string, []any, map[string]any
//
// with the §4.2 number unification applied at construction: every number whose
// mathematical value is an integer within ±(2^53−1) is an int64; every other
// number is a float64. NaN and infinities are unrepresentable.
package value

import (
	"math"
	"sort"
)

// MaxSafeInteger is 2^53 − 1 (§4.2).
const MaxSafeInteger = int64(9007199254740991)

// UnifyFloat applies the §4.2 unification to a binary64 value: an integral
// value within the integer range becomes the integer (−0 becomes integer 0).
// The bool result is false when the value is NaN or an infinity (not a value).
func UnifyFloat(f float64) (any, bool) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return nil, false
	}
	if f == math.Trunc(f) && f >= -float64(MaxSafeInteger) && f <= float64(MaxSafeInteger) {
		return int64(f), true // −0 truncates to 0 here
	}
	return f, true
}

// Equal implements value equality (§4.5).
func Equal(a, b any) bool {
	switch x := a.(type) {
	case nil:
		return b == nil
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	case int64:
		y, ok := b.(int64)
		return ok && x == y
	case float64:
		y, ok := b.(float64)
		return ok && x == y
	case string:
		y, ok := b.(string)
		return ok && x == y
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !Equal(x[i], y[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, v := range x {
			w, present := y[k]
			if !present || !Equal(v, w) {
				return false
			}
		}
		return true
	}
	return false
}

// Depth returns the container-nesting depth of v (§4.6): a scalar has depth 0;
// a container's depth is 1 + max depth of its children.
func Depth(v any) int {
	switch x := v.(type) {
	case []any:
		d := 0
		for _, e := range x {
			if cd := Depth(e); cd > d {
				d = cd
			}
		}
		return d + 1
	case map[string]any:
		d := 0
		for _, e := range x {
			if cd := Depth(e); cd > d {
				d = cd
			}
		}
		return d + 1
	}
	return 0
}

// Bounds constants of §4.6.
const (
	MaxDepth        = 64
	MaxStringBytes  = 1048576
	MaxNumberLength = 100
	MaxFanoutWidth  = 10000
)

// CheckBounds checks the foreign-value bounds of §4.6 that apply to values
// already in the model (depth, string length; keys are strings too). It
// returns the reason token ("depth" or "string_length") or "".
func CheckBounds(v any) string {
	return checkBounds(v, 0)
}

func checkBounds(v any, depth int) string {
	switch x := v.(type) {
	case string:
		if len(x) > MaxStringBytes {
			return "string_length"
		}
	case []any:
		if depth+1 > MaxDepth {
			return "depth"
		}
		for _, e := range x {
			if r := checkBounds(e, depth+1); r != "" {
				return r
			}
		}
	case map[string]any:
		if depth+1 > MaxDepth {
			return "depth"
		}
		for k, e := range x {
			if len(k) > MaxStringBytes {
				return "string_length"
			}
			if r := checkBounds(e, depth+1); r != "" {
				return r
			}
		}
	}
	return ""
}

// SortedKeys returns the map's keys sorted ascending by UTF-8 bytes
// (bytewise lexicographic — Go's native string comparison).
func SortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
