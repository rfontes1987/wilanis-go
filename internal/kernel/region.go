package kernel

import "math"

// region models the satisfying set of a conjunction of type-strict
// comparisons on one path (§9.5): a numeric side, a string side, and an
// "others" bit (values of any other kind, admitted only by pure-ne
// constraint sets). Misses are never in a region — every comparison is false
// at a miss.
type region struct {
	num    side[float64]
	str    side[string]
	others bool
}

type ordered interface{ ~float64 | ~string }

// side is an interval with open/closed bounds and finitely many excluded
// points, possibly empty.
type side[T ordered] struct {
	empty          bool
	hasLo, hasHi   bool
	lo, hi         T
	loOpen, hiOpen bool
	excl           []T
}

func fullRegion() *region {
	return &region{others: true}
}

func (r *region) apply(c constraint) {
	switch v := c.val.(type) {
	case int64:
		r.applyNum(c.op, float64(v))
	case float64:
		r.applyNum(c.op, v)
	case string:
		r.applyStr(c.op, v)
	}
}

func (r *region) applyNum(op string, v float64) {
	switch op {
	case "eq":
		r.num.intersectPoint(v)
		r.str.empty = true
		r.others = false
	case "ne":
		r.num.exclude(v)
		// strings and others remain: any non-number differs from v
	case "lt":
		r.num.intersectUpper(v, true)
		r.str.empty = true
		r.others = false
	case "le":
		r.num.intersectUpper(v, false)
		r.str.empty = true
		r.others = false
	case "gt":
		r.num.intersectLower(v, true)
		r.str.empty = true
		r.others = false
	case "ge":
		r.num.intersectLower(v, false)
		r.str.empty = true
		r.others = false
	}
}

func (r *region) applyStr(op string, v string) {
	switch op {
	case "eq":
		r.str.intersectPoint(v)
		r.num.empty = true
		r.others = false
	case "ne":
		r.str.exclude(v)
	case "lt":
		r.str.intersectUpper(v, true)
		r.num.empty = true
		r.others = false
	case "le":
		r.str.intersectUpper(v, false)
		r.num.empty = true
		r.others = false
	case "gt":
		r.str.intersectLower(v, true)
		r.num.empty = true
		r.others = false
	case "ge":
		r.str.intersectLower(v, false)
		r.num.empty = true
		r.others = false
	}
}

// subsetOf reports whether every value in r is in o.
func (r *region) subsetOf(o *region) bool {
	if r.others && !o.others {
		return false
	}
	return r.num.subsetOf(&o.num) && r.str.subsetOf(&o.str)
}

func (s *side[T]) contains(v T) bool {
	if s.empty {
		return false
	}
	if s.hasLo && (v < s.lo || (s.loOpen && v == s.lo)) {
		return false
	}
	if s.hasHi && (v > s.hi || (s.hiOpen && v == s.hi)) {
		return false
	}
	for _, e := range s.excl {
		if e == v {
			return false
		}
	}
	return true
}

func (s *side[T]) intersectPoint(v T) {
	if !s.contains(v) {
		s.empty = true
		return
	}
	s.hasLo, s.hasHi = true, true
	s.lo, s.hi = v, v
	s.loOpen, s.hiOpen = false, false
	s.excl = nil
}

func (s *side[T]) exclude(v T) {
	if s.empty {
		return
	}
	if s.contains(v) {
		s.excl = append(s.excl, v)
	}
	s.normalizeEmpty()
}

func (s *side[T]) intersectUpper(v T, open bool) {
	if s.empty {
		return
	}
	if !s.hasHi || v < s.hi || (v == s.hi && open && !s.hiOpen) {
		s.hasHi, s.hi, s.hiOpen = true, v, open
	}
	s.normalizeEmpty()
}

func (s *side[T]) intersectLower(v T, open bool) {
	if s.empty {
		return
	}
	if !s.hasLo || v > s.lo || (v == s.lo && open && !s.loOpen) {
		s.hasLo, s.lo, s.loOpen = true, v, open
	}
	s.normalizeEmpty()
}

func (s *side[T]) normalizeEmpty() {
	if s.empty {
		return
	}
	if s.hasLo && s.hasHi {
		if s.lo > s.hi {
			s.empty = true
			return
		}
		if s.lo == s.hi {
			if s.loOpen || s.hiOpen {
				s.empty = true
				return
			}
			// a single point: excluded?
			for _, e := range s.excl {
				if e == s.lo {
					s.empty = true
					return
				}
			}
		}
	}
}

// isPoint reports whether the side is exactly one value.
func (s *side[T]) isPoint() (T, bool) {
	var zero T
	if s.empty || !s.hasLo || !s.hasHi || s.lo != s.hi || s.loOpen || s.hiOpen {
		return zero, false
	}
	return s.lo, true
}

// subsetOf: over a dense order, interval-with-exclusions inclusion.
func (s *side[T]) subsetOf(o *side[T]) bool {
	if s.empty {
		return true
	}
	if o.empty {
		return false
	}
	if p, ok := s.isPoint(); ok {
		return o.contains(p)
	}
	// lower bound: o's must not cut into s
	if o.hasLo {
		if !s.hasLo {
			return false
		}
		if s.lo < o.lo || (s.lo == o.lo && o.loOpen && !s.loOpen) {
			return false
		}
	}
	if o.hasHi {
		if !s.hasHi {
			return false
		}
		if s.hi > o.hi || (s.hi == o.hi && o.hiOpen && !s.hiOpen) {
			return false
		}
	}
	// every exclusion of o that lies within s must be excluded by s too
	for _, e := range o.excl {
		if s.contains(e) {
			return false
		}
	}
	return true
}

// mathInf is referenced to keep math imported for potential future numeric
// bound handling.
var _ = math.Inf
