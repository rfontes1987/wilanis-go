package kernel

// This file is the evaluator seam (§9.6, §15.12): the only place in the
// kernel that imports the expression evaluator. Everything predicate-shaped —
// match specifications, guarded expressions, weights, shadowing, evaluation —
// funnels through here.

import (
	"fmt"

	"github.com/rfontes1987/wilanis-go/internal/expr"
	"github.com/rfontes1987/wilanis-go/internal/value"
)

// evaluatorVersionTag is the version participating in graph identity (§7.8).
func evaluatorVersionTag() string { return expr.Version }

const weightCeiling = 64 // §9.4, decision D-29d

// checkDecisionPredicates runs the §9 checks for one decision node.
func checkDecisionPredicates(n *nodeView, d *diags) {
	bound := map[string]bool{}
	for iname := range n.inputs {
		bound[iname] = true
	}
	rules, _ := n.spec["rules"].([]any)

	type ruleInfo struct {
		constraints []constraint
		inFragment  bool
	}
	infos := make([]ruleInfo, len(rules))

	for i, rv := range rules {
		rule := rv.(map[string]any)
		when, _ := rule["when"].(map[string]any)
		addr := fmt.Sprintf("node:%s/rule:%d", n.id, i)

		if src, isExpr := when["expr"].(string); isExpr {
			node, err := expr.Parse(src)
			if err != nil {
				d.add("E_PRED_PARSE", "expression does not parse: "+err.Error(), n.id, "", addr, "")
				continue
			}
			for _, issue := range expr.Check(node, bound) {
				d.add(issue.Code, "predicate violates a §9.3.2 rule", n.id, "", addr, "")
			}
			if expr.Weight(node) > weightCeiling {
				d.add("E_PRED_TOO_COMPLEX", "predicate weight exceeds the ceiling", n.id, "", addr, "")
			}
			if cs, ok := exprFragment(node); ok {
				infos[i] = ruleInfo{constraints: cs, inFragment: true}
			}
			continue
		}
		// match specification
		checkMatchStatic(when, bound, n.id, addr, d)
		if matchWeight(when) > weightCeiling {
			d.add("E_PRED_TOO_COMPLEX", "predicate weight exceeds the ceiling", n.id, "", addr, "")
		}
		if cs, ok := matchFragment(when); ok {
			infos[i] = ruleInfo{constraints: cs, inFragment: true}
		}
	}

	// shadowed-rule analysis (§9.5): per pair (i, j), i < j, both in fragment
	for j := 1; j < len(rules); j++ {
		if !infos[j].inFragment {
			continue
		}
		for i := 0; i < j; i++ {
			if !infos[i].inFragment {
				continue
			}
			if implies(infos[j].constraints, infos[i].constraints) {
				addr := fmt.Sprintf("node:%s/rule:%d", n.id, j)
				d.add("L_RULE_SHADOWED", fmt.Sprintf("rule %d is shadowed by rule %d", j, i), n.id, "", addr, "")
			}
		}
	}
}

// checkMatchStatic applies the §9.2 static rules over a match specification.
func checkMatchStatic(m map[string]any, bound map[string]bool, nodeID, addr string, d *diags) {
	kind, _ := m["kind"].(string)
	switch kind {
	case "compare", "present", "absent":
		path, _ := m["path"].([]any)
		first := ""
		if len(path) > 0 {
			first, _ = path[0].(string)
		}
		if first == "" || !bound[first] {
			d.add("E_PRED_REF", "predicate references an unbound input", nodeID, "", addr, "")
		}
		if kind == "compare" {
			op, _ := m["op"].(string)
			val := m["value"]
			switch op {
			case "lt", "le", "gt", "ge":
				switch val.(type) {
				case int64, float64, string:
				default:
					d.add("E_MATCH_INVALID", "ordering comparison against a non-orderable literal is unsatisfiable", nodeID, "", addr, "")
				}
			case "in":
				if _, isSeq := val.([]any); !isSeq {
					d.add("E_MATCH_INVALID", "in requires a sequence value", nodeID, "", addr, "")
				}
			}
		}
	case "all", "any":
		of, _ := m["of"].([]any)
		for _, sub := range of {
			if sm, ok := sub.(map[string]any); ok {
				checkMatchStatic(sm, bound, nodeID, addr, d)
			}
		}
	}
}

// matchWeight computes the §9.4 weight of a match specification: compare /
// present / absent weigh 2 plus their operands (path 1, value 1); all / any
// weigh 2 plus the sum of their members.
func matchWeight(m map[string]any) int {
	kind, _ := m["kind"].(string)
	switch kind {
	case "compare":
		return 2 + 1 + 1
	case "present", "absent":
		return 2 + 1
	case "all", "any":
		w := 2
		of, _ := m["of"].([]any)
		for _, sub := range of {
			if sm, ok := sub.(map[string]any); ok {
				w += matchWeight(sm)
			}
		}
		return w
	}
	return 0
}

// EvalPredicate evaluates one predicate over the environment (§9.1).
func EvalPredicate(when map[string]any, env map[string]any) bool {
	if src, isExpr := when["expr"].(string); isExpr {
		node, err := expr.Parse(src)
		if err != nil {
			return false // unreachable post-compile
		}
		return expr.Eval(node, env)
	}
	return evalMatch(when, env)
}

// evalMatch evaluates a match specification (§9.2): path miss is false for
// every operator except absent; comparison is type-strict, never coercing.
func evalMatch(m map[string]any, env map[string]any) bool {
	kind, _ := m["kind"].(string)
	switch kind {
	case "all":
		of, _ := m["of"].([]any)
		for _, sub := range of {
			if !evalMatch(sub.(map[string]any), env) {
				return false
			}
		}
		return true
	case "any":
		of, _ := m["of"].([]any)
		for _, sub := range of {
			if evalMatch(sub.(map[string]any), env) {
				return true
			}
		}
		return false
	}
	path, _ := m["path"].([]any)
	v, ok := resolveMatchPath(env, path)
	switch kind {
	case "present":
		return ok
	case "absent":
		return !ok
	case "compare":
		if !ok {
			return false
		}
		op, _ := m["op"].(string)
		val := m["value"]
		switch op {
		case "eq":
			return value.Equal(v, val)
		case "ne":
			return !value.Equal(v, val)
		case "in":
			seq, isSeq := val.([]any)
			if !isSeq {
				return false
			}
			for _, e := range seq {
				if value.Equal(v, e) {
					return true
				}
			}
			return false
		case "lt", "le", "gt", "ge":
			return orderCompare(op, v, val)
		}
	}
	return false
}

func orderCompare(op string, l, r any) bool {
	lf, lNum := numRank(l)
	rf, rNum := numRank(r)
	if lNum && rNum {
		switch op {
		case "lt":
			return lf < rf
		case "le":
			return lf <= rf
		case "gt":
			return lf > rf
		case "ge":
			return lf >= rf
		}
	}
	ls, lStr := l.(string)
	rs, rStr := r.(string)
	if lStr && rStr {
		switch op {
		case "lt":
			return ls < rs
		case "le":
			return ls <= rs
		case "gt":
			return ls > rs
		case "ge":
			return ls >= rs
		}
	}
	return false
}

func numRank(v any) (float64, bool) {
	switch n := v.(type) {
	case int64:
		return float64(n), true
	case float64:
		return n, true
	}
	return 0, false
}

func resolveMatchPath(env map[string]any, path []any) (any, bool) {
	if len(path) == 0 {
		return nil, false
	}
	first, ok := path[0].(string)
	if !ok {
		return nil, false
	}
	cur, ok := env[first]
	if !ok {
		return nil, false
	}
	for _, seg := range path[1:] {
		switch s := seg.(type) {
		case string:
			m, isMap := cur.(map[string]any)
			if !isMap {
				return nil, false
			}
			cur, isMap = m[s]
			if !isMap {
				return nil, false
			}
		case int64:
			sq, isSeq := cur.([]any)
			if !isSeq || s < 0 || int(s) >= len(sq) {
				return nil, false
			}
			cur = sq[s]
		default:
			return nil, false
		}
	}
	return cur, true
}

// --- the decidable fragment (§9.5) ---

// constraint is one comparison between a path and a number-or-string literal,
// reference on the left.
type constraint struct {
	path []any
	op   string // eq ne lt le gt ge
	val  any    // int64 | float64 | string
}

func fragmentLiteral(v any) bool {
	switch v.(type) {
	case int64, float64, string:
		return true
	}
	return false
}

// matchFragment extracts the fragment form of a match specification: a
// conjunction (all, or a single term) of compares against number-or-string
// literals with ops eq/ne/lt/le/gt/ge.
func matchFragment(m map[string]any) ([]constraint, bool) {
	kind, _ := m["kind"].(string)
	switch kind {
	case "compare":
		op, _ := m["op"].(string)
		if op == "in" {
			return nil, false
		}
		val := m["value"]
		if !fragmentLiteral(val) {
			return nil, false
		}
		path, _ := m["path"].([]any)
		return []constraint{{path: path, op: op, val: val}}, true
	case "all":
		var out []constraint
		of, _ := m["of"].([]any)
		for _, sub := range of {
			cs, ok := matchFragment(sub.(map[string]any))
			if !ok {
				return nil, false
			}
			out = append(out, cs...)
		}
		return out, true
	}
	return nil, false
}

// exprFragment extracts the fragment form of an expression: a conjunction
// (&&, nested conjunctions flattened, or a single term) of comparisons
// between one reference and one number-or-string literal, on either side (a
// reversed operator is normalized).
func exprFragment(n expr.Node) ([]constraint, bool) {
	switch x := n.(type) {
	case *expr.Binary:
		switch x.Op {
		case "&&":
			l, ok := exprFragment(x.L)
			if !ok {
				return nil, false
			}
			r, ok := exprFragment(x.R)
			if !ok {
				return nil, false
			}
			return append(l, r...), true
		case "==", "!=", "<", "<=", ">", ">=":
			opMap := map[string]string{"==": "eq", "!=": "ne", "<": "lt", "<=": "le", ">": "gt", ">=": "ge"}
			revMap := map[string]string{"eq": "eq", "ne": "ne", "lt": "gt", "le": "ge", "gt": "lt", "ge": "le"}
			op := opMap[x.Op]
			if ref, ok := x.L.(*expr.Ref); ok {
				if lit, ok := x.R.(*expr.Lit); ok && fragmentLiteral(lit.V) {
					return []constraint{{path: ref.Segs, op: op, val: lit.V}}, true
				}
			}
			if ref, ok := x.R.(*expr.Ref); ok {
				if lit, ok := x.L.(*expr.Lit); ok && fragmentLiteral(lit.V) {
					return []constraint{{path: ref.Segs, op: revMap[op], val: lit.V}}, true
				}
			}
		}
	}
	return nil, false
}

// implies reports whether every environment satisfying cj also satisfies ci
// (constraint-set implication over per-path intervals and point constraints).
func implies(cj, ci []constraint) bool {
	regJ := buildRegions(cj)
	regI := buildRegions(ci)
	for pathKey, ri := range regI {
		rj, constrained := regJ[pathKey]
		if !constrained {
			return false // j allows a miss at this path; i's comparison is then false
		}
		if !rj.subsetOf(ri) {
			return false
		}
	}
	return true
}

func buildRegions(cs []constraint) map[string]*region {
	out := map[string]*region{}
	for _, c := range cs {
		key := value.Hash(pathValue(c.path))
		r, ok := out[key]
		if !ok {
			r = fullRegion()
			out[key] = r
		}
		r.apply(c)
	}
	return out
}
