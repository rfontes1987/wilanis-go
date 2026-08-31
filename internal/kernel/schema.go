package kernel

import (
	"fmt"
	"strings"
)

// validateShape (stage 1 of §10.1) checks the authoring spec's packaging
// shape: required fields, value kinds, closed key sets, species
// discrimination. The schema's lexical patterns (identifier / endpoint
// grammars) are deliberately not checked here — the analyzer reports those
// with full addressing (§10.1).
func validateShape(spec any, d *diags) {
	root, ok := spec.(map[string]any)
	if !ok {
		d.add("E_SCHEMA", "the graph spec is not a map", "", "", "graph", "")
		return
	}
	allowed := map[string]bool{
		"name": true, "evaluatorVersion": true, "distribution": true,
		"inputs": true, "guards": true, "renames": true,
		"nodes": true, "edges": true, "exports": true,
	}
	for k := range root {
		if !allowed[k] {
			d.add("E_SCHEMA", "unknown graph key "+quote(k), "", "", "graph", "/"+escapePtr(k))
		}
	}
	requireString(root, "name", "", d)
	if v, ok := root["evaluatorVersion"]; ok {
		checkString(v, "/evaluatorVersion", d)
	}
	if v, ok := root["distribution"]; ok {
		s, isStr := v.(string)
		if !isStr || (s != "server" && s != "client") {
			d.add("E_SCHEMA", "distribution must be \"server\" or \"client\"", "", "", "graph", "/distribution")
		}
	}
	if v, ok := root["inputs"]; ok {
		if m, isMap := v.(map[string]any); isMap {
			for name, decl := range m {
				validateInputDecl(decl, "/inputs/"+escapePtr(name), d)
			}
		} else {
			d.add("E_SCHEMA", "inputs must be a map", "", "", "graph", "/inputs")
		}
	}
	if v, ok := root["guards"]; ok {
		validateStringSeq(v, "/guards", d)
	}
	if v, ok := root["renames"]; ok {
		if m, isMap := v.(map[string]any); isMap {
			for k, rv := range m {
				checkString(rv, "/renames/"+escapePtr(k), d)
			}
		} else {
			d.add("E_SCHEMA", "renames must be a map", "", "", "graph", "/renames")
		}
	}
	nodes, ok := root["nodes"].([]any)
	if !ok || len(nodes) == 0 {
		d.add("E_SCHEMA", "nodes must be a non-empty sequence", "", "", "graph", "/nodes")
	} else {
		for i, nv := range nodes {
			validateNode(nv, fmt.Sprintf("/nodes/%d", i), d)
		}
	}
	exports, ok := root["exports"].([]any)
	if !ok {
		d.add("E_SCHEMA", "exports must be a sequence", "", "", "graph", "/exports")
	} else {
		for i, ev := range exports {
			ptr := fmt.Sprintf("/exports/%d", i)
			em, isMap := ev.(map[string]any)
			if !isMap {
				d.add("E_SCHEMA", "export must be a map", "", "", "graph", ptr)
				continue
			}
			requireString(em, "name", ptr, d)
			requireString(em, "from", ptr, d)
			for k := range em {
				if k != "name" && k != "from" {
					d.add("E_SCHEMA", "unknown export key "+quote(k), "", "", "graph", ptr+"/"+escapePtr(k))
				}
			}
		}
	}
	if v, ok := root["edges"]; ok {
		edges, isSeq := v.([]any)
		if !isSeq {
			d.add("E_SCHEMA", "edges must be a sequence", "", "", "graph", "/edges")
		} else {
			for i, ev := range edges {
				validateEdge(ev, fmt.Sprintf("/edges/%d", i), d)
			}
		}
	}
}

func validateEdge(v any, ptr string, d *diags) {
	m, ok := v.(map[string]any)
	if !ok {
		d.add("E_SCHEMA", "edge must be a map", "", "", "graph", ptr)
		return
	}
	kind, _ := m["kind"].(string)
	if kind != "data" && kind != "order" {
		d.add("E_SCHEMA", "edge kind must be \"data\" or \"order\"", "", "", "graph", ptr+"/kind")
	}
	for k := range m {
		switch k {
		case "id", "kind", "from", "to":
		default:
			d.add("E_SCHEMA", "unknown edge key "+quote(k), "", "", "graph", ptr+"/"+escapePtr(k))
		}
	}
	if iv, ok := m["id"]; ok {
		checkString(iv, ptr+"/id", d)
	}
	requireString(m, "from", ptr, d)
	requireString(m, "to", ptr, d)
}

func validateInputDecl(v any, ptr string, d *diags) {
	m, ok := v.(map[string]any)
	if !ok {
		d.add("E_SCHEMA", "input declaration must be a map", "", "", "graph", ptr)
		return
	}
	for k, kv := range m {
		switch k {
		case "shape":
			validateShapeDecl(kv, ptr+"/shape", d)
		case "optional", "subject":
			if _, isBool := kv.(bool); !isBool {
				d.add("E_SCHEMA", k+" must be a boolean", "", "", "graph", ptr+"/"+k)
			}
		case "sensitivity":
			checkSensitivity(kv, ptr+"/sensitivity", d)
		default:
			d.add("E_SCHEMA", "unknown input declaration key "+quote(k), "", "", "graph", ptr+"/"+escapePtr(k))
		}
	}
}

func checkSensitivity(v any, ptr string, d *diags) {
	s, ok := v.(string)
	if !ok || (s != "public" && s != "internal" && s != "pii") {
		d.add("E_SCHEMA", "sensitivity must be public, internal, or pii", "", "", "graph", ptr)
	}
}

func validateShapeDecl(v any, ptr string, d *diags) {
	m, ok := v.(map[string]any)
	if !ok {
		d.add("E_SCHEMA", "shape must be a map", "", "", "graph", ptr)
		return
	}
	kinds := map[string]bool{"any": true, "null": true, "boolean": true, "integer": true,
		"number": true, "string": true, "blob": true, "sequence": true, "record": true, "map": true}
	kind, _ := m["kind"].(string)
	if !kinds[kind] {
		d.add("E_SCHEMA", "shape kind invalid", "", "", "graph", ptr+"/kind")
	}
	for k, kv := range m {
		switch k {
		case "kind":
		case "of":
			validateShapeDecl(kv, ptr+"/of", d)
		case "fields":
			fm, ok := kv.(map[string]any)
			if !ok {
				d.add("E_SCHEMA", "fields must be a map", "", "", "graph", ptr+"/fields")
				continue
			}
			for fn, fv := range fm {
				fmm, ok := fv.(map[string]any)
				if !ok {
					d.add("E_SCHEMA", "field declaration must be a map", "", "", "graph", ptr+"/fields/"+escapePtr(fn))
					continue
				}
				for fk, fkv := range fmm {
					switch fk {
					case "shape":
						validateShapeDecl(fkv, ptr+"/fields/"+escapePtr(fn)+"/shape", d)
					case "optional":
						if _, isBool := fkv.(bool); !isBool {
							d.add("E_SCHEMA", "optional must be a boolean", "", "", "graph", ptr+"/fields/"+escapePtr(fn)+"/optional")
						}
					default:
						d.add("E_SCHEMA", "unknown field key "+quote(fk), "", "", "graph", ptr+"/fields/"+escapePtr(fn)+"/"+escapePtr(fk))
					}
				}
			}
		default:
			d.add("E_SCHEMA", "unknown shape key "+quote(k), "", "", "graph", ptr+"/"+escapePtr(k))
		}
	}
}

func validateNode(v any, ptr string, d *diags) {
	m, ok := v.(map[string]any)
	if !ok {
		d.add("E_SCHEMA", "node must be a map", "", "", "graph", ptr)
		return
	}
	species, hasSpecies := m["species"]
	sp := "routine"
	if hasSpecies {
		s, isStr := species.(string)
		if !isStr || (s != "routine" && s != "decision" && s != "map" && s != "invoke") {
			d.add("E_SCHEMA", "unknown species", "", "", "graph", ptr+"/species")
			return
		}
		sp = s
	}
	requireString(m, "id", ptr, d)
	var allowed map[string]bool
	switch sp {
	case "routine":
		allowed = map[string]bool{"id": true, "species": true, "routine": true, "params": true,
			"joins": true, "retry": true, "absorb": true, "bind": true, "in": true, "needs": true}
		requireString(m, "routine", ptr, d)
	case "decision":
		allowed = map[string]bool{"id": true, "species": true, "rules": true, "default": true,
			"defaultTo": true, "joins": true, "in": true, "needs": true}
		requireString(m, "default", ptr, d)
		rules, ok := m["rules"].([]any)
		if !ok || len(rules) == 0 {
			d.add("E_SCHEMA", "rules must be a non-empty sequence", "", "", "graph", ptr+"/rules")
		} else {
			for i, rv := range rules {
				validateRule(rv, fmt.Sprintf("%s/rules/%d", ptr, i), d)
			}
		}
		if v, ok := m["defaultTo"]; ok {
			validateStringSeq(v, ptr+"/defaultTo", d)
		}
	case "map":
		allowed = map[string]bool{"id": true, "species": true, "body": true, "over": true,
			"bind": true, "params": true, "joins": true, "retry": true, "absorb": true, "in": true, "needs": true}
		requireString(m, "body", ptr, d)
		requireString(m, "over", ptr, d)
	case "invoke":
		allowed = map[string]bool{"id": true, "species": true, "graph": true, "joins": true, "in": true, "needs": true}
		requireString(m, "graph", ptr, d)
	}
	for k := range m {
		if !allowed[k] {
			d.add("E_SCHEMA", "unknown node key "+quote(k), "", "", "graph", ptr+"/"+escapePtr(k))
		}
	}
	if v, ok := m["params"]; ok {
		if _, isMap := v.(map[string]any); !isMap {
			d.add("E_SCHEMA", "params must be a map", "", "", "graph", ptr+"/params")
		}
	}
	if v, ok := m["joins"]; ok {
		jm, isMap := v.(map[string]any)
		if !isMap {
			d.add("E_SCHEMA", "joins must be a map", "", "", "graph", ptr+"/joins")
		} else {
			for k, jv := range jm {
				s, isStr := jv.(string)
				if !isStr || (s != "all" && s != "any") {
					d.add("E_SCHEMA", "join mode must be \"all\" or \"any\"", "", "", "graph", ptr+"/joins/"+escapePtr(k))
				}
			}
		}
	}
	if v, ok := m["retry"]; ok {
		rm, isMap := v.(map[string]any)
		if !isMap {
			d.add("E_SCHEMA", "retry must be a map", "", "", "graph", ptr+"/retry")
		} else {
			ma, hasMA := rm["maxAttempts"].(int64)
			if !hasMA || ma < 1 {
				d.add("E_SCHEMA", "retry.maxAttempts must be an integer >= 1", "", "", "graph", ptr+"/retry/maxAttempts")
			}
			for k, kv := range rm {
				switch k {
				case "maxAttempts":
				case "backoff":
					checkString(kv, ptr+"/retry/backoff", d)
				default:
					d.add("E_SCHEMA", "unknown retry key "+quote(k), "", "", "graph", ptr+"/retry/"+escapePtr(k))
				}
			}
		}
	}
	if v, ok := m["absorb"]; ok {
		if b, isBool := v.(bool); !isBool || !b {
			d.add("E_SCHEMA", "absorb accepts only true", "", "", "graph", ptr+"/absorb")
		}
	}
	if v, ok := m["bind"]; ok {
		validateBind(v, ptr+"/bind", d)
	}
	if v, ok := m["in"]; ok {
		im, isMap := v.(map[string]any)
		if !isMap {
			d.add("E_SCHEMA", "in must be a map", "", "", "graph", ptr+"/in")
		} else {
			for k, iv := range im {
				switch e := iv.(type) {
				case string:
				case []any:
					if len(e) == 0 {
						d.add("E_SCHEMA", "in entry sequence must be non-empty", "", "", "graph", ptr+"/in/"+escapePtr(k))
					}
					for i, ev := range e {
						checkString(ev, fmt.Sprintf("%s/in/%s/%d", ptr, escapePtr(k), i), d)
					}
				default:
					d.add("E_SCHEMA", "in entry must be an endpoint or sequence of endpoints", "", "", "graph", ptr+"/in/"+escapePtr(k))
				}
			}
		}
	}
	if v, ok := m["needs"]; ok {
		validateStringSeq(v, ptr+"/needs", d)
	}
}

func validateBind(v any, ptr string, d *diags) {
	bm, isMap := v.(map[string]any)
	if !isMap {
		d.add("E_SCHEMA", "bind must be a map", "", "", "graph", ptr)
		return
	}
	for k, bv := range bm {
		path, isSeq := bv.([]any)
		if !isSeq {
			d.add("E_SCHEMA", "bind path must be a sequence", "", "", "graph", ptr+"/"+escapePtr(k))
			continue
		}
		for i, pe := range path {
			switch n := pe.(type) {
			case string:
			case int64:
				if n < 0 {
					d.add("E_SCHEMA", "bind path index must be >= 0", "", "", "graph", fmt.Sprintf("%s/%s/%d", ptr, escapePtr(k), i))
				}
			default:
				d.add("E_SCHEMA", "bind path element must be a string or integer", "", "", "graph", fmt.Sprintf("%s/%s/%d", ptr, escapePtr(k), i))
			}
		}
	}
}

func validateRule(v any, ptr string, d *diags) {
	m, ok := v.(map[string]any)
	if !ok {
		d.add("E_SCHEMA", "rule must be a map", "", "", "graph", ptr)
		return
	}
	requireString(m, "route", ptr, d)
	when, hasWhen := m["when"]
	if !hasWhen {
		d.add("E_SCHEMA", "rule requires when", "", "", "graph", ptr+"/when")
	} else {
		validatePredicateShape(when, ptr+"/when", d)
	}
	for k := range m {
		switch k {
		case "route", "when":
		case "to":
			validateStringSeq(m[k], ptr+"/to", d)
		default:
			d.add("E_SCHEMA", "unknown rule key "+quote(k), "", "", "graph", ptr+"/"+escapePtr(k))
		}
	}
}

// validatePredicateShape checks the predicate packaging (defs predicate /
// match-spec.schema.json shapes) — a bad shape is E_SCHEMA; a well-shaped but
// unsatisfiable or illegal predicate is the analyzer's business (§9).
func validatePredicateShape(v any, ptr string, d *diags) {
	m, ok := v.(map[string]any)
	if !ok {
		d.add("E_SCHEMA", "predicate must be a map", "", "", "graph", ptr)
		return
	}
	if ev, isExpr := m["expr"]; isExpr {
		if len(m) != 1 {
			d.add("E_SCHEMA", "guarded expression carries only expr", "", "", "graph", ptr)
		}
		if s, isStr := ev.(string); !isStr || s == "" {
			d.add("E_SCHEMA", "expr must be a non-empty string", "", "", "graph", ptr+"/expr")
		}
		return
	}
	validateMatchShape(v, ptr, d)
}

func validateMatchShape(v any, ptr string, d *diags) {
	m, ok := v.(map[string]any)
	if !ok {
		d.add("E_SCHEMA", "match specification must be a map", "", "", "graph", ptr)
		return
	}
	kind, _ := m["kind"].(string)
	switch kind {
	case "compare":
		op, _ := m["op"].(string)
		switch op {
		case "eq", "ne", "lt", "le", "gt", "ge", "in":
		default:
			d.add("E_SCHEMA", "compare op invalid", "", "", "graph", ptr+"/op")
		}
		if _, hasValue := m["value"]; !hasValue {
			d.add("E_SCHEMA", "compare requires value", "", "", "graph", ptr+"/value")
		}
		validateValuePath(m["path"], ptr+"/path", d)
		for k := range m {
			switch k {
			case "kind", "path", "op", "value":
			default:
				d.add("E_SCHEMA", "unknown match key "+quote(k), "", "", "graph", ptr+"/"+escapePtr(k))
			}
		}
	case "present", "absent":
		validateValuePath(m["path"], ptr+"/path", d)
		for k := range m {
			switch k {
			case "kind", "path":
			default:
				d.add("E_SCHEMA", "unknown match key "+quote(k), "", "", "graph", ptr+"/"+escapePtr(k))
			}
		}
	case "all", "any":
		of, ok := m["of"].([]any)
		if !ok || len(of) == 0 {
			d.add("E_SCHEMA", "of must be a non-empty sequence", "", "", "graph", ptr+"/of")
		} else {
			for i, sub := range of {
				validateMatchShape(sub, fmt.Sprintf("%s/of/%d", ptr, i), d)
			}
		}
		for k := range m {
			switch k {
			case "kind", "of":
			default:
				d.add("E_SCHEMA", "unknown match key "+quote(k), "", "", "graph", ptr+"/"+escapePtr(k))
			}
		}
	default:
		d.add("E_SCHEMA", "predicate kind invalid", "", "", "graph", ptr+"/kind")
	}
}

func validateValuePath(v any, ptr string, d *diags) {
	path, ok := v.([]any)
	if !ok {
		d.add("E_SCHEMA", "path must be a sequence", "", "", "graph", ptr)
		return
	}
	for i, pe := range path {
		switch n := pe.(type) {
		case string:
		case int64:
			if n < 0 {
				d.add("E_SCHEMA", "path index must be >= 0", "", "", "graph", fmt.Sprintf("%s/%d", ptr, i))
			}
		default:
			d.add("E_SCHEMA", "path element must be a string or integer", "", "", "graph", fmt.Sprintf("%s/%d", ptr, i))
		}
	}
}

func validateStringSeq(v any, ptr string, d *diags) {
	s, ok := v.([]any)
	if !ok {
		d.add("E_SCHEMA", "expected a sequence of strings", "", "", "graph", ptr)
		return
	}
	for i, e := range s {
		checkString(e, fmt.Sprintf("%s/%d", ptr, i), d)
	}
}

func requireString(m map[string]any, key, ptr string, d *diags) {
	v, ok := m[key]
	if !ok {
		d.add("E_SCHEMA", "missing required "+key, "", "", "graph", ptr+"/"+key)
		return
	}
	checkString(v, ptr+"/"+key, d)
}

func checkString(v any, ptr string, d *diags) {
	if _, ok := v.(string); !ok {
		d.add("E_SCHEMA", "expected a string", "", "", "graph", ptr)
	}
}

func quote(s string) string { return "\"" + s + "\"" }

func escapePtr(s string) string {
	s = strings.ReplaceAll(s, "~", "~0")
	return strings.ReplaceAll(s, "/", "~1")
}
