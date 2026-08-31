package kernel

import (
	"fmt"
	"sort"
	"strings"

	"github.com/rfontes1987/wilanis-go/internal/value"
)

// Artifact is the compiled artifact's public surface (§10.8): identity, the
// canonical spec, and per-node derivation hashes. Everything else is private.
type Artifact struct {
	GraphHash     string
	CanonicalSpec map[string]any
	Derivations   map[string]string
	Lints         []Diagnostic

	// private executable layout
	reg           *Registry
	anal          *analysis
	exportClasses map[string]int // export name → sensitivity rank
	hasPii        bool           // any node output/export of this graph or a composed child
	subjectInput  string         // the input declared subject:true, if exactly one
}

// Compile is the kernel's first operation (§10): spec + registry (+ options)
// to a compiled artifact or exhaustive diagnostics.
func Compile(spec any, reg *Registry, options map[string]any) (*Artifact, []Diagnostic) {
	strict := false
	if options != nil {
		strict, _ = options["strict"].(bool)
	}

	// Stage 1: packaging shape (§10.1.1). A violation poisons all later stages.
	d := &diags{}
	validateShape(spec, d)
	if len(d.list) > 0 {
		return nil, d.sorted()
	}
	root := deepCopy(spec).(map[string]any)

	// Stage 2: fan-out sugar (§7.6 rule 4); violations are E_SCHEMA and poison.
	expandFanoutSugar(root, d)
	if len(d.list) > 0 {
		return nil, d.sorted()
	}

	// Stage 3: desugar the remaining conveniences (§7.6 rules 1–3, 5).
	desugar(root)

	// Stage 4: normalize (§7.7).
	canonical := normalize(root)

	// Stages 5–6: analyze structure and propagate sensitivity, over the
	// canonical form only.
	a := analyze(canonical, reg, d)

	// Stage 7: gate.
	if d.hasBlocking() || (strict && len(d.list) > 0) {
		return nil, d.sorted()
	}

	// Stage 8: hash.
	derivations := deriveHashes(canonical, a, reg)
	a.derivations = derivations
	graphHash := value.Hash(any(canonical))

	art := &Artifact{
		GraphHash:     graphHash,
		CanonicalSpec: canonical,
		Derivations:   derivations,
		Lints:         d.sorted(),
		reg:           reg,
		anal:          a,
		exportClasses: a.exportClasses,
		hasPii:        a.hasPii,
		subjectInput:  a.subjectInput,
	}
	return art, nil
}

func deepCopy(v any) any {
	switch x := v.(type) {
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = deepCopy(e)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = deepCopy(e)
		}
		return out
	}
	return v
}

// hasMarker reports whether an `in` entry (string or sequence) carries the
// fan-out marker `[*]`.
func entryHasMarker(v any) bool {
	switch e := v.(type) {
	case string:
		return strings.HasSuffix(e, "[*]")
	case []any:
		for _, s := range e {
			if str, ok := s.(string); ok && strings.HasSuffix(str, "[*]") {
				return true
			}
		}
	}
	return false
}

func stripMarker(v any) any {
	switch e := v.(type) {
	case string:
		return strings.TrimSuffix(e, "[*]")
	case []any:
		out := make([]any, len(e))
		for i, s := range e {
			if str, ok := s.(string); ok {
				out[i] = strings.TrimSuffix(str, "[*]")
			} else {
				out[i] = s
			}
		}
		return out
	}
	return v
}

// expandFanoutSugar applies §7.6 rule 4.
func expandFanoutSugar(root map[string]any, d *diags) {
	nodes, _ := root["nodes"].([]any)
	for i, nv := range nodes {
		node := nv.(map[string]any)
		id, _ := node["id"].(string)
		species, _ := node["species"].(string)
		isRoutine := species == "" || species == "routine"
		in, _ := node["in"].(map[string]any)
		var marked []string
		for k, e := range in {
			if entryHasMarker(e) {
				marked = append(marked, k)
			}
		}
		sort.Strings(marked)
		ptr := fmt.Sprintf("/nodes/%d", i)
		if len(marked) == 0 {
			if _, hasBind := node["bind"]; hasBind && isRoutine {
				d.add("E_SCHEMA", "bind on a routine node without a fan-out marker", id, "", "node:"+id, ptr+"/bind")
			}
			continue
		}
		if !isRoutine {
			d.add("E_SCHEMA", "fan-out marker on a non-routine node", id, "", "node:"+id, ptr+"/in")
			continue
		}
		if len(marked) > 1 {
			d.add("E_SCHEMA", "fan-out markers on more than one entry of one node", id, "", "node:"+id, ptr+"/in")
			continue
		}
		over := marked[0]
		node["species"] = "map"
		node["body"] = node["routine"]
		delete(node, "routine")
		node["over"] = over
		in[over] = stripMarker(in[over])
	}
}

// desugar applies §7.6 rules 1–3 and 5, leaving root with explicit edges only.
func desugar(root map[string]any) {
	nodes, _ := root["nodes"].([]any)
	var edges []any
	if e, ok := root["edges"].([]any); ok {
		edges = e
	}

	// Rule 1: per-node input bindings. Explicit edges (already in the list)
	// take the earlier binding indexes for a shared input.
	for _, nv := range nodes {
		node := nv.(map[string]any)
		id, _ := node["id"].(string)
		if in, ok := node["in"].(map[string]any); ok {
			for _, name := range value.SortedKeys(in) {
				entry := in[name]
				var endpoints []any
				switch e := entry.(type) {
				case string:
					endpoints = []any{e}
				case []any:
					endpoints = e
				}
				for _, ep := range endpoints {
					eps, _ := ep.(string)
					edges = append(edges, map[string]any{
						"kind": "data", "from": eps, "to": id + "." + name,
					})
				}
			}
			delete(node, "in")
		}
		// Rule 2: per-node ordering dependencies.
		if needs, ok := node["needs"].([]any); ok {
			for _, nid := range needs {
				ns, _ := nid.(string)
				edges = append(edges, map[string]any{
					"kind": "order", "from": ns, "to": id,
				})
			}
			delete(node, "needs")
		}
		// Rule 5: gate edges from a decision table.
		if species, _ := node["species"].(string); species == "decision" {
			rules, _ := node["rules"].([]any)
			for _, rv := range rules {
				rule := rv.(map[string]any)
				if to, ok := rule["to"].([]any); ok {
					route, _ := rule["route"].(string)
					for _, tv := range to {
						ts, _ := tv.(string)
						edges = append(edges, map[string]any{
							"kind": "order", "from": id + ".route." + route, "to": ts,
						})
					}
					delete(rule, "to")
				}
			}
			if defaultTo, ok := node["defaultTo"].([]any); ok {
				def, _ := node["default"].(string)
				for _, tv := range defaultTo {
					ts, _ := tv.(string)
					edges = append(edges, map[string]any{
						"kind": "order", "from": id + ".route." + def, "to": ts,
					})
				}
				delete(node, "defaultTo")
			}
		}
	}

	// Rule 3: graph-level guards expand last. An entry node has no incoming
	// edge whose from names a node ($input edges do not count); guards
	// themselves are excluded.
	if guards, ok := root["guards"].([]any); ok {
		guardSet := map[string]bool{}
		for _, gv := range guards {
			if gs, ok := gv.(string); ok {
				guardSet[gs] = true
			}
		}
		hasIncoming := map[string]bool{}
		for _, ev := range edges {
			edge := ev.(map[string]any)
			from, _ := edge["from"].(string)
			if strings.HasPrefix(from, "$input.") {
				continue
			}
			to, _ := edge["to"].(string)
			toNode := to
			if i := strings.IndexByte(to, '.'); i >= 0 {
				toNode = to[:i]
			}
			hasIncoming[toNode] = true
		}
		for _, gv := range guards {
			gs, _ := gv.(string)
			for _, nv := range nodes {
				node := nv.(map[string]any)
				id, _ := node["id"].(string)
				if guardSet[id] || hasIncoming[id] {
					continue
				}
				edges = append(edges, map[string]any{
					"kind": "order", "from": gs, "to": id,
				})
			}
		}
		delete(root, "guards")
	}

	root["edges"] = edges
}

// normalize applies §7.7 to a desugared root, returning the canonical spec.
func normalize(root map[string]any) map[string]any {
	nodes, _ := root["nodes"].([]any)
	// rule 1: one spelling — remove species: "routine"
	canonNodes := make([]any, 0, len(nodes))
	for _, nv := range nodes {
		node := deepCopy(nv).(map[string]any)
		if s, _ := node["species"].(string); s == "routine" {
			delete(node, "species")
		}
		canonNodes = append(canonNodes, node)
	}
	// rule 2: nodes sort by id (UTF-8 bytes)
	sort.SliceStable(canonNodes, func(i, j int) bool {
		a, _ := canonNodes[i].(map[string]any)["id"].(string)
		b, _ := canonNodes[j].(map[string]any)["id"].(string)
		return a < b
	})

	// rule 3: edges sort by (to.node, to.input, bindingIndex); binding index
	// is declaration position among data edges sharing (to.node, to.input),
	// preserved; order edges take to.input = "" and tie by (from.node,
	// from.path).
	edges, _ := root["edges"].([]any)
	type edgeRec struct {
		m                       map[string]any
		kind, toNode, toInput   string
		bindingIndex            int
		fromNode, fromPathSpell string
	}
	recs := make([]*edgeRec, 0, len(edges))
	bindingCount := map[string]int{}
	for _, ev := range edges {
		edge := deepCopy(ev).(map[string]any)
		rec := &edgeRec{m: edge}
		rec.kind, _ = edge["kind"].(string)
		to, _ := edge["to"].(string)
		from, _ := edge["from"].(string)
		if i := strings.IndexByte(from, '.'); i >= 0 {
			rec.fromNode, rec.fromPathSpell = from[:i], from[i+1:]
		} else {
			rec.fromNode = from
		}
		if rec.kind == "data" {
			if i := strings.IndexByte(to, '.'); i >= 0 {
				rec.toNode, rec.toInput = to[:i], to[i+1:]
			} else {
				rec.toNode = to
			}
			key := rec.toNode + "\x00" + rec.toInput
			rec.bindingIndex = bindingCount[key]
			bindingCount[key]++
		} else {
			rec.toNode = to
		}
		recs = append(recs, rec)
	}
	sort.SliceStable(recs, func(i, j int) bool {
		a, b := recs[i], recs[j]
		if a.toNode != b.toNode {
			return a.toNode < b.toNode
		}
		if a.toInput != b.toInput {
			return a.toInput < b.toInput
		}
		if a.kind == "data" && b.kind == "data" {
			return a.bindingIndex < b.bindingIndex
		}
		if a.fromNode != b.fromNode {
			return a.fromNode < b.fromNode
		}
		return a.fromPathSpell < b.fromPathSpell
	})
	// rule 4: regenerate every edge id
	orderCount := map[string]int{}
	canonEdges := make([]any, 0, len(recs))
	for _, rec := range recs {
		if rec.kind == "data" {
			rec.m["id"] = fmt.Sprintf("d:%s:%s:%d", rec.toNode, rec.toInput, rec.bindingIndex)
		} else {
			rec.m["id"] = fmt.Sprintf("o:%s:%d", rec.toNode, orderCount[rec.toNode])
			orderCount[rec.toNode]++
		}
		canonEdges = append(canonEdges, rec.m)
	}

	canonical := map[string]any{
		"name":  root["name"],
		"nodes": canonNodes,
		"edges": canonEdges,
		// rule 5: the evaluator version the compiler will apply (§9.6)
		"evaluatorVersion": evaluatorVersionTag(),
	}
	if exports, ok := root["exports"]; ok {
		canonical["exports"] = deepCopy(exports)
	} else {
		canonical["exports"] = []any{}
	}
	// rule 6: everything else copied verbatim; absent stays absent
	for _, k := range []string{"inputs", "distribution", "renames"} {
		if v, ok := root[k]; ok {
			canonical[k] = deepCopy(v)
		}
	}
	return canonical
}

// deriveHashes computes every node's derivation hash (§7.9) in topological
// order over data edges.
func deriveHashes(canonical map[string]any, a *analysis, reg *Registry) map[string]string {
	out := map[string]string{}
	var visit func(id string) string
	visiting := map[string]bool{}
	visit = func(id string) string {
		if h, ok := out[id]; ok {
			return h
		}
		if visiting[id] {
			return "" // cycle: gated before hashing; defensive only
		}
		visiting[id] = true
		defer delete(visiting, id)
		n := a.nodes[id]
		recipe := map[string]any{}
		inputs := map[string]any{}
		for name, group := range n.inputs {
			bindings := make([]any, 0, len(group.bindings))
			for _, b := range group.bindings {
				if b.isInput {
					bindings = append(bindings, map[string]any{"input": b.inputName})
				} else {
					bindings = append(bindings, map[string]any{
						"from": visit(b.producer),
						"path": pathValue(b.path),
					})
				}
			}
			inputs[name] = map[string]any{"join": group.mode, "bindings": bindings}
		}
		recipe["inputs"] = inputs
		switch n.species {
		case "routine":
			recipe["species"] = "routine"
			recipe["routine"] = n.ref
			if params, ok := n.spec["params"]; ok {
				recipe["params"] = deepCopy(params)
			}
			if absorb, _ := n.spec["absorb"].(bool); absorb {
				recipe["absorb"] = true
			}
		case "decision":
			recipe["species"] = "decision"
			rules, _ := n.spec["rules"].([]any)
			recipe["rules"] = deepCopy(rules)
			recipe["default"] = n.spec["default"]
			recipe["evaluator"] = canonical["evaluatorVersion"]
		case "map":
			recipe["species"] = "map"
			recipe["body"] = n.ref
			recipe["over"] = n.spec["over"]
			if bind, ok := n.spec["bind"]; ok {
				recipe["bind"] = deepCopy(bind)
			}
			if params, ok := n.spec["params"]; ok {
				recipe["params"] = deepCopy(params)
			}
			if absorb, _ := n.spec["absorb"].(bool); absorb {
				recipe["absorb"] = true
			}
		case "invoke":
			recipe["species"] = "invoke"
			recipe["graph"] = n.ref
		}
		h := value.Hash(any(recipe))
		out[id] = h
		return h
	}
	for id := range a.nodes {
		visit(id)
	}
	return out
}
