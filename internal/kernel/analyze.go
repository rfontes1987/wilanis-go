package kernel

import (
	"fmt"
	"strings"

	"github.com/rfontes1987/wilanis-go/internal/value"
)

// bindingView is one data binding (one edge into one input).
type bindingView struct {
	isInput   bool
	inputName string // graph input, when isInput
	producer  string // node id, when !isInput
	path      []any
	edgeID    string
	fromRaw   string
	parsedOK  bool
	srcKnown  bool // producer exists (or is a declared graph input)
}

// groupView is one consumer input's join group (§7.5).
type groupView struct {
	mode     string // effective: "all" | "any"
	declared bool
	bindings []*bindingView
}

// orderEdgeView is one order requirement.
type orderEdgeView struct {
	producer string
	path     []any // empty, or ["route", label]
	edgeID   string
	parsedOK bool
	srcKnown bool
}

type nodeView struct {
	id         string
	species    string // routine | decision | map | invoke
	ref        string // routine / body / graph reference
	spec       map[string]any
	contract   *Contract // routine contract or fan-out body contract
	childArt   *Artifact // invoke child
	refKnown   bool
	inputs     map[string]*groupView
	inputOrder []string // deterministic iteration
	orderEdges []*orderEdgeView
}

type exportView struct {
	name string
	ep   endpoint
	ok   bool
}

type analysis struct {
	spec           map[string]any
	nodes          map[string]*nodeView
	nodeOrder      []string
	declaredInputs map[string]map[string]any
	exports        []exportView
	hasCycle       bool

	// sensitivity results
	portClass     map[string]map[string]int // node id → port → rank (fan-out/decision under "")
	nodeClass     map[string]int
	fanChildClass map[string]int // fan-out node id → its routine-body children's fact class
	exportClasses map[string]int
	hasPii        bool
	subjectInput  string

	// per-node derivation hashes, filled by deriveHashes post-gate
	derivations map[string]string
}

const (
	classPublic   = 0
	classInternal = 1
	classPii      = 2
)

func classRank(s string) int {
	switch s {
	case "public":
		return classPublic
	case "pii":
		return classPii
	}
	return classInternal
}

// analyze runs stages 5–6 of §10.1 over the canonical form: every §10.5
// structural check, exhaustively, then sensitivity propagation (§10.6).
func analyze(canonical map[string]any, reg *Registry, d *diags) *analysis {
	a := &analysis{
		spec:           canonical,
		nodes:          map[string]*nodeView{},
		declaredInputs: map[string]map[string]any{},
		portClass:      map[string]map[string]int{},
		nodeClass:      map[string]int{},
		fanChildClass:  map[string]int{},
		exportClasses:  map[string]int{},
	}

	// --- nodes: identifiers, duplicates, references ---
	nodesSeq, _ := canonical["nodes"].([]any)
	for _, nv := range nodesSeq {
		spec := nv.(map[string]any)
		id, _ := spec["id"].(string)
		species, _ := spec["species"].(string)
		if species == "" {
			species = "routine"
		}
		if !identOK(id) {
			d.add("E_IDENT", "node id violates the identifier grammar", id, "", "node:"+id, "")
		}
		if _, dup := a.nodes[id]; dup {
			d.add("E_NODE_DUP", "duplicate node id "+quote(id), id, "", "node:"+id, "")
			continue
		}
		n := &nodeView{id: id, species: species, spec: spec, inputs: map[string]*groupView{}}
		a.nodes[id] = n
		a.nodeOrder = append(a.nodeOrder, id)

		switch species {
		case "routine", "map":
			refKey := "routine"
			if species == "map" {
				refKey = "body"
			}
			ref, _ := spec[refKey].(string)
			n.ref = ref
			if !versionedRefOK(ref) {
				d.add("E_IDENT", refKey+" reference violates the versioned-reference grammar", id, "", "node:"+id, "")
			} else if c, ok := reg.Routines[ref]; ok {
				n.contract = c
				n.refKnown = true
			} else if ga := reg.ResolveGraph(ref); species == "map" && ga != nil {
				// a fan-out body may be a graph used as one (§7.2)
				n.childArt = ga
				n.refKnown = true
			} else {
				d.add("E_REF_UNKNOWN", "reference "+quote(ref)+" is not bound by the registry", id, "", "node:"+id, "")
			}
			if species == "map" {
				if over, _ := spec["over"].(string); !identOK(over) {
					d.add("E_IDENT", "over violates the identifier grammar", id, "", "node:"+id, "")
				}
				if bind, ok := spec["bind"].(map[string]any); ok {
					for _, k := range value.SortedKeys(bind) {
						if !identOK(k) {
							d.add("E_IDENT", "bind target violates the identifier grammar", id, "", "node:"+id+"/input:"+k, "")
						}
					}
				}
			}
		case "decision":
			seen := map[string]bool{}
			rules, _ := spec["rules"].([]any)
			for i, rv := range rules {
				rule := rv.(map[string]any)
				route, _ := rule["route"].(string)
				addr := fmt.Sprintf("node:%s/rule:%d", id, i)
				if !identOK(route) {
					d.add("E_IDENT", "route label violates the identifier grammar", id, "", addr, "")
				}
				if seen[route] {
					d.add("E_DECISION_ROUTE_DUP", "duplicate route label "+quote(route), id, "", addr, "")
				}
				seen[route] = true
			}
			def, _ := spec["default"].(string)
			if !identOK(def) {
				d.add("E_IDENT", "default route label violates the identifier grammar", id, "", "node:"+id, "")
			}
			if seen[def] {
				d.add("E_DECISION_ROUTE_DUP", "default duplicates route label "+quote(def), id, "", "node:"+id, "")
			}
			n.refKnown = true
		case "invoke":
			ref, _ := spec["graph"].(string)
			n.ref = ref
			if !versionedRefOK(ref) {
				d.add("E_IDENT", "graph reference violates the versioned-reference grammar", id, "", "node:"+id, "")
			} else if ga := reg.ResolveGraph(ref); ga != nil {
				n.childArt = ga
				n.refKnown = true
			} else {
				d.add("E_REF_UNKNOWN", "graph reference "+quote(ref)+" does not resolve", id, "", "node:"+id, "")
			}
		}
		if joins, ok := spec["joins"].(map[string]any); ok {
			for _, k := range value.SortedKeys(joins) {
				if !identOK(k) {
					d.add("E_IDENT", "join key violates the identifier grammar", id, "", "node:"+id+"/input:"+k, "")
				}
			}
		}
		if params, ok := spec["params"].(map[string]any); ok {
			for _, k := range value.SortedKeys(params) {
				if !identOK(k) {
					d.add("E_IDENT", "params key violates the identifier grammar", id, "", "node:"+id+"/param:"+k, "")
				}
			}
		}
	}

	// --- declared inputs and exports ---
	name, _ := canonical["name"].(string)
	if !identOK(name) {
		d.add("E_IDENT", "graph name violates the identifier grammar", "", "", "graph", "/name")
	}
	if inputs, ok := canonical["inputs"].(map[string]any); ok {
		for _, iname := range value.SortedKeys(inputs) {
			if !identOK(iname) {
				d.add("E_IDENT", "input name violates the identifier grammar", "", "", "input:"+iname, "")
			}
			a.declaredInputs[iname] = inputs[iname].(map[string]any)
		}
	}
	exportsSeq, _ := canonical["exports"].([]any)
	exportNames := map[string]bool{}
	for _, ev := range exportsSeq {
		em := ev.(map[string]any)
		ename, _ := em["name"].(string)
		efrom, _ := em["from"].(string)
		if !identOK(ename) {
			d.add("E_IDENT", "export name violates the identifier grammar", "", "", "export:"+ename, "")
		}
		if exportNames[ename] {
			d.add("E_EXPORT_DUP", "duplicate export name "+quote(ename), "", "", "export:"+ename, "")
		}
		exportNames[ename] = true
		ep, ok := parseEndpoint(efrom)
		if !ok {
			d.add("E_ENDPOINT_PARSE", "export endpoint does not parse", "", "", "export:"+ename, "")
		}
		a.exports = append(a.exports, exportView{name: ename, ep: ep, ok: ok})
	}

	// --- edges ---
	edgesSeq, _ := canonical["edges"].([]any)
	inputRead := map[string]bool{}
	for _, ev := range edgesSeq {
		em := ev.(map[string]any)
		kind, _ := em["kind"].(string)
		fromRaw, _ := em["from"].(string)
		toRaw, _ := em["to"].(string)
		edgeID, _ := em["id"].(string)
		addr := "edge:" + edgeID

		fromEp, fromOK := parseEndpoint(fromRaw)
		if !fromOK {
			d.add("E_ENDPOINT_PARSE", "edge from endpoint does not parse", "", edgeID, addr, "")
		}
		if kind == "data" {
			dot := strings.IndexByte(toRaw, '.')
			var toNode, toInput string
			toOK := dot > 0
			if toOK {
				toNode, toInput = toRaw[:dot], toRaw[dot+1:]
				if !identOK(toNode) || !identOK(toInput) {
					toOK = false
				}
			}
			if !toOK {
				d.add("E_ENDPOINT_PARSE", "data edge to endpoint does not parse", "", edgeID, addr, "")
				continue
			}
			consumer, consumerKnown := a.nodes[toNode]
			if !consumerKnown {
				d.add("E_EDGE_UNKNOWN_NODE", "data edge to unknown node "+quote(toNode), "", edgeID, addr, "")
			}
			b := &bindingView{edgeID: edgeID, fromRaw: fromRaw, parsedOK: fromOK}
			if fromOK {
				if fromEp.IsInput {
					b.isInput = true
					b.inputName = fromEp.Input
					inputRead[fromEp.Input] = true
					if _, declared := a.declaredInputs[fromEp.Input]; !declared {
						d.add("E_INPUT_UNDECLARED", "edge reads undeclared graph input "+quote(fromEp.Input), "", edgeID, addr, "")
					} else {
						b.srcKnown = true
					}
				} else {
					b.producer = fromEp.Node
					b.path = fromEp.Path
					producer, ok := a.nodes[fromEp.Node]
					if !ok {
						d.add("E_EDGE_UNKNOWN_NODE", "edge from unknown node "+quote(fromEp.Node), "", edgeID, addr, "")
					} else {
						b.srcKnown = true
						checkFromPort(producer, fromEp.Path, false, edgeID, addr, d)
					}
				}
			}
			if consumerKnown {
				group := consumer.inputs[toInput]
				if group == nil {
					group = &groupView{mode: "all"}
					consumer.inputs[toInput] = group
					consumer.inputOrder = append(consumer.inputOrder, toInput)
				}
				group.bindings = append(group.bindings, b)
				// consumer input declared? (statically known input sets only)
				checkConsumerInput(consumer, toInput, edgeID, addr, d)
			}
		} else { // order
			if !identOK(toRaw) {
				d.add("E_ENDPOINT_PARSE", "order edge to endpoint does not parse", "", edgeID, addr, "")
				continue
			}
			consumer, consumerKnown := a.nodes[toRaw]
			if !consumerKnown {
				d.add("E_EDGE_UNKNOWN_NODE", "order edge to unknown node "+quote(toRaw), "", edgeID, addr, "")
			}
			oe := &orderEdgeView{edgeID: edgeID, parsedOK: fromOK}
			if fromOK {
				if fromEp.IsInput {
					d.add("E_ENDPOINT_PARSE", "order edge from a graph input", "", edgeID, addr, "")
				} else {
					oe.producer = fromEp.Node
					oe.path = fromEp.Path
					producer, ok := a.nodes[fromEp.Node]
					if !ok {
						d.add("E_EDGE_UNKNOWN_NODE", "order edge from unknown node "+quote(fromEp.Node), "", edgeID, addr, "")
					} else {
						oe.srcKnown = true
						if len(fromEp.Path) > 0 {
							// only a decision route port may carry a path (§7.3)
							if producer.species == "decision" && len(fromEp.Path) == 2 && eqSeg(fromEp.Path[0], "route") {
								label, isStr := fromEp.Path[1].(string)
								if !isStr || !decisionHasRoute(producer, label) {
									d.add("E_GATE_UNKNOWN_ROUTE", "gate references undeclared route", "", edgeID, addr, "")
								}
							} else {
								d.add("E_ORDER_PATH", "order edge path is not a decision route port", "", edgeID, addr, "")
							}
						}
					}
				}
			}
			if consumerKnown {
				consumer.orderEdges = append(consumer.orderEdges, oe)
			}
		}
	}

	// --- joins (§7.5, §10.5.4) ---
	for _, id := range a.nodeOrder {
		n := a.nodes[id]
		joins, _ := n.spec["joins"].(map[string]any)
		for _, iname := range n.inputOrder {
			group := n.inputs[iname]
			if mode, ok := joins[iname].(string); ok {
				group.mode = mode
				group.declared = true
			}
			if len(group.bindings) > 1 && !group.declared {
				d.add("E_DUP_BINDING", "input "+quote(iname)+" has multiple bindings and no join declaration", id, "", "node:"+id+"/input:"+iname, "")
			}
		}
		for _, jname := range value.SortedKeys(joins) {
			if g, ok := n.inputs[jname]; !ok || len(g.bindings) == 0 {
				d.add("E_JOIN_INVALID", "join declaration names input "+quote(jname)+" with no bindings", id, "", "node:"+id+"/input:"+jname, "")
			}
		}
	}

	// --- shapes (§10.5.3 tail) ---
	for _, id := range a.nodeOrder {
		n := a.nodes[id]
		for _, iname := range n.inputOrder {
			group := n.inputs[iname]
			if len(group.bindings) != 1 {
				continue // a joined input's constructed value is not statically checked
			}
			b := group.bindings[0]
			if !b.parsedOK || !b.srcKnown {
				continue
			}
			consumerShape := consumerInputShape(a, n, iname)
			if consumerShape == nil {
				continue
			}
			producerShape := a.sourceShape(b)
			if producerShape == nil {
				continue
			}
			if !shapeCompatible(producerShape, consumerShape) {
				d.add("E_SHAPE_MISMATCH", "producer shape incompatible with consumer input "+quote(iname), id, "", "node:"+id+"/input:"+iname, "")
			}
		}
	}

	// --- cycle over the full edge set (§10.5.5) ---
	adj := map[string][]string{}
	for _, id := range a.nodeOrder {
		n := a.nodes[id]
		for _, g := range n.inputs {
			for _, b := range g.bindings {
				if !b.isInput && b.srcKnown {
					adj[b.producer] = append(adj[b.producer], id)
				}
			}
		}
		for _, oe := range n.orderEdges {
			if oe.srcKnown {
				adj[oe.producer] = append(adj[oe.producer], id)
			}
		}
	}
	if hasCycle(a.nodeOrder, adj) {
		a.hasCycle = true
		d.add("E_CYCLE", "the edge set contains a cycle", "", "", "graph", "")
	}

	// --- reachability (§10.5.6) ---
	target := map[string]bool{}
	for _, ex := range a.exports {
		if ex.ok && !ex.ep.IsInput {
			target[ex.ep.Node] = true
		}
	}
	for _, id := range a.nodeOrder {
		n := a.nodes[id]
		// a node whose reference failed to resolve has an unknowable effect
		// class: the check is skipped for it and for its ancestors (§10.2)
		if !n.refKnown || a.nodeEffectful(n) {
			target[id] = true
		}
	}
	// ancestors of targets: reverse-walk
	good := map[string]bool{}
	var mark func(id string)
	radj := map[string][]string{}
	for from, tos := range adj {
		for _, to := range tos {
			radj[to] = append(radj[to], from)
		}
	}
	mark = func(id string) {
		if good[id] {
			return
		}
		good[id] = true
		for _, p := range radj[id] {
			mark(p)
		}
	}
	for id := range target {
		mark(id)
	}
	for _, id := range a.nodeOrder {
		if !good[id] && a.nodes[id].refKnown {
			d.add("E_UNREACHABLE", "node influences no export and no effectful node", id, "", "node:"+id, "")
		}
	}

	// --- params (§10.5.9) and required inputs (§10.5.8) ---
	for _, id := range a.nodeOrder {
		n := a.nodes[id]
		a.checkParams(n, d)
		a.checkRequiredInputs(n, d)
	}

	// --- exports resolve (§10.5.7) ---
	for _, ex := range a.exports {
		if !ex.ok {
			continue
		}
		if ex.ep.IsInput {
			if _, declared := a.declaredInputs[ex.ep.Input]; !declared {
				d.add("E_INPUT_UNDECLARED", "export reads undeclared graph input "+quote(ex.ep.Input), "", "", "export:"+ex.name, "")
			} else {
				inputRead[ex.ep.Input] = true
			}
			continue
		}
		producer, ok := a.nodes[ex.ep.Node]
		if !ok {
			d.add("E_EXPORT_UNKNOWN", "export projects unknown node "+quote(ex.ep.Node), "", "", "export:"+ex.name, "")
			continue
		}
		checkFromPort(producer, ex.ep.Path, true, "", "export:"+ex.name, d)
	}

	// --- unused declared inputs ---
	for _, iname := range value.SortedKeys(mapAny(a.declaredInputs)) {
		if !inputRead[iname] {
			d.add("L_INPUT_UNUSED", "declared input "+quote(iname)+" is never read", "", "", "input:"+iname, "")
		}
	}

	// --- predicates (§9, §10.5.10) ---
	for _, id := range a.nodeOrder {
		n := a.nodes[id]
		if n.species == "decision" {
			checkDecisionPredicates(n, d)
		}
	}

	// --- fan-out checks (§10.5.11) ---
	for _, id := range a.nodeOrder {
		n := a.nodes[id]
		if n.species == "map" {
			a.checkFanout(n, d)
		}
	}

	// --- sensitivity (§10.6) ---
	a.propagateSensitivity(d)

	return a
}

func mapAny(m map[string]map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k := range m {
		out[k] = nil
	}
	return out
}

func eqSeg(seg any, s string) bool {
	str, ok := seg.(string)
	return ok && str == s
}

func decisionHasRoute(n *nodeView, label string) bool {
	rules, _ := n.spec["rules"].([]any)
	for _, rv := range rules {
		if r, _ := rv.(map[string]any)["route"].(string); r == label {
			return true
		}
	}
	def, _ := n.spec["default"].(string)
	return def == label
}

// checkFromPort checks a from path against the producer's statically known
// port set (§10.5.3). isExport selects the diagnostic code.
func checkFromPort(producer *nodeView, path []any, isExport bool, edgeID, addr string, d *diags) {
	code := "E_EDGE_UNKNOWN_PORT"
	msg := "edge from path names no statically known port"
	if isExport {
		code = "E_EXPORT_UNKNOWN"
		msg = "export projects no statically known port"
	}
	bad := func() { d.add(code, msg, producer.id, edgeID, addr, "") }
	switch producer.species {
	case "routine":
		if !producer.refKnown {
			return // poisoned by E_REF_UNKNOWN
		}
		if producer.contract.LoneDefaultPort() {
			return // committed bare: any path is statically legal (§8.4)
		}
		if len(path) == 0 {
			bad()
			return
		}
		port, ok := path[0].(string)
		if !ok || producer.contract.Output(port) == nil {
			bad()
		}
	case "decision":
		if len(path) == 0 {
			bad() // a decision's empty path names no port in the static set
			return
		}
		port, ok := path[0].(string)
		if !ok || (port != "selected" && port != "matched_rule") {
			bad()
		}
	case "map":
		// the bare gather — any path
		return
	case "invoke":
		if !producer.refKnown {
			return
		}
		if len(path) == 0 {
			bad()
			return
		}
		port, ok := path[0].(string)
		if !ok || !producer.childArt.hasExport(port) {
			bad()
		}
	}
}

func (art *Artifact) hasExport(name string) bool {
	exports, _ := art.CanonicalSpec["exports"].([]any)
	for _, ev := range exports {
		if n, _ := ev.(map[string]any)["name"].(string); n == name {
			return true
		}
	}
	return false
}

func (art *Artifact) declaredInputs() map[string]map[string]any {
	out := map[string]map[string]any{}
	if inputs, ok := art.CanonicalSpec["inputs"].(map[string]any); ok {
		for k, v := range inputs {
			if m, ok := v.(map[string]any); ok {
				out[k] = m
			}
		}
	}
	return out
}

// checkConsumerInput checks E_EDGE_UNKNOWN_INPUT where the consumer's input
// set is statically known (§10.5.3).
func checkConsumerInput(consumer *nodeView, input string, edgeID, addr string, d *diags) {
	unknown := func() {
		d.add("E_EDGE_UNKNOWN_INPUT", "consumer does not declare input "+quote(input), consumer.id, edgeID, addr, "")
	}
	switch consumer.species {
	case "routine":
		if !consumer.refKnown {
			return
		}
		if consumer.contract.Input(input) == nil {
			unknown()
		}
	case "map":
		if input == over(consumer) {
			return
		}
		if !consumer.refKnown {
			return
		}
		// body-derived names (broadcasts)
		if consumer.contract != nil {
			if consumer.contract.Input(input) == nil {
				unknown()
			}
		} else if consumer.childArt != nil {
			if _, ok := consumer.childArt.declaredInputs()[input]; !ok {
				unknown()
			}
		}
	case "invoke":
		if !consumer.refKnown {
			return
		}
		if _, ok := consumer.childArt.declaredInputs()[input]; !ok {
			unknown()
		}
	case "decision":
		// a decision node's inputs are declared by its edges
	}
}

func over(n *nodeView) string {
	o, _ := n.spec["over"].(string)
	return o
}

func hasCycle(order []string, adj map[string][]string) bool {
	state := map[string]int{} // 0 unvisited, 1 visiting, 2 done
	var visit func(string) bool
	visit = func(id string) bool {
		switch state[id] {
		case 1:
			return true
		case 2:
			return false
		}
		state[id] = 1
		for _, next := range adj[id] {
			if visit(next) {
				return true
			}
		}
		state[id] = 2
		return false
	}
	for _, id := range order {
		if visit(id) {
			return true
		}
	}
	return false
}

// nodeEffectful reports whether a node is effectful for reachability (§10.5.6)
// and migration (§14.3): a routine or fan-out invoking an effectful contract,
// or a composition whose child graph contains one.
func (a *analysis) nodeEffectful(n *nodeView) bool {
	switch n.species {
	case "routine", "map":
		if n.contract != nil {
			return n.contract.Effectful()
		}
		if n.childArt != nil {
			return n.childArt.containsEffectful()
		}
	case "invoke":
		if n.childArt != nil {
			return n.childArt.containsEffectful()
		}
	}
	return false
}

func (art *Artifact) containsEffectful() bool {
	nodes, _ := art.CanonicalSpec["nodes"].([]any)
	for _, nv := range nodes {
		spec := nv.(map[string]any)
		species, _ := spec["species"].(string)
		switch species {
		case "", "routine":
			ref, _ := spec["routine"].(string)
			if c, ok := art.reg.Routines[ref]; ok && c.Effectful() {
				return true
			}
		case "map":
			ref, _ := spec["body"].(string)
			if c, ok := art.reg.Routines[ref]; ok && c.Effectful() {
				return true
			}
			if ga := art.reg.ResolveGraph(ref); ga != nil && ga.containsEffectful() {
				return true
			}
		case "invoke":
			ref, _ := spec["graph"].(string)
			if ga := art.reg.ResolveGraph(ref); ga != nil && ga.containsEffectful() {
				return true
			}
		}
	}
	return false
}

func (a *analysis) checkParams(n *nodeView, d *diags) {
	params, ok := n.spec["params"].(map[string]any)
	if !ok {
		return
	}
	if !n.refKnown || n.contract == nil {
		return // poisoned, or a species with no contract params
	}
	for _, k := range value.SortedKeys(params) {
		decl := n.contract.Input(k)
		addr := "node:" + n.id + "/param:" + k
		if decl == nil || !decl.ConfigEligible {
			d.add("E_PARAM_UNDECLARED", "params key "+quote(k)+" is not a config-eligible contract input", n.id, "", addr, "")
			continue
		}
		if g, bound := n.inputs[k]; bound && len(g.bindings) > 0 {
			d.add("E_PARAM_INPUT_COLLISION", "params key "+quote(k)+" is also bound by a data edge", n.id, "", addr, "")
		}
		if decl.Secret && !isSecretMarker(params[k]) {
			d.add("E_SCHEMA", "secret parameter position must carry the secret marker (§10.7)", n.id, "", addr, "")
		}
	}
}

func isSecretMarker(v any) bool {
	m, ok := v.(map[string]any)
	if !ok || len(m) != 1 {
		return false
	}
	inner, ok := m["$secret"].(map[string]any)
	if !ok || len(inner) != 2 {
		return false
	}
	name, ok1 := inner["name"].(string)
	salt, ok2 := inner["salt"].(string)
	return ok1 && ok2 && name != "" && salt != ""
}

func (a *analysis) checkRequiredInputs(n *nodeView, d *diags) {
	params, _ := n.spec["params"].(map[string]any)
	switch n.species {
	case "routine":
		if !n.refKnown {
			return
		}
		for _, decl := range n.contract.Inputs {
			if decl.Optional {
				continue
			}
			if g, ok := n.inputs[decl.Name]; ok && len(g.bindings) > 0 {
				continue
			}
			if _, ok := params[decl.Name]; ok && decl.ConfigEligible {
				continue
			}
			d.add("E_INPUT_UNBOUND", "required input "+quote(decl.Name)+" has neither binding nor parameter", n.id, "", "node:"+n.id+"/input:"+decl.Name, "")
		}
	case "map":
		// the over input must be bound by an ordinary data edge (§7.2)
		ov := over(n)
		if g, ok := n.inputs[ov]; !ok || len(g.bindings) == 0 {
			d.add("E_INPUT_UNBOUND", "the over input "+quote(ov)+" is unbound", n.id, "", "node:"+n.id+"/input:"+ov, "")
		}
		if !n.refKnown {
			return
		}
		bind, _ := n.spec["bind"].(map[string]any)
		var required []string
		if n.contract != nil {
			for _, decl := range n.contract.Inputs {
				if !decl.Optional {
					required = append(required, decl.Name)
				}
			}
		} else if n.childArt != nil {
			decls := n.childArt.declaredInputs()
			for _, iname := range value.SortedKeys(mapAny(decls)) {
				if opt, _ := decls[iname]["optional"].(bool); !opt {
					required = append(required, iname)
				}
			}
		}
		for _, iname := range required {
			if _, isBind := bind[iname]; isBind {
				continue
			}
			if bind == nil && len(required) == 1 {
				continue // element binds whole to the single required input (D-31)
			}
			if g, ok := n.inputs[iname]; ok && len(g.bindings) > 0 {
				continue // broadcast
			}
			if _, ok := params[iname]; ok {
				continue
			}
			if n.childArt != nil {
				continue // a graph body child input awaits at runtime (§11.13)
			}
			d.add("E_INPUT_UNBOUND", "required body input "+quote(iname)+" is unbound", n.id, "", "node:"+n.id+"/input:"+iname, "")
		}
	case "invoke":
		// exempt: a child input with no parent binding is a runtime await
	}
}

func (a *analysis) checkFanout(n *nodeView, d *diags) {
	ov := over(n)
	bind, hasBind := n.spec["bind"].(map[string]any)
	addr := "node:" + n.id

	var bodyInput func(name string) bool
	var requiredCount int
	if n.contract != nil {
		bodyInput = func(name string) bool { return n.contract.Input(name) != nil }
		for _, decl := range n.contract.Inputs {
			if !decl.Optional {
				requiredCount++
			}
		}
	} else if n.childArt != nil {
		decls := n.childArt.declaredInputs()
		bodyInput = func(name string) bool { _, ok := decls[name]; return ok }
		for _, m := range decls {
			if opt, _ := m["optional"].(bool); !opt {
				requiredCount++
			}
		}
	} else {
		return // poisoned
	}

	if hasBind {
		for _, k := range value.SortedKeys(bind) {
			if !bodyInput(k) {
				d.add("E_FANOUT_BIND", "bind target "+quote(k)+" is not a body input", n.id, "", addr, "")
				continue
			}
			// a bind target must not collide with a broadcast input (§7.2)
			if g, bound := n.inputs[k]; bound && len(g.bindings) > 0 && k != ov {
				d.add("E_FANOUT_BIND", "bind target "+quote(k)+" collides with a broadcast input", n.id, "", addr, "")
			}
		}
	} else {
		if requiredCount != 1 {
			d.add("E_FANOUT_BIND", "bind absent and the body does not declare exactly one required input", n.id, "", addr, "")
		}
	}
}
