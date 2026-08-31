package kernel

import (
	"fmt"
	"sort"
	"strconv"

	"github.com/rfontes1987/wilanis-go/internal/kernel/clock"
	"github.com/rfontes1987/wilanis-go/internal/value"
)

// State is the append-only map from fact key to fact plus its provenance
// side-map (§5.3).
type State struct {
	Facts      map[string]any
	Provenance map[string]any
}

// Capabilities is the closed §13 taxonomy: schedule, observe, substitute,
// seal.
type Capabilities struct {
	Policy *Policy
	// Observe receives events synchronously; exceptions are caught, counted
	// in sinkErrors, and discarded (§11.15).
	Observe func(event map[string]any)
	// Memo is the substitute capability (§13.2); nil means none configured.
	MemoLookup func(cacheKey string) (map[string]any, bool)
	MemoStore  func(cacheKey string, emission map[string]any)
	HasMemo    bool
	// Seal encrypts and stores a sensitive value's bytes (§13.3); the kernel
	// computed contentHash. nil means no sealer configured.
	Seal func(plaintext any, contentHash string, subject any)
}

// KernelError is a violated kernel invariant (§11.18): the call aborts
// exceptionally, committing nothing.
type KernelError struct {
	Code string
	Msg  string
	Keys []string
}

func (e *KernelError) Error() string { return e.Code + ": " + e.Msg }

// rnode is one runtime node: a graph node of the root or of an open child,
// or a fan-out child.
type rnode struct {
	key  string
	inst *instance // owning graph instance; nil for fan-out children
	view *nodeView // nil for fan-out children

	// fan-out child fields
	fanParent    *rnode
	fanIndex     int
	bound        map[string]any // resolved body inputs (bind + broadcasts)
	bindFail     *Failure       // kernel/bind detected at open
	isGraphChild bool

	// open child structures
	opened      bool
	child       *instance
	fanChildren []*rnode

	// settlement
	settled  bool
	outcome  string // executed | skipped | failed | cancelled
	attempts int64
	cached   bool
	absorbed bool
	failure  *Failure
	backoff  string
	cause    map[string]any

	// classification at return
	classification string // blocked | yielded
	awaiting       []map[string]any
}

// instance is one open graph: the root, an invoke child, or a graph-body
// fan-out child.
type instance struct {
	art    *Artifact
	ns     string // "" or "<node>/"... with trailing slash
	nodes  map[string]*rnode
	parent *rnode // nil for the root
}

type exec struct {
	caps       *Capabilities
	execID     string
	detail     string
	entry      map[string]bool
	facts      map[string]any
	newFacts   map[string]any
	newProv    map[string]any
	cost       map[string]int64
	sinkErrors int64
	root       *instance
	all        []*rnode
	subject    any
	eventSeq   map[string]int64
}

type resolution struct {
	state int // 0 unresolved, 1 live, 2 dead
	value any
	cause map[string]any
	await []map[string]any
	// death summary source (for any-join tagged arrays)
	summary map[string]any
}

const (
	resUnresolved = 0
	resLive       = 1
	resDead       = 2
)

// Execute is the kernel's second operation (§11).
func Execute(art *Artifact, state State, caps *Capabilities, options map[string]any) (map[string]any, error) {
	start := clock.Start()

	execID, _ := options["executionId"].(string)
	if execID == "" {
		return nil, &KernelError{Code: "kernel/options", Msg: "executionId is required and non-empty (§11.1)"}
	}
	detail, _ := options["detail"].(string)
	if detail == "" {
		detail = "full"
	}
	if caps == nil || caps.Policy == nil {
		p, _ := ParsePolicy(map[string]any{"name": "quiescence"})
		if caps == nil {
			caps = &Capabilities{}
		}
		caps.Policy = p
	}

	// Entry preconditions (§11.2) — kernel errors before any node runs.
	for key, fact := range state.Facts {
		if reason := value.CheckBounds(fact); reason != "" {
			return nil, &KernelError{Code: "kernel/bounds", Msg: "state fact violates a bound (" + reason + ")", Keys: []string{key}}
		}
	}
	e := &exec{
		caps:     caps,
		execID:   execID,
		detail:   detail,
		entry:    map[string]bool{},
		facts:    map[string]any{},
		newFacts: map[string]any{},
		newProv:  map[string]any{},
		cost:     map[string]int64{},
		eventSeq: map[string]int64{},
	}
	for k, v := range state.Facts {
		e.entry[k] = true
		e.facts[k] = v
	}
	if art.hasPii {
		if caps.Seal == nil {
			return nil, &KernelError{Code: "kernel/seal", Msg: "graph carries sensitive facts but no seal capability is configured (§11.2)"}
		}
		subjectKey := "$in/" + art.subjectInput
		sub, ok := e.facts[subjectKey]
		if !ok {
			return nil, &KernelError{Code: "kernel/seal", Msg: "subject input fact absent at entry (§11.2)", Keys: []string{subjectKey}}
		}
		e.subject = sub
	}

	e.root = e.openInstance(art, "", nil)
	e.emit("execution_started", "", nil)

	quiescent := false
	yieldReason := any(nil)
	var wave int64
	for {
		if err := e.fixpoint(); err != nil {
			return nil, err
		}
		ready := e.readyNodes()
		if len(ready) == 0 {
			quiescent = true
			break
		}
		e.emit("wave_started", "", map[string]any{"wave": wave})
		entries := make([]PolicyEntry, len(ready))
		for i, n := range ready {
			entries[i] = PolicyEntry{Key: n.key, CostClass: e.costClass(n)}
		}
		e.caps.Policy.Consulted++
		sel, yield, reason := e.caps.Policy.decide(PolicyContext{
			Ready: entries, Wave: wave, Used: copyCounts(e.cost), Ceiling: e.caps.Policy.Ceilings,
		})
		if yield {
			for _, n := range ready {
				n.classification = "yielded"
			}
			yieldReason = reason
			break
		}
		readyKeys := map[string]bool{}
		for _, n := range ready {
			readyKeys[n.key] = true
		}
		if len(sel) == 0 {
			return nil, &KernelError{Code: "kernel/policy", Msg: "policy returned an empty selection without yielding (§12.1)"}
		}
		for k := range sel {
			if !readyKeys[k] {
				return nil, &KernelError{Code: "kernel/policy", Msg: "policy selected a non-ready key (§12.1)", Keys: []string{k}}
			}
		}
		for _, n := range ready {
			if sel[n.key] {
				if err := e.runNode(n); err != nil {
					return nil, err
				}
			}
		}
		wave++
	}

	// classify the unsettled (§11.6)
	for _, n := range e.all {
		if n.settled || n.classification == "yielded" {
			continue
		}
		n.classification = "blocked"
		n.awaiting = e.awaitingOf(n)
	}
	e.emit("execution_ended", "", nil)

	return e.buildReport(art, quiescent, yieldReason, start), nil
}

func copyCounts(m map[string]int64) map[string]int64 {
	out := make(map[string]int64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// openInstance materializes a graph's nodes as runtime nodes.
func (e *exec) openInstance(art *Artifact, ns string, parent *rnode) *instance {
	inst := &instance{art: art, ns: ns, nodes: map[string]*rnode{}, parent: parent}
	for _, id := range art.anal.nodeOrder {
		n := &rnode{key: ns + id, inst: inst, view: art.anal.nodes[id]}
		inst.nodes[id] = n
		e.all = append(e.all, n)
	}
	return inst
}

// costClass is the ready entry's declared cost class (§12.1).
func (e *exec) costClass(n *rnode) string {
	if n.view == nil { // fan-out child
		fp := n.fanParent
		if n.isGraphChild {
			return "none"
		}
		return fp.view.contract.EffectiveCostClass()
	}
	switch n.view.species {
	case "routine":
		return n.view.contract.EffectiveCostClass()
	}
	return "none" // decision, map, invoke tick no cost (§11.14)
}

// fixpoint is §11.3 step 1: readiness and deadness recomputed to fixpoint,
// settling skips, cancellations, and auto-commits as revealed.
func (e *exec) fixpoint() error {
	for {
		changed := false
		for i := 0; i < len(e.all); i++ {
			n := e.all[i]
			if n.settled {
				continue
			}
			// the replay rule: a fact already present at entry settles skipped
			if e.entry[n.key] {
				n.settled = true
				n.outcome = "skipped"
				e.emit("node_settled", n.key, map[string]any{"outcome": "skipped"})
				changed = true
				continue
			}
			// gather (§11.12): auto-commit when every child settled
			if n.opened && n.fanChildren != nil {
				all := true
				for _, c := range n.fanChildren {
					if !c.settled {
						all = false
						break
					}
				}
				if all {
					if err := e.gather(n); err != nil {
						return err
					}
					changed = true
				}
				continue
			}
			// export projection (§11.13): auto-commit when every export live
			if n.opened && n.child != nil {
				done, err := e.tryCommitChild(n)
				if err != nil {
					return err
				}
				if done {
					changed = true
				}
				continue
			}
			// deadness
			if n.view == nil {
				continue // fan-out routine children have no unresolved deps
			}
			st := e.nodeState(n)
			if st.state == resDead {
				n.settled = true
				n.outcome = "cancelled"
				n.cause = st.cause
				e.emit("node_settled", n.key, map[string]any{"outcome": "cancelled"})
				changed = true
			}
		}
		if !changed {
			return nil
		}
	}
}

// nodeState folds a node's input groups and order requirements: dead with the
// first dead cause in (input-name, binding-index, order-edge) canonical
// order; ready when everything is satisfied; else unresolved with awaits.
func (e *exec) nodeState(n *rnode) resolution {
	var awaits []map[string]any
	ready := true
	names := make([]string, 0, len(n.view.inputs))
	for name := range n.view.inputs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		g := n.view.inputs[name]
		r := e.foldGroup(n.inst, g)
		switch r.state {
		case resDead:
			return resolution{state: resDead, cause: r.cause}
		case resUnresolved:
			ready = false
			awaits = append(awaits, r.await...)
		}
	}
	for _, oe := range n.view.orderEdges {
		r := e.resolveOrder(n.inst, oe)
		switch r.state {
		case resDead:
			return resolution{state: resDead, cause: r.cause}
		case resUnresolved:
			ready = false
			awaits = append(awaits, r.await...)
		}
	}
	if ready {
		return resolution{state: resLive}
	}
	return resolution{state: resUnresolved, await: awaits}
}

// foldGroup folds one input group under its join mode (§11.5).
func (e *exec) foldGroup(inst *instance, g *groupView) resolution {
	rs := make([]resolution, len(g.bindings))
	for i, b := range g.bindings {
		rs[i] = e.resolveBinding(inst, b)
	}
	if g.mode == "any" {
		allResolved := true
		anyLive := false
		var awaits []map[string]any
		for _, r := range rs {
			if r.state == resUnresolved {
				allResolved = false
				awaits = append(awaits, r.await...)
			}
			if r.state == resLive {
				anyLive = true
			}
		}
		if !allResolved {
			return resolution{state: resUnresolved, await: awaits}
		}
		if !anyLive {
			return resolution{state: resDead, cause: rs[0].cause}
		}
		// the tagged array, in binding order (§11.5)
		out := make([]any, len(rs))
		for i, r := range rs {
			if r.state == resLive {
				out[i] = map[string]any{"status": "ok", "value": r.value}
			} else {
				out[i] = map[string]any{"status": "error", "error": r.summary}
			}
		}
		return resolution{state: resLive, value: out}
	}
	// ALL
	var awaits []map[string]any
	for _, r := range rs {
		if r.state == resDead {
			return resolution{state: resDead, cause: r.cause}
		}
		if r.state == resUnresolved {
			awaits = append(awaits, r.await...)
		}
	}
	if len(awaits) > 0 {
		return resolution{state: resUnresolved, await: awaits}
	}
	if len(rs) == 1 {
		return resolution{state: resLive, value: rs[0].value}
	}
	out := make([]any, len(rs))
	for i, r := range rs {
		out[i] = r.value
	}
	return resolution{state: resLive, value: out}
}

// resolveBinding is the §11.4 trichotomy for one data binding.
func (e *exec) resolveBinding(inst *instance, b *bindingView) resolution {
	if b.isInput {
		return e.inputRes(inst, b.inputName)
	}
	producer := inst.nodes[b.producer]
	return e.resolveFromProducer(producer, b.path)
}

func (e *exec) resolveFromProducer(producer *rnode, path []any) resolution {
	switch producer.outcome {
	case "executed", "skipped":
		fact := e.facts[producer.key]
		v, ok := resolveFactPath(fact, path)
		if !ok {
			return resolution{
				state:   resDead,
				cause:   map[string]any{"kind": "port_absent", "node": producer.key, "path": pathValue(path)},
				summary: map[string]any{"code": "port_absent", "by": producer.key},
			}
		}
		return resolution{state: resLive, value: v}
	case "failed":
		summary := map[string]any{"code": producer.failure.Code, "by": producer.key}
		if producer.failure.Message != "" {
			summary["message"] = producer.failure.Message
		}
		return resolution{
			state:   resDead,
			cause:   map[string]any{"kind": "failed", "node": producer.key},
			summary: summary,
		}
	case "cancelled":
		// the producer's cause propagates, so the cascade names the root
		return resolution{
			state:   resDead,
			cause:   producer.cause,
			summary: map[string]any{"code": "cancelled", "by": producer.key},
		}
	}
	return resolution{state: resUnresolved, await: []map[string]any{{"kind": "node", "key": producer.key}}}
}

// inputRes resolves a graph-input reference within an instance (§11.13).
func (e *exec) inputRes(inst *instance, name string) resolution {
	if inst.parent != nil {
		p := inst.parent
		if p.view == nil || p.isGraphChild {
			// graph-body fan-out child: bind targets and broadcasts arrive bound
			if v, ok := p.bound[name]; ok {
				return resolution{state: resLive, value: v}
			}
		} else {
			if g, ok := p.view.inputs[name]; ok && len(g.bindings) > 0 {
				return e.foldGroup(p.inst, g)
			}
		}
	}
	key := inst.ns + "$in/" + name
	if v, ok := e.facts[key]; ok {
		return resolution{state: resLive, value: v}
	}
	await := map[string]any{"kind": "input", "name": name, "key": key}
	if decl, ok := inst.art.anal.declaredInputs[name]; ok {
		if shape, ok := decl["shape"]; ok {
			await["shape"] = deepCopy(shape)
		}
		if opt, ok := decl["optional"]; ok {
			await["optional"] = opt
		}
	}
	return resolution{state: resUnresolved, await: []map[string]any{await}}
}

// resolveOrder resolves one order requirement (§11.4).
func (e *exec) resolveOrder(inst *instance, oe *orderEdgeView) resolution {
	producer := inst.nodes[oe.producer]
	switch producer.outcome {
	case "executed", "skipped":
		if len(oe.path) == 2 { // route port: satisfied iff that route selected
			label, _ := oe.path[1].(string)
			fact, _ := e.facts[producer.key].(map[string]any)
			selected, _ := fact["selected"].(string)
			if selected == label {
				return resolution{state: resLive}
			}
			return resolution{state: resDead, cause: map[string]any{
				"kind": "routed", "decision": producer.key, "selected": selected, "route": label,
			}}
		}
		return resolution{state: resLive}
	case "failed":
		return resolution{state: resDead, cause: map[string]any{"kind": "failed", "node": producer.key}}
	case "cancelled":
		return resolution{state: resDead, cause: producer.cause}
	}
	return resolution{state: resUnresolved, await: []map[string]any{{"kind": "node", "key": producer.key}}}
}

// resolveFactPath resolves a port path into a committed fact (§11.4).
func resolveFactPath(fact any, path []any) (any, bool) {
	cur := fact
	for _, seg := range path {
		switch s := seg.(type) {
		case string:
			m, ok := cur.(map[string]any)
			if !ok {
				return nil, false
			}
			cur, ok = m[s]
			if !ok {
				return nil, false
			}
		case int64:
			sq, ok := cur.([]any)
			if !ok || s < 0 || int(s) >= len(sq) {
				return nil, false
			}
			cur = sq[s]
		default:
			return nil, false
		}
	}
	return cur, true
}

// isReady reports §11.4 readiness.
func (e *exec) isReady(n *rnode) bool {
	if n.settled || n.opened {
		return false
	}
	if n.view == nil {
		return true // fan-out children arrive fully bound
	}
	return e.nodeState(n).state == resLive
}

// readyNodes returns the ready set in the one global order (§11.16.1).
func (e *exec) readyNodes() []*rnode {
	var out []*rnode
	for _, n := range e.reportOrder() {
		if e.isReady(n) {
			out = append(out, n)
		}
	}
	return out
}

// reportOrder is the deterministic topological index order of §11.16.1:
// per graph, repeatedly the id-smallest node whose in-graph edge sources are
// all emitted; children spliced depth-first after their open node.
func (e *exec) reportOrder() []*rnode {
	var out []*rnode
	var emitInstance func(inst *instance)
	emitInstance = func(inst *instance) {
		anal := inst.art.anal
		emitted := map[string]bool{}
		for len(out) >= 0 {
			best := ""
			for _, id := range anal.nodeOrder {
				if emitted[id] {
					continue
				}
				n := anal.nodes[id]
				ok := true
				for _, name := range n.inputOrder {
					for _, b := range n.inputs[name].bindings {
						if !b.isInput && b.srcKnown && !emitted[b.producer] {
							ok = false
						}
					}
				}
				for _, oe := range n.orderEdges {
					if oe.srcKnown && !emitted[oe.producer] {
						ok = false
					}
				}
				if ok && (best == "" || id < best) {
					best = id
				}
			}
			if best == "" {
				break
			}
			emitted[best] = true
			rn := inst.nodes[best]
			out = append(out, rn)
			if rn.opened && rn.fanChildren != nil {
				for _, c := range rn.fanChildren {
					out = append(out, c)
					if c.opened && c.child != nil {
						emitInstance(c.child)
					}
				}
			} else if rn.opened && rn.child != nil {
				emitInstance(rn.child)
			}
		}
	}
	emitInstance(e.root)
	return out
}

func (e *exec) emit(kind, key string, extra map[string]any) {
	if e.caps.Observe == nil {
		return
	}
	event := map[string]any{"kind": kind, "executionId": e.execID}
	if key != "" {
		event["key"] = key
		e.eventSeq[key]++
		event["seq"] = e.eventSeq[key]
	}
	for k, v := range extra {
		event[k] = v
	}
	func() {
		defer func() {
			if r := recover(); r != nil {
				e.sinkErrors++
			}
		}()
		e.caps.Observe(event)
	}()
}

func itoa(i int) string { return strconv.Itoa(i) }

var _ = fmt.Sprintf
