package kernel

import (
	"fmt"
	"sort"

	"github.com/rfontes1987/wilanis-go/internal/kernel/clock"
	"github.com/rfontes1987/wilanis-go/internal/value"
)

// runNode runs one selected node (§11.3 step 5), settling it per §11.7–§11.8.
func (e *exec) runNode(n *rnode) error {
	e.emit("node_started", n.key, nil)
	if n.view == nil {
		return e.runFanChild(n)
	}
	switch n.view.species {
	case "routine":
		st := e.nodeState(n) // ready: all satisfied
		_ = st
		inputs := e.inputsEnv(n)
		params, _ := n.view.spec["params"].(map[string]any)
		return e.invokeAndSettle(n, invocation{
			ref:        n.view.ref,
			contract:   n.view.contract,
			inputs:     inputs,
			params:     params,
			retry:      n.view.spec["retry"],
			absorb:     boolOf(n.view.spec["absorb"]),
			species:    "routine",
			provRef:    n.view.ref,
			graphHash:  n.inst.art.GraphHash,
			derivation: n.inst.art.anal.derivations[n.view.id],
			factClass:  n.inst.art.anal.nodeClass[n.view.id],
		})
	case "decision":
		return e.runDecision(n)
	case "map":
		return e.openFanout(n)
	case "invoke":
		e.openChild(n)
		return nil
	}
	return nil
}

// inputsEnv builds the map from satisfied input name to joined value.
func (e *exec) inputsEnv(n *rnode) map[string]any {
	env := map[string]any{}
	for name, g := range n.view.inputs {
		r := e.foldGroup(n.inst, g)
		if r.state == resLive {
			env[name] = r.value
		}
	}
	return env
}

func boolOf(v any) bool {
	b, _ := v.(bool)
	return b
}

type invocation struct {
	ref        string
	contract   *Contract
	inputs     map[string]any
	params     map[string]any
	retry      any
	absorb     bool
	species    string // provenance species
	provRef    string // provenance routine ref ("" for none)
	graphHash  string
	derivation string
	factClass  int
	noTick     bool
}

// invokeAndSettle is the single invocation path (§11.8): memo, attempts,
// bounds, the fact shape rule, absorb, and single-path settlement (§11.7).
func (e *exec) invokeAndSettle(n *rnode, inv invocation) error {
	contract := inv.contract
	pure := !contract.Effectful()

	// memoization eligibility is checked before any key is computed (§13.2)
	var cacheKey string
	memoEligible := pure && !inv.absorb && e.caps.HasMemo
	if memoEligible {
		paramsVal := any(map[string]any{})
		if inv.params != nil {
			paramsVal = any(inv.params)
		}
		cacheKey = value.Hash([]any{inv.ref, value.Hash(any(inv.inputs)), value.Hash(paramsVal)})
		hit, found := e.memoLookup(cacheKey)
		if found {
			fact := e.factFromEmission(contract, hit)
			return e.settleExecuted(n, fact, inv, 0, true, false)
		}
	}

	impl := e.rootRegistry().Impls[inv.ref]
	if impl == nil {
		// an unbound implementation is a misconfiguration, not an outcome
		return &KernelError{Code: "kernel/registry", Msg: "no implementation bound for " + inv.ref}
	}
	maxAttempts := int64(1)
	backoff := ""
	if rm, ok := inv.retry.(map[string]any); ok {
		if ma, ok := rm["maxAttempts"].(int64); ok {
			maxAttempts = ma
		}
		backoff, _ = rm["backoff"].(string)
	}
	class := contract.EffectiveCostClass()

	var attempt int64
	for attempt = 1; ; attempt++ {
		if !inv.noTick {
			e.cost[class]++ // one tick per invocation attempt (§11.14)
		}
		env := map[string]any{}
		for k, v := range inv.inputs {
			env[k] = v
		}
		for k, v := range inv.params {
			env[k] = v
		}
		if !pure { // reserved fields are effectful-only (§8.2)
			env["$key"] = value.Hash([]any{e.execID, n.key})
			env["$attempt"] = attempt
		}
		emission, failure, crashed := safeInvoke(impl, env)
		if crashed {
			failure = &Failure{Code: "kernel/crash", Message: "routine crashed", Retryable: false, HasRetryable: true}
		} else if failure == nil {
			// bounds and shape of the emission (§11.8)
			if conv := checkEmission(contract, emission); conv != nil {
				failure = conv
			}
		}
		if failure == nil {
			fact := e.factFromEmission(contract, emission)
			if memoEligible {
				e.memoStore(cacheKey, emission)
			}
			return e.settleExecuted(n, fact, inv, attempt, false, false)
		}
		if !crashed && failure.Retryable && attempt < maxAttempts {
			e.emit("node_retrying", n.key, map[string]any{"attempt": attempt})
			continue
		}
		// final failure
		if inv.absorb {
			fact := map[string]any{"status": "error", "error": failure.Value()}
			n.failure = failure
			return e.settleExecuted(n, any(fact), inv, attempt, false, true)
		}
		return e.settleFailed(n, failure, attempt, backoff)
	}
}

// checkEmission converts a bounds or shape violation into the pinned typed
// failures (§11.8).
func checkEmission(contract *Contract, emission map[string]any) *Failure {
	if emission == nil {
		return &Failure{Code: "kernel/emission", Message: "emission is not a map over declared ports", Retryable: false, HasRetryable: true}
	}
	for port, v := range emission {
		if contract.Output(port) == nil {
			return &Failure{Code: "kernel/emission", Message: "emission is not a map over declared ports", Retryable: false, HasRetryable: true}
		}
		if reason := value.CheckBounds(v); reason != "" {
			return &Failure{Code: "kernel/bounds", Message: "emission violates a bound (" + reason + ")", Retryable: false, HasRetryable: true}
		}
		if reasonKey := value.CheckBounds(port); reasonKey != "" {
			return &Failure{Code: "kernel/bounds", Message: "emission violates a bound (" + reasonKey + ")", Retryable: false, HasRetryable: true}
		}
	}
	return nil
}

// factFromEmission applies the fact shape rule (§8.4).
func (e *exec) factFromEmission(contract *Contract, emission map[string]any) any {
	if contract.LoneDefaultPort() {
		return emission["value"]
	}
	return any(emission)
}

func safeInvoke(impl Impl, env map[string]any) (emission map[string]any, failure *Failure, crashed bool) {
	defer func() {
		if r := recover(); r != nil {
			emission, failure, crashed = nil, nil, true
		}
	}()
	emission, failure = impl(env)
	return
}

func (e *exec) memoLookup(key string) (map[string]any, bool) {
	var hit map[string]any
	var found bool
	func() {
		defer func() {
			if r := recover(); r != nil {
				hit, found = nil, false // a lookup that throws is a miss (§13.2)
			}
		}()
		hit, found = e.caps.MemoLookup(key)
	}()
	return hit, found
}

func (e *exec) memoStore(key string, emission map[string]any) {
	if e.caps.MemoStore == nil {
		return
	}
	func() {
		defer func() {
			if r := recover(); r != nil {
				e.sinkErrors++ // counted and discarded (§13.2, D-58)
			}
		}()
		e.caps.MemoStore(key, emission)
	}()
}

func (e *exec) rootRegistry() *Registry { return e.root.art.reg }

// settleExecuted is §11.7: seal if sensitive, commit with provenance, mark
// settled, row, event.
func (e *exec) settleExecuted(n *rnode, fact any, inv invocation, attempts int64, cached, absorbed bool) error {
	if inv.factClass == classPii {
		if e.caps.Seal == nil {
			return &KernelError{Code: "kernel/seal", Msg: "sensitive fact reached settlement with no sealer (§13.3)"}
		}
		contentHash := value.Hash(fact) // the kernel hashes the plaintext itself
		func() {
			defer func() { recover() }()
			e.caps.Seal(fact, contentHash, e.subject)
		}()
		fact = map[string]any{"sealed": true, "contentHash": contentHash}
	}
	if old, exists := e.facts[n.key]; exists {
		if !value.Equal(old, fact) {
			return &KernelError{Code: "kernel/overwrite", Msg: "a fact never changes once observed (§5.3)", Keys: []string{n.key}}
		}
	} else {
		e.facts[n.key] = fact
		e.newFacts[n.key] = fact
		prov := map[string]any{
			"node":           n.key,
			"species":        inv.species,
			"graphHash":      "sha256:" + inv.graphHash,
			"derivationHash": "sha256:" + inv.derivation,
			"cached":         cached,
		}
		if inv.provRef != "" {
			prov["routine"] = inv.provRef
		}
		e.newProv[n.key] = prov
	}
	n.settled = true
	n.outcome = "executed"
	n.attempts = attempts
	n.cached = cached
	n.absorbed = absorbed
	e.emit("node_settled", n.key, map[string]any{"outcome": "executed"})
	return nil
}

func (e *exec) settleFailed(n *rnode, f *Failure, attempts int64, backoff string) error {
	n.settled = true
	n.outcome = "failed"
	n.failure = f
	n.attempts = attempts
	n.backoff = backoff
	e.emit("node_settled", n.key, map[string]any{"outcome": "failed"})
	return nil
}

// runDecision is §11.11: first matching rule wins; the default is total.
func (e *exec) runDecision(n *rnode) error {
	env := e.inputsEnv(n)
	rules, _ := n.view.spec["rules"].([]any)
	selected, _ := n.view.spec["default"].(string)
	matched := any(nil) // null on the default path: data, not absence
	for i, rv := range rules {
		rule := rv.(map[string]any)
		when, _ := rule["when"].(map[string]any)
		if EvalPredicate(when, env) {
			selected, _ = rule["route"].(string)
			matched = int64(i)
			break
		}
	}
	fact := map[string]any{"selected": selected, "matched_rule": matched}
	inv := invocation{
		species:    "decision",
		graphHash:  n.inst.art.GraphHash,
		derivation: n.inst.art.anal.derivations[n.view.id],
		factClass:  n.inst.art.anal.nodeClass[n.view.id],
	}
	return e.settleExecuted(n, any(fact), inv, 0, false, false)
}

// openFanout is §11.12.
func (e *exec) openFanout(n *rnode) error {
	overName := over(n.view)
	overRes := e.foldGroup(n.inst, n.view.inputs[overName])
	seq, isSeq := overRes.value.([]any)
	if !isSeq {
		return e.settleFailed(n, &Failure{Code: "kernel/fanout", Message: "the over input is not a sequence", Retryable: false, HasRetryable: true}, 1, "")
	}
	if len(seq) > value.MaxFanoutWidth {
		return e.settleFailed(n, &Failure{Code: "kernel/bounds", Message: "fan-out wider than the bound", Retryable: false, HasRetryable: true}, 1, "")
	}
	inv := e.fanProvenance(n)
	if len(seq) == 0 {
		// the empty sequence settles the node immediately as executed []
		return e.settleExecuted(n, any([]any{}), inv, 0, false, false)
	}
	// broadcasts: every input other than over, unchanged, by name (§7.2)
	broadcasts := map[string]any{}
	for name, g := range n.view.inputs {
		if name == overName {
			continue
		}
		r := e.foldGroup(n.inst, g)
		if r.state == resLive {
			broadcasts[name] = r.value
		}
	}
	bind, hasBind := n.view.spec["bind"].(map[string]any)
	soleRequired := ""
	if !hasBind {
		if n.view.contract != nil {
			for _, decl := range n.view.contract.Inputs {
				if !decl.Optional {
					soleRequired = decl.Name
				}
			}
		} else if n.view.childArt != nil {
			decls := n.view.childArt.declaredInputs()
			for name, m := range decls {
				if opt, _ := m["optional"].(bool); !opt {
					soleRequired = name
				}
			}
		}
	}
	for i, elem := range seq {
		c := &rnode{
			key:       fmt.Sprintf("%s/%d", n.key, i),
			fanParent: n,
			fanIndex:  i,
			bound:     map[string]any{},
		}
		if n.view.childArt != nil {
			c.isGraphChild = true
		}
		for k, v := range broadcasts {
			c.bound[k] = v
		}
		if hasBind {
			for _, k := range value.SortedKeys(bind) {
				path, _ := bind[k].([]any)
				v, ok := resolveFactPath(elem, normalizeBindPath(path))
				if !ok {
					c.bindFail = &Failure{
						Code:      "kernel/bind",
						Message:   fmt.Sprintf("bind path '%s' misses element %d", k, i),
						Retryable: false, HasRetryable: true,
					}
					break
				}
				c.bound[k] = v
			}
		} else if soleRequired != "" {
			c.bound[soleRequired] = elem
		}
		n.fanChildren = append(n.fanChildren, c)
		e.all = append(e.all, c)
	}
	n.opened = true
	return nil
}

func normalizeBindPath(path []any) []any { return path }

func (e *exec) fanProvenance(n *rnode) invocation {
	return invocation{
		species:    "map",
		provRef:    n.view.ref, // the fan-out node records the body reference
		graphHash:  n.inst.art.GraphHash,
		derivation: n.inst.art.anal.derivations[n.view.id],
		factClass:  n.inst.art.anal.nodeClass[n.view.id],
	}
}

// runFanChild runs one fan-out child (§11.12): a routine invocation, or the
// opening of an implicit composition for a graph body.
func (e *exec) runFanChild(c *rnode) error {
	n := c.fanParent
	if c.bindFail != nil {
		// never invoked anything: ticks nothing; its row records attempts 1
		return e.settleFailed(c, c.bindFail, 1, "")
	}
	if c.isGraphChild {
		e.openChild(c)
		return nil
	}
	params, _ := n.view.spec["params"].(map[string]any)
	return e.invokeAndSettle(c, invocation{
		ref:        n.view.ref,
		contract:   n.view.contract,
		inputs:     c.bound,
		params:     params,
		retry:      n.view.spec["retry"], // retry applies per child
		absorb:     false,                // absorb applies at the gather, never per child
		species:    "map-child",
		provRef:    n.view.ref,
		graphHash:  n.inst.art.GraphHash,
		derivation: n.inst.art.anal.derivations[n.view.id],
		factClass:  n.inst.art.anal.fanChildClass[n.view.id],
	})
}

// gather is §11.12: the sequence, in index order, of tagged envelopes.
func (e *exec) gather(n *rnode) error {
	absorb := boolOf(n.view.spec["absorb"])
	inv := e.fanProvenance(n)
	if !absorb {
		lowest := -1
		for _, c := range n.fanChildren {
			if c.outcome == "failed" || c.outcome == "cancelled" {
				lowest = c.fanIndex
				break
			}
		}
		if lowest >= 0 {
			return e.settleFailed(n, &Failure{
				Code: "kernel/fanout_child", Message: fmt.Sprintf("child %d failed", lowest),
				Retryable: false, HasRetryable: true, Detail: map[string]any{"index": int64(lowest)}, HasDetail: true,
			}, 1, "")
		}
	}
	out := make([]any, len(n.fanChildren))
	for i, c := range n.fanChildren {
		switch c.outcome {
		case "executed", "skipped":
			out[i] = map[string]any{"status": "ok", "value": e.facts[c.key]}
		case "failed":
			summary := map[string]any{"code": c.failure.Code, "by": c.key}
			if c.failure.Message != "" {
				summary["message"] = c.failure.Message
			}
			out[i] = map[string]any{"status": "error", "error": summary}
		case "cancelled":
			out[i] = map[string]any{"status": "error", "error": map[string]any{"code": "cancelled", "by": c.key}}
		}
	}
	return e.settleExecuted(n, any(out), inv, 0, false, false)
}

// openChild opens a composition (§11.13) or a graph-body fan-out child.
func (e *exec) openChild(n *rnode) {
	var art *Artifact
	if n.view != nil {
		art = n.view.childArt
	} else {
		art = n.fanParent.view.childArt
	}
	n.child = e.openInstance(art, n.key+"/", n)
	n.opened = true
}

// tryCommitChild auto-commits the child's export map when every export is
// live; a dead export port cancels the node with the propagated cause.
func (e *exec) tryCommitChild(n *rnode) (bool, error) {
	child := n.child
	fact := map[string]any{}
	for _, ex := range child.art.anal.exports {
		var r resolution
		if ex.ep.IsInput {
			r = e.inputRes(child, ex.ep.Input)
		} else {
			r = e.resolveFromProducer(child.nodes[ex.ep.Node], ex.ep.Path)
		}
		switch r.state {
		case resDead:
			n.settled = true
			n.outcome = "cancelled"
			n.cause = r.cause
			e.emit("node_settled", n.key, map[string]any{"outcome": "cancelled"})
			return true, nil
		case resUnresolved:
			return false, nil
		}
		fact[ex.name] = r.value
	}
	var inv invocation
	if n.view != nil {
		inv = invocation{
			species:    "invoke",
			graphHash:  n.inst.art.GraphHash,
			derivation: n.inst.art.anal.derivations[n.view.id],
			factClass:  n.inst.art.anal.nodeClass[n.view.id],
		}
	} else {
		fp := n.fanParent
		factClass := 0
		for _, rank := range child.art.exportClasses {
			if rank > factClass {
				factClass = rank
			}
		}
		inv = invocation{
			species:    "map-child",
			graphHash:  fp.inst.art.GraphHash,
			derivation: fp.inst.art.anal.derivations[fp.view.id],
			factClass:  factClass,
		}
	}
	if err := e.settleExecuted(n, any(fact), inv, 0, false, false); err != nil {
		return true, err
	}
	return true, nil
}

// awaitingOf names what a blocked node awaits (§11.16), deduplicated and
// sorted by (kind, key) — input sorts before node.
func (e *exec) awaitingOf(n *rnode) []map[string]any {
	var list []map[string]any
	switch {
	case n.opened && n.fanChildren != nil:
		for _, c := range n.fanChildren {
			if !c.settled {
				list = append(list, map[string]any{"kind": "node", "key": c.key})
			}
		}
	case n.opened && n.child != nil:
		// blocked awaiting its child's unsettled nodes (§11.13)
		for _, id := range n.child.art.anal.nodeOrder {
			c := n.child.nodes[id]
			if !c.settled {
				list = append(list, map[string]any{"kind": "node", "key": c.key})
			}
		}
	case n.view != nil:
		list = e.nodeState(n).await
	}
	// dedup and sort
	seen := map[string]bool{}
	var out []map[string]any
	for _, a := range list {
		k, _ := a["kind"].(string)
		key, _ := a["key"].(string)
		sig := k + "\x00" + key
		if seen[sig] {
			continue
		}
		seen[sig] = true
		out = append(out, a)
	}
	sort.SliceStable(out, func(i, j int) bool {
		ki, _ := out[i]["kind"].(string)
		kj, _ := out[j]["kind"].(string)
		if ki != kj {
			return ki < kj // "input" < "node" in UTF-8 bytes
		}
		ai, _ := out[i]["key"].(string)
		aj, _ := out[j]["key"].(string)
		return ai < aj
	})
	return out
}

// buildReport assembles the canonical audit record (§11.16).
func (e *exec) buildReport(art *Artifact, quiescent bool, yieldReason any, start clock.Token) map[string]any {
	rows := make([]any, 0, len(e.all))
	for _, n := range e.reportOrder() {
		row := map[string]any{"key": n.key}
		outcome := n.outcome
		if !n.settled {
			outcome = n.classification
		}
		row["outcome"] = outcome
		switch outcome {
		case "executed":
			if n.attempts > 1 {
				row["attempts"] = n.attempts
			}
			if n.cached {
				row["cached"] = true
			}
			if n.absorbed {
				row["absorbed"] = true
			}
			if e.detail == "full" {
				row["output"] = e.facts[n.key]
			}
		case "failed":
			row["attempts"] = n.attempts
			row["error"] = n.failure.Value()
			if n.backoff != "" {
				row["backoff"] = n.backoff
			}
		case "cancelled":
			row["cause"] = n.cause
		case "blocked":
			row["awaiting"] = anySlice(n.awaiting)
		case "yielded", "skipped":
		}
		rows = append(rows, row)
	}

	entrySettled := make([]any, 0, len(e.entry))
	keys := make([]string, 0, len(e.entry))
	for k := range e.entry {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		entrySettled = append(entrySettled, k)
	}

	used := map[string]any{}
	for class, ticks := range e.cost {
		if ticks > 0 {
			used[class] = ticks
		}
	}
	ceiling := map[string]any{}
	for class, c := range e.caps.Policy.Ceilings {
		ceiling[class] = c
	}

	name, _ := art.CanonicalSpec["name"].(string)
	policy := map[string]any{"name": e.caps.Policy.Name}
	if e.caps.Policy.HasConfig {
		policy["config"] = e.caps.Policy.Config
	}
	report := map[string]any{
		"executionId":  e.execID,
		"graph":        map[string]any{"name": name, "hash": "sha256:" + art.GraphHash},
		"policy":       policy,
		"registry":     e.rootRegistry().Identity,
		"detail":       e.detail,
		"entrySettled": entrySettled,
		"rows":         rows,
		"facts":        e.newFacts,
		"provenance":   e.newProv,
		"quiescent":    quiescent,
		"yieldReason":  yieldReason,
		"sinkErrors":   e.sinkErrors,
		"cost":         map[string]any{"used": used, "ceiling": ceiling},
	}
	if e.detail == "full" {
		report["elapsed"] = clock.ElapsedMillis(start)
	}
	return report
}

func anySlice(in []map[string]any) []any {
	out := make([]any, len(in))
	for i, m := range in {
		out[i] = m
	}
	return out
}
