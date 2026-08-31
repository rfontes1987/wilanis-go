package kernel

import (
	"fmt"
	"sort"
)

// PolicyEntry is one ready-set entry offered to the policy: the namespaced
// key plus the node's declared cost class — static contract metadata, never
// data (§12.1).
type PolicyEntry struct {
	Key       string
	CostClass string
}

// PolicyContext is everything a policy may see (§12.1).
type PolicyContext struct {
	Ready   []PolicyEntry
	Wave    int64
	Used    map[string]int64
	Ceiling map[string]int64
}

// Policy is the schedule capability: a pure function of its context returning
// a non-empty selection or a yield with a reason.
type Policy struct {
	Name      string
	Config    any
	HasConfig bool
	decide    func(ctx PolicyContext) (selection map[string]bool, yield bool, reason string)
	// Ceilings are the policy's declared abstract-cost ceilings, echoed in
	// the report (§11.16); empty when none.
	Ceilings map[string]int64
	// Consulted counts policy consultations — harness-only visibility for the
	// T4 vacuity check (§15.7); the kernel writes it, never reads it.
	Consulted int64
}

// ParsePolicy builds a stock policy (§12.4) from its {name, config?} value.
func ParsePolicy(doc map[string]any) (*Policy, error) {
	name, _ := doc["name"].(string)
	config, hasConfig := doc["config"]
	p := &Policy{Name: name, Config: config, HasConfig: hasConfig, Ceilings: map[string]int64{}}
	switch name {
	case "quiescence":
		p.decide = func(ctx PolicyContext) (map[string]bool, bool, string) {
			return selectAll(ctx.Ready), false, ""
		}
	case "single-wave":
		p.decide = func(ctx PolicyContext) (map[string]bool, bool, string) {
			if ctx.Wave == 0 {
				return selectAll(ctx.Ready), false, ""
			}
			return nil, true, "single-wave"
		}
	case "defer-costly":
		var order []string
		if cm, ok := config.(map[string]any); ok {
			if ov, ok := cm["order"].([]any); ok {
				for _, c := range ov {
					if s, ok := c.(string); ok {
						order = append(order, s)
					}
				}
			}
		}
		p.decide = func(ctx PolicyContext) (map[string]bool, bool, string) {
			rank := func(class string) (int, string) {
				for i, c := range order {
					if c == class {
						return i, ""
					}
				}
				return len(order), class // unlisted rank after listed, by class name bytes
			}
			bestSet := false
			var bestI int
			var bestS string
			for _, e := range ctx.Ready {
				i, s := rank(e.CostClass)
				if !bestSet || i < bestI || (i == bestI && s < bestS) {
					bestSet, bestI, bestS = true, i, s
				}
			}
			sel := map[string]bool{}
			for _, e := range ctx.Ready {
				i, s := rank(e.CostClass)
				if i == bestI && s == bestS {
					sel[e.Key] = true
				}
			}
			return sel, false, "" // never yields on a non-empty ready set
		}
	case "budgeted":
		ceilings := map[string]int64{}
		if cm, ok := config.(map[string]any); ok {
			if cv, ok := cm["ceilings"].(map[string]any); ok {
				for class, nv := range cv {
					if n, ok := nv.(int64); ok {
						ceilings[class] = n
					}
				}
			}
		}
		p.Ceilings = ceilings
		p.decide = func(ctx PolicyContext) (map[string]bool, bool, string) {
			sel := map[string]bool{}
			selected := map[string]int64{}
			for _, e := range ctx.Ready {
				ceiling, listed := ceilings[e.CostClass]
				if !listed {
					sel[e.Key] = true
					continue
				}
				if ctx.Used[e.CostClass]+selected[e.CostClass]+1 <= ceiling {
					sel[e.Key] = true
					selected[e.CostClass]++
				}
			}
			if len(sel) == 0 {
				return nil, true, "budget"
			}
			return sel, false, ""
		}
	case "script":
		var waves []any
		if cm, ok := config.(map[string]any); ok {
			waves, _ = cm["waves"].([]any)
		}
		p.decide = func(ctx PolicyContext) (map[string]bool, bool, string) {
			if ctx.Wave >= int64(len(waves)) {
				return nil, true, "script-exhausted"
			}
			switch entry := waves[ctx.Wave].(type) {
			case string:
				if entry == "all" {
					return selectAll(ctx.Ready), false, ""
				}
			case []any:
				sel := map[string]bool{}
				for _, kv := range entry {
					if k, ok := kv.(string); ok {
						sel[k] = true
					}
				}
				return sel, false, ""
			case map[string]any:
				if reason, ok := entry["yield"].(string); ok {
					return nil, true, reason
				}
			}
			return nil, true, "script-exhausted"
		}
	default:
		return nil, fmt.Errorf("unknown policy %q", name)
	}
	return p, nil
}

func selectAll(ready []PolicyEntry) map[string]bool {
	sel := make(map[string]bool, len(ready))
	for _, e := range ready {
		sel[e.Key] = true
	}
	return sel
}

// UnlawfulPolicy builds a policy that selects a key outside the offered ready
// set — used by the T4 theorem harness only.
func UnlawfulPolicy() *Policy {
	p := &Policy{Name: "unlawful", Ceilings: map[string]int64{}}
	p.decide = func(ctx PolicyContext) (map[string]bool, bool, string) {
		keys := make([]string, 0, len(ctx.Ready))
		for _, e := range ctx.Ready {
			keys = append(keys, e.Key)
		}
		sort.Strings(keys)
		return map[string]bool{"not-a-ready-key-zzz": true}, false, ""
	}
	return p
}
