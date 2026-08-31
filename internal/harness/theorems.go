package harness

import (
	"fmt"
	"sort"

	"github.com/rfontes1987/wilanis-go/internal/gen"
	"github.com/rfontes1987/wilanis-go/internal/kernel"
	"github.com/rfontes1987/wilanis-go/internal/value"
	"github.com/rfontes1987/wilanis-go/internal/vec"
)

// RunTheorems drives T1–T5 over the seeded generator (§15.7–§15.8). Theorem
// checks return violations (with the seed) rather than asserting.
func RunTheorems(seeds *Seeds) map[string]TheoremResult {
	out := map[string]TheoremResult{}
	runners := map[string]func(seed int64) bool{
		"T1": t1, "T2": t2, "T3": t3, "T5": t5,
	}
	for tid, run := range runners {
		var violations []int64
		for _, seed := range seeds.Theorems[tid] {
			ok := func() (ok bool) {
				defer func() {
					if r := recover(); r != nil {
						ok = false
					}
				}()
				return run(seed)
			}()
			if !ok {
				violations = append(violations, seed)
			}
		}
		res := TheoremResult{Outcome: "pass"}
		if len(violations) > 0 {
			sort.Slice(violations, func(i, j int) bool { return violations[i] < violations[j] })
			res = TheoremResult{Outcome: "fail", Violations: violations}
		}
		out[tid] = res
	}
	out["T4"] = t4(seeds.Theorems["T4"])
	return out
}

func compileSeed(seed int64) *kernel.Artifact {
	spec := gen.Generate(uint64(seed))
	reg := vec.TheoremRegistry()
	art, diags := kernel.Compile(spec, reg, nil)
	if art == nil {
		panic(fmt.Sprintf("generated graph for seed %d failed to compile: %v", seed, diags))
	}
	return art
}

func mustPolicy(doc map[string]any) *kernel.Policy {
	p, err := kernel.ParsePolicy(doc)
	if err != nil {
		panic(err)
	}
	return p
}

// drive runs the embedder loop (Appendix B.1): call, merge committed facts,
// call again; ends on a quiescent report, with a no-progress + call-count
// backstop. Returns the merged facts and the reports in call order.
func drive(art *kernel.Artifact, policyDoc map[string]any, idPrefix string) (map[string]any, []map[string]any) {
	state := kernel.State{Facts: map[string]any{}, Provenance: map[string]any{}}
	var reports []map[string]any
	for call := 0; call < 200; call++ {
		caps := &kernel.Capabilities{Policy: mustPolicy(policyDoc)}
		report, err := kernel.Execute(art, state, caps, map[string]any{
			"executionId": fmt.Sprintf("%s-call-%d", idPrefix, call),
		})
		if err != nil {
			panic(err)
		}
		reports = append(reports, report)
		progressed := false
		facts, _ := report["facts"].(map[string]any)
		for k, v := range facts {
			if _, ok := state.Facts[k]; !ok {
				state.Facts[k] = v
				progressed = true
			}
		}
		prov, _ := report["provenance"].(map[string]any)
		for k, v := range prov {
			state.Provenance[k] = v
		}
		if q, _ := report["quiescent"].(bool); q {
			break
		}
		if !progressed {
			break
		}
	}
	return state.Facts, reports
}

func factsHash(facts map[string]any) string { return value.Hash(any(facts)) }

// t1 — Confluence: quiescence in one call, single-wave iterated, and budgeted
// {default:1, effect:1} iterated settle the same facts.
func t1(seed int64) bool {
	art := compileSeed(seed)
	a, _ := drive(art, map[string]any{"name": "quiescence"}, fmt.Sprintf("t1-q-%d", seed))
	b, _ := drive(art, map[string]any{"name": "single-wave"}, fmt.Sprintf("t1-sw-%d", seed))
	c, _ := drive(art, map[string]any{
		"name":   "budgeted",
		"config": map[string]any{"ceilings": map[string]any{"default": int64(1), "effect": int64(1)}},
	}, fmt.Sprintf("t1-b-%d", seed))
	ha, hb, hc := factsHash(a), factsHash(b), factsHash(c)
	return ha == hb && hb == hc
}

// t2 — Replay idempotence: re-executing with state ∪ report.facts settles
// every fact-committing node as skipped, reproduces every failure and
// cancellation identically, and commits nothing new.
func t2(seed int64) bool {
	art := compileSeed(seed)
	state := kernel.State{Facts: map[string]any{}, Provenance: map[string]any{}}
	run := func(call int) map[string]any {
		caps := &kernel.Capabilities{Policy: mustPolicy(map[string]any{"name": "quiescence"})}
		report, err := kernel.Execute(art, state, caps, map[string]any{
			"executionId": fmt.Sprintf("t2-%d-call-%d", seed, call),
		})
		if err != nil {
			panic(err)
		}
		return report
	}
	r1 := run(1)
	facts1, _ := r1["facts"].(map[string]any)
	prov1, _ := r1["provenance"].(map[string]any)
	for k, v := range facts1 {
		state.Facts[k] = v
	}
	for k, v := range prov1 {
		state.Provenance[k] = v
	}
	r2 := run(2)
	facts2, _ := r2["facts"].(map[string]any)
	if len(facts2) != 0 {
		return false
	}
	rows1 := rowsByKey(r1)
	rows2 := rowsByKey(r2)
	for key, row2 := range rows2 {
		row1 := rows1[key]
		if row1 == nil {
			return false
		}
		o1, _ := row1["outcome"].(string)
		o2, _ := row2["outcome"].(string)
		switch o1 {
		case "executed", "skipped":
			if o2 != "skipped" {
				return false
			}
		case "failed", "cancelled":
			if !value.Equal(any(row1), any(row2)) {
				return false
			}
		default:
			if o1 != o2 {
				return false
			}
		}
	}
	return true
}

func rowsByKey(report map[string]any) map[string]map[string]any {
	out := map[string]map[string]any{}
	rows, _ := report["rows"].([]any)
	for _, rv := range rows {
		row := rv.(map[string]any)
		key, _ := row["key"].(string)
		out[key] = row
	}
	return out
}

// t3 — Monotone settlement: across successive calls, a fact-committing
// classification stays fact-committing (executed replays as skipped), a
// cancellation stays a cancellation, failures fail identically over the
// deterministic corpus, and no fact is removed or changed.
func t3(seed int64) bool {
	art := compileSeed(seed)
	_, reports := drive(art, map[string]any{"name": "single-wave"}, fmt.Sprintf("t3-%d", seed))
	classified := map[string]string{}
	failures := map[string]map[string]any{}
	facts := map[string]any{}
	for _, report := range reports {
		rfacts, _ := report["facts"].(map[string]any)
		for k, v := range rfacts {
			if old, ok := facts[k]; ok && !value.Equal(old, v) {
				return false // a fact changed
			}
			facts[k] = v
		}
		for key, row := range rowsByKey(report) {
			outcome, _ := row["outcome"].(string)
			prev, seen := classified[key]
			switch outcome {
			case "executed", "skipped":
				if seen && prev != "committed" {
					return false
				}
				classified[key] = "committed"
			case "cancelled":
				if seen && prev != "cancelled" {
					return false
				}
				classified[key] = "cancelled"
			case "failed":
				if seen && prev != "failed" {
					return false
				}
				classified[key] = "failed"
				errVal, _ := row["error"].(map[string]any)
				if old, ok := failures[key]; ok && !value.Equal(any(old), any(errVal)) {
					return false // must fail identically
				}
				failures[key] = errVal
			}
		}
	}
	return true
}

// t4 — Policy lawfulness with vacuity detection.
func t4(seedList []int64) TheoremResult {
	var violations []int64
	vacuous := false
	for _, seed := range seedList {
		ok := func() (ok bool) {
			art := compileSeed(seed)
			policy := kernel.UnlawfulPolicy()
			caps := &kernel.Capabilities{Policy: policy}
			_, err := kernel.Execute(art, kernel.State{Facts: map[string]any{}, Provenance: map[string]any{}},
				caps, map[string]any{"executionId": fmt.Sprintf("t4-%d", seed)})
			if policy.Consulted == 0 {
				vacuous = true // proves nothing (§15.7)
				return true
			}
			_, isKernelErr := err.(*kernel.KernelError)
			return isKernelErr
		}()
		if !ok {
			violations = append(violations, seed)
		}
	}
	if len(violations) > 0 {
		sort.Slice(violations, func(i, j int) bool { return violations[i] < violations[j] })
		return TheoremResult{Outcome: "fail", Violations: violations}
	}
	if vacuous {
		return TheoremResult{Outcome: "vacuous"}
	}
	return TheoremResult{Outcome: "pass"}
}

// t5 — Substitution invariance: a warm memo store never changes what a graph
// computes; only the audit trail (cached flags) may differ.
func t5(seed int64) bool {
	art := compileSeed(seed)
	store := map[string]map[string]any{}
	runWith := func(prefix string) map[string]any {
		state := kernel.State{Facts: map[string]any{}, Provenance: map[string]any{}}
		caps := &kernel.Capabilities{
			Policy:  mustPolicy(map[string]any{"name": "quiescence"}),
			HasMemo: true,
			MemoLookup: func(key string) (map[string]any, bool) {
				v, ok := store[key]
				return v, ok
			},
			MemoStore: func(key string, emission map[string]any) { store[key] = emission },
		}
		report, err := kernel.Execute(art, state, caps, map[string]any{"executionId": prefix})
		if err != nil {
			panic(err)
		}
		return report
	}
	cold := runWith(fmt.Sprintf("t5-cold-%d", seed))
	warm := runWith(fmt.Sprintf("t5-warm-%d", seed))
	coldFacts, _ := cold["facts"].(map[string]any)
	warmFacts, _ := warm["facts"].(map[string]any)
	if !value.Equal(any(coldFacts), any(warmFacts)) {
		return false
	}
	// only the audit trail may differ: compare rows with cached stripped
	strip := func(report map[string]any) any {
		rows, _ := report["rows"].([]any)
		out := make([]any, 0, len(rows))
		for _, rv := range rows {
			row := rv.(map[string]any)
			cp := map[string]any{}
			for k, v := range row {
				if k == "cached" {
					continue
				}
				cp[k] = v
			}
			out = append(out, cp)
		}
		return out
	}
	return value.Equal(strip(cold), strip(warm))
}
