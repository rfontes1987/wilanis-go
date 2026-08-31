// Package gen is the seeded deterministic graph generator of SPEC.md §15.8 —
// a cross-language contract: the draw order is normative and two
// implementations given the same seed generate the identical authoring spec.
package gen

import "fmt"

// SplitMix64 is the pinned random source (D-57), all arithmetic modulo 2⁶⁴.
type SplitMix64 struct{ s uint64 }

// New seeds the state directly.
func New(seed uint64) *SplitMix64 { return &SplitMix64{s: seed} }

// Next advances the state.
func (r *SplitMix64) Next() uint64 {
	r.s += 0x9E3779B97F4A7C15
	z := r.s
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
	z = (z ^ (z >> 27)) * 0x94D049BB133111EB
	return z ^ (z >> 31)
}

// Draw is next() mod n (n ≤ 2³², bias accepted and pinned).
func (r *SplitMix64) Draw(n uint64) uint64 { return r.Next() % n }

// Generate produces the authoring spec for one seed, every draw in exactly
// the §15.8 order.
func Generate(seed uint64) map[string]any {
	r := New(seed)
	n := 2 + r.Draw(5) // node count 2–6
	nodes := make([]any, 0, n)
	edges := make([]any, 0)
	for i := uint64(0); i < n; i++ {
		f := r.Draw(10)
		failNode := f == 0 && i > 0
		id := fmt.Sprintf("n%d", i)
		if i == 0 {
			nodes = append(nodes, map[string]any{
				"id":      id,
				"routine": "vec/const@1",
				"params":  map[string]any{"value": int64(r.Draw(1000))},
			})
			continue
		}
		if !failNode {
			k := 1 + r.Draw(minU(i, 3))
			node := map[string]any{"id": id, "routine": "vec/pack@1"}
			nodes = append(nodes, node)
			for j := uint64(0); j < k; j++ {
				p := r.Draw(i)
				edges = append(edges, map[string]any{
					"kind": "data",
					"from": fmt.Sprintf("n%d", p),
					"to":   fmt.Sprintf("%s.a%d", id, j),
				})
			}
		} else {
			node := map[string]any{
				"id":      id,
				"routine": "vec/fail@1",
				"params": map[string]any{
					"code":      "vec/planned",
					"message":   "planned failure",
					"retryable": false,
				},
			}
			nodes = append(nodes, node)
			p := r.Draw(i)
			edges = append(edges, map[string]any{
				"kind": "data",
				"from": fmt.Sprintf("n%d", p),
				"to":   id + ".in",
			})
		}
	}
	exports := make([]any, 0, n)
	for i := uint64(0); i < n; i++ {
		exports = append(exports, map[string]any{
			"name": fmt.Sprintf("out%d", i),
			"from": fmt.Sprintf("n%d", i),
		})
	}
	return map[string]any{
		"name":    fmt.Sprintf("gen%d", seed),
		"nodes":   nodes,
		"edges":   edges,
		"exports": exports,
	}
}

func minU(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}
