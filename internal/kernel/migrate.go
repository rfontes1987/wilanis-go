package kernel

import (
	"sort"
	"strings"
)

// Migrate is §14: fact filtering, never state transformation. It classifies
// every fact of the old execution against compiled graph B by derivation-hash
// comparison over provenance alone, and returns the plan, or a kernel error
// demanding acknowledgment when an invalidated fact's B-node is effectful
// (§14.3).
func Migrate(compiledB *Artifact, state State, options map[string]any) (map[string]any, *KernelError) {
	classifications := map[string]any{}
	outFacts := map[string]any{}
	outProv := map[string]any{}
	var requiresAck []string

	keys := make([]string, 0, len(state.Facts))
	for k := range state.Facts {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		fact := state.Facts[k]
		if isCallerInputKey(k) {
			// always carried — verbatim, never re-keyed, no classification entry
			outFacts[k] = fact
			if p, ok := state.Provenance[k]; ok {
				outProv[k] = p
			}
			continue
		}
		provRec, hasProv := state.Provenance[k].(map[string]any)
		provDeriv := ""
		if hasProv {
			if d, ok := provRec["derivationHash"].(string); ok {
				provDeriv = strings.TrimPrefix(d, "sha256:")
			}
		}

		_, plainPos := resolvePosition(compiledB, k, false)
		renKey, renPos := resolvePosition(compiledB, k, true)

		// 1. carry — B has a node at k's position with derivation equal to d
		if plainPos != nil && hasProv && plainPos.derivation == provDeriv {
			classifications[k] = map[string]any{"class": "carry"}
			outFacts[k] = fact
			outProv[k] = provRec
			continue
		}
		// 2. rename — the re-keyed position has derivation equal to d
		if renPos != nil && renKey != k && hasProv && renPos.derivation == provDeriv {
			classifications[k] = map[string]any{"class": "rename", "to": renKey}
			outFacts[renKey] = fact
			newRec := map[string]any{}
			for pk, pv := range provRec {
				newRec[pk] = pv
			}
			newRec["node"] = renKey
			outProv[renKey] = newRec
			continue
		}
		// 3. invalidate — a node exists at the (possibly re-keyed) position
		// but the derivation differs (or the fact can prove none)
		pos := renPos
		if pos == nil {
			pos = plainPos
		}
		if pos != nil {
			classifications[k] = map[string]any{"class": "invalidate"}
			if pos.effectful {
				requiresAck = append(requiresAck, k)
			}
			continue
		}
		// 4. orphan
		classifications[k] = map[string]any{"class": "orphan"}
	}

	// 5. new — statically known positions of B with no surviving fact
	var newKeys []string
	var enumerate func(art *Artifact, ns string)
	enumerate = func(art *Artifact, ns string) {
		for _, id := range art.anal.nodeOrder {
			key := ns + id
			if _, survived := outFacts[key]; !survived {
				newKeys = append(newKeys, key)
			}
			n := art.anal.nodes[id]
			if n.species == "invoke" && n.childArt != nil {
				enumerate(n.childArt, key+"/")
			}
		}
	}
	enumerate(compiledB, "")
	sort.Strings(newKeys)
	sort.Strings(requiresAck)

	ack, _ := options["acknowledgeEffects"].(bool)
	if len(requiresAck) > 0 && !ack {
		return nil, &KernelError{Code: "kernel/migration_ack", Msg: "invalidated effectful facts require acknowledgment (§14.3)", Keys: requiresAck}
	}

	plan := map[string]any{
		"graphB":          "sha256:" + compiledB.GraphHash,
		"classifications": classifications,
		"new":             strsToAny(newKeys),
		"requiresAck":     strsToAny(requiresAck),
		"state": map[string]any{
			"facts":      outFacts,
			"provenance": outProv,
		},
	}
	return plan, nil
}

func strsToAny(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}

// isCallerInputKey reports whether any segment of the key is `$in`.
func isCallerInputKey(k string) bool {
	for _, seg := range strings.Split(k, "/") {
		if seg == "$in" {
			return true
		}
	}
	return false
}

type position struct {
	derivation string
	effectful  bool
}

// resolvePosition walks a fact key's segments through B (renames applied per
// namespace level when useRenames), returning the possibly re-keyed key and
// the position's derivation and effect class, or nil when B has no node
// there.
func resolvePosition(art *Artifact, key string, useRenames bool) (string, *position) {
	segs := strings.Split(key, "/")
	var outSegs []string
	cur := art
	for i := 0; i < len(segs); i++ {
		seg := segs[i]
		if useRenames {
			if renames, ok := cur.CanonicalSpec["renames"].(map[string]any); ok {
				if to, ok := renames[seg].(string); ok {
					seg = to
				}
			}
		}
		n, ok := cur.anal.nodes[seg]
		if !ok {
			return "", nil
		}
		outSegs = append(outSegs, seg)
		last := i == len(segs)-1
		switch n.species {
		case "invoke":
			if last {
				return strings.Join(outSegs, "/"), &position{
					derivation: cur.anal.derivations[seg],
					effectful:  cur.anal.nodeEffectful(n),
				}
			}
			if n.childArt == nil {
				return "", nil
			}
			cur = n.childArt
		case "map":
			if last {
				return strings.Join(outSegs, "/"), &position{
					derivation: cur.anal.derivations[seg],
					effectful:  cur.anal.nodeEffectful(n),
				}
			}
			// next segment is the dynamic child index {i}
			i++
			idx := segs[i]
			if !indexSegmentOK(idx) {
				return "", nil
			}
			outSegs = append(outSegs, idx)
			if i == len(segs)-1 {
				// the fan-out child position: carries the fan-out node's derivation
				return strings.Join(outSegs, "/"), &position{
					derivation: cur.anal.derivations[seg],
					effectful:  cur.anal.nodeEffectful(n),
				}
			}
			if n.childArt == nil {
				return "", nil // a routine body has no deeper positions
			}
			cur = n.childArt
		default:
			if !last {
				return "", nil
			}
			return strings.Join(outSegs, "/"), &position{
				derivation: cur.anal.derivations[seg],
				effectful:  cur.anal.nodeEffectful(n),
			}
		}
	}
	return "", nil
}

func indexSegmentOK(s string) bool {
	if s == "" {
		return false
	}
	if s == "0" {
		return true
	}
	if s[0] < '1' || s[0] > '9' {
		return false
	}
	for i := 1; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
