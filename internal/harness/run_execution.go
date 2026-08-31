package harness

import (
	"fmt"
	"github.com/rfontes1987/wilanis-go/internal/kernel"
	"github.com/rfontes1987/wilanis-go/internal/value"
	"github.com/rfontes1987/wilanis-go/internal/vec"
)

// runExecutionShaped compiles the vector's canonical spec against its
// registry, executes with the vector's state, capabilities, and options, and
// compares the report by value equality after zeroing elapsed (§15.2,
// CERTIFICATION.md §3.2).
func runExecutionShaped(doc map[string]any, optionsKey string) string {
	report, execErr := executeForDebug(doc, optionsKey)
	if execErr != nil {
		return "fail"
	}
	expect, _ := doc["expect"].(map[string]any)
	want := expect["report"]
	if value.Equal(zeroElapsed(any(report)), zeroElapsed(want)) {
		return "pass"
	}
	return "fail"
}

// executeForDebug is the compile+execute half, shared with the debug dumper.
func executeForDebug(doc map[string]any, optionsKey string) (map[string]any, error) {
	spec := doc["spec"]
	registryDoc, _ := doc["registry"].(map[string]any)
	reg := vec.Registry(registryDoc)
	art, diags := kernel.Compile(spec, reg, nil)
	if art == nil {
		return nil, fmt.Errorf("vector spec failed to compile: %v", diags)
	}
	stateDoc, _ := doc["state"].(map[string]any)
	state := parseState(stateDoc)
	capsDoc, _ := doc["capabilities"].(map[string]any)
	caps, err := ParseCapabilities(capsDoc)
	if err != nil {
		return nil, err
	}
	options, _ := doc[optionsKey].(map[string]any)
	return kernel.Execute(art, state, caps, options)
}

func parseState(doc map[string]any) kernel.State {
	st := kernel.State{Facts: map[string]any{}, Provenance: map[string]any{}}
	if doc == nil {
		return st
	}
	if facts, ok := doc["facts"].(map[string]any); ok {
		st.Facts = facts
	}
	if prov, ok := doc["provenance"].(map[string]any); ok {
		st.Provenance = prov
	}
	return st
}

// ParseCapabilities builds the §13 capability set from a vector's
// capabilities value: a §12.4 policy, scripted memo entries, and `seal: true`
// meaning a sealer is configured.
func ParseCapabilities(doc map[string]any) (*kernel.Capabilities, error) {
	caps := &kernel.Capabilities{}
	policyDoc, _ := doc["policy"].(map[string]any)
	if policyDoc == nil {
		policyDoc = map[string]any{"name": "quiescence"}
	}
	p, err := kernel.ParsePolicy(policyDoc)
	if err != nil {
		return nil, err
	}
	caps.Policy = p
	if memoDoc, ok := doc["memo"].(map[string]any); ok {
		entries, _ := memoDoc["entries"].(map[string]any)
		caps.HasMemo = true
		caps.MemoLookup = func(key string) (map[string]any, bool) {
			v, ok := entries[key]
			if !ok {
				return nil, false
			}
			m, isMap := v.(map[string]any)
			if !isMap {
				return nil, false
			}
			return m, true
		}
		caps.MemoStore = func(key string, emission map[string]any) {}
	}
	if sealFlag, ok := doc["seal"].(bool); ok && sealFlag {
		caps.Seal = func(plaintext any, contentHash string, subject any) {}
	}
	return caps, nil
}

// zeroElapsed replaces every `elapsed` field in a report with 0 (§15.2).
func zeroElapsed(v any) any {
	m, ok := v.(map[string]any)
	if !ok {
		return v
	}
	if _, has := m["elapsed"]; has {
		out := make(map[string]any, len(m))
		for k, val := range m {
			out[k] = val
		}
		out["elapsed"] = int64(0)
		return out
	}
	return m
}
