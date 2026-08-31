package harness

import (
	"github.com/rfontes1987/wilanis-go/internal/kernel"
	"github.com/rfontes1987/wilanis-go/internal/value"
	"github.com/rfontes1987/wilanis-go/internal/vec"
)

// runMigrationShaped compiles graphB.spec, then migrates with the vector's
// state and options, comparing the plan or the error {code, keys}
// (CERTIFICATION.md §3.2).
func runMigrationShaped(doc map[string]any) string {
	graphB, _ := doc["graphB"].(map[string]any)
	registryDoc, _ := graphB["registry"].(map[string]any)
	reg := vec.Registry(registryDoc)
	art, _ := kernel.Compile(graphB["spec"], reg, nil)
	if art == nil {
		return "fail"
	}
	stateDoc, _ := doc["state"].(map[string]any)
	state := parseState(stateDoc)
	options, _ := doc["options"].(map[string]any)
	plan, kerr := kernel.Migrate(art, state, options)
	expect, _ := doc["expect"].(map[string]any)

	var got map[string]any
	if kerr != nil {
		got = map[string]any{"error": map[string]any{
			"code": kerr.Code,
			"keys": strsAny(kerr.Keys),
		}}
	} else {
		got = map[string]any{"plan": plan}
	}
	if value.Equal(any(got), any(expect)) {
		return "pass"
	}
	return "fail"
}

func strsAny(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}
