package harness

import (
	"github.com/rfontes1987/wilanis-go/internal/kernel"
	"github.com/rfontes1987/wilanis-go/internal/value"
)

// compileSurface runs compile and renders the compared surface: either the
// §10.8 ok surface or diagnostics projected per §15.2 to {code, severity}.
func compileSurface(spec any, registryDoc, options map[string]any) map[string]any {
	reg := kernel.ParseRegistry(registryDoc)
	art, diagsList := kernel.Compile(spec, reg, options)
	if art != nil {
		return map[string]any{"ok": map[string]any{
			"graphHash":     art.GraphHash,
			"canonicalSpec": art.CanonicalSpec,
			"derivations":   derivationsValue(art.Derivations),
		}}
	}
	rows := make([]any, 0, len(diagsList))
	for _, d := range diagsList {
		rows = append(rows, map[string]any{"code": d.Code, "severity": d.Severity})
	}
	return map[string]any{"diagnostics": rows}
}

func derivationsValue(m map[string]string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// projectExpect normalizes a compile expectation per §15.2: diagnostics keep
// only {code, severity}; an ok surface is compared whole.
func projectExpect(expect map[string]any) map[string]any {
	if dl, ok := expect["diagnostics"].([]any); ok {
		rows := make([]any, 0, len(dl))
		for _, dv := range dl {
			dm := dv.(map[string]any)
			rows = append(rows, map[string]any{"code": dm["code"], "severity": dm["severity"]})
		}
		return map[string]any{"diagnostics": rows}
	}
	return expect
}

func runCompileShaped(doc map[string]any) string {
	spec := doc["spec"]
	registryDoc, _ := doc["registry"].(map[string]any)
	options, _ := doc["options"].(map[string]any)
	expect, _ := doc["expect"].(map[string]any)
	got := compileSurface(spec, registryDoc, options)
	if value.Equal(any(got), any(projectExpect(expect))) {
		return "pass"
	}
	return "fail"
}
