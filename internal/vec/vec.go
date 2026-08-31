// Package vec implements the vector routines of SPEC.md §15.13 — part of the
// conformance kit, not of the kernel.
package vec

import (
	"github.com/rfontes1987/wilanis-go/internal/kernel"
	"github.com/rfontes1987/wilanis-go/internal/value"
)

// Impls returns the implementations of the §15.13 vector routines.
func Impls() map[string]kernel.Impl {
	return map[string]kernel.Impl{
		"vec/const@1": func(env map[string]any) (map[string]any, *kernel.Failure) {
			return map[string]any{"value": env["value"]}, nil
		},
		"vec/echo@1": func(env map[string]any) (map[string]any, *kernel.Failure) {
			return map[string]any{"value": env["in"]}, nil
		},
		"vec/pack@1": func(env map[string]any) (map[string]any, *kernel.Failure) {
			out := map[string]any{}
			for _, name := range []string{"a0", "a1", "a2", "a3", "a4", "a5"} {
				if v, ok := env[name]; ok {
					out[name] = v
				}
			}
			return map[string]any{"value": out}, nil
		},
		"vec/two@1": func(env map[string]any) (map[string]any, *kernel.Failure) {
			return map[string]any{"a": env["a"], "b": env["b"]}, nil
		},
		"vec/sense@1": func(env map[string]any) (map[string]any, *kernel.Failure) {
			return map[string]any{"value": env["in"]}, nil
		},
		"vec/scrub@1": func(env map[string]any) (map[string]any, *kernel.Failure) {
			return map[string]any{"value": "scrubbed"}, nil
		},
		"vec/fail@1": func(env map[string]any) (map[string]any, *kernel.Failure) {
			code, _ := env["code"].(string)
			message, _ := env["message"].(string)
			retryable, _ := env["retryable"].(bool)
			return nil, &kernel.Failure{Code: code, Message: message, Retryable: retryable, HasRetryable: true}
		},
		"vec/flaky@1": func(env map[string]any) (map[string]any, *kernel.Failure) {
			attempt, _ := env["$attempt"].(int64)
			succeedOn, _ := env["succeed_on"].(int64)
			if attempt < succeedOn {
				return nil, &kernel.Failure{Code: "vec/again", Message: "not yet", Retryable: true}
			}
			return map[string]any{"value": env["value"]}, nil
		},
		"vec/keyecho@1": func(env map[string]any) (map[string]any, *kernel.Failure) {
			return map[string]any{"value": map[string]any{"key": env["$key"]}}, nil
		},
		"vec/failif@1": func(env map[string]any) (map[string]any, *kernel.Failure) {
			if value.Equal(env["in"], env["when"]) {
				code, _ := env["code"].(string)
				return nil, &kernel.Failure{Code: code, Message: "matched", Retryable: false, HasRetryable: true}
			}
			return map[string]any{"value": env["in"]}, nil
		},
		"vec/deep@1": func(env map[string]any) (map[string]any, *kernel.Failure) {
			n, _ := env["n"].(int64)
			var v any = int64(0)
			for i := int64(0); i < n; i++ {
				v = []any{v}
			}
			return map[string]any{"value": v}, nil
		},
	}
}

// TheoremRegistry is the registry the theorem harness binds (§15.8, §15.13):
// the vector-routine contracts used by generated graphs, identity
// "vec-registry@0.1.0".
func TheoremRegistry() *kernel.Registry {
	anyShape := map[string]any{"kind": "any"}
	doc := map[string]any{
		"identity": "vec-registry@0.1.0",
		"routines": map[string]any{
			"vec/const@1": map[string]any{
				"costClass": "default", "effect": "pure",
				"inputs":  []any{map[string]any{"name": "value", "configEligible": true, "shape": anyShape}},
				"outputs": []any{map[string]any{"port": "value"}},
			},
			"vec/pack@1": map[string]any{
				"costClass": "default", "effect": "pure",
				"inputs": []any{
					map[string]any{"name": "a0", "optional": true, "shape": anyShape},
					map[string]any{"name": "a1", "optional": true, "shape": anyShape},
					map[string]any{"name": "a2", "optional": true, "shape": anyShape},
					map[string]any{"name": "a3", "optional": true, "shape": anyShape},
					map[string]any{"name": "a4", "optional": true, "shape": anyShape},
					map[string]any{"name": "a5", "optional": true, "shape": anyShape},
				},
				"outputs": []any{map[string]any{"port": "value"}},
			},
			"vec/fail@1": map[string]any{
				"costClass": "effect", "effect": "effectful",
				"inputs": []any{
					map[string]any{"name": "in", "optional": true, "shape": anyShape},
					map[string]any{"name": "code", "configEligible": true, "shape": map[string]any{"kind": "string"}},
					map[string]any{"name": "message", "configEligible": true, "shape": map[string]any{"kind": "string"}},
					map[string]any{"name": "retryable", "configEligible": true, "shape": map[string]any{"kind": "boolean"}},
				},
				"outputs": []any{map[string]any{"port": "value"}},
			},
		},
	}
	return Registry(doc)
}

// Registry parses a contract document and binds the vector-routine
// implementations.
func Registry(doc map[string]any) *kernel.Registry {
	reg := kernel.ParseRegistry(doc)
	for ref, impl := range Impls() {
		reg.Impls[ref] = impl
	}
	return reg
}
