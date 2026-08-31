# wilanis-go

**A certified implementation of the Wilanis Kernel — not the reference.**

The definition of correct is the conformance corpus of the specification repository,
[rfontes1987/wilanis](https://github.com/rfontes1987/wilanis); this repository is one
implementation measured against it. Per the specification's own doctrine, no implementation
— this one included — is ever the reference.

**Certification: Level 3 (full kernel).** All 134 conformance vectors pass by value equality
and property theorems T1–T5 hold over the shipped seeds, against conformance manifest 0.1.0.
The certification results are `results/level-{0..3}.json`, rendered byte-canonically per
SPEC.md Appendix A.6 — recomputing them is byte-identical.

## Provenance

This kernel was implemented **from the specification alone** by an AI agent (Claude,
Anthropic) working in Claude Code: no web access, no other implementation consulted, Go
standard library only. The exact task prompt is [PROMPT.md](PROMPT.md). The corpus verifies
every observable behavior; code style and non-observable qualities carry no further warranty
than that.

## Reproduce the certification

```bash
git clone https://github.com/rfontes1987/wilanis ../wilanis
go run ./cmd/certify ../wilanis
```

This verifies the corpus manifest (SHA-256 over every schema, vector, and seed file), runs
every vector family and every theorem, and rewrites `results/level-{0..3}.json`. Each
level-N document is the certification result attempting levels 0..N.

## Layout

| Path | What |
|---|---|
| `cmd/certify` | the certification harness: manifest freeze check, vector families, theorems, result rendering |
| `internal/value` | the data model and the structural hash (SPEC.md §4, §6) |
| `internal/wire` | packaging: ingestion bounds, canonical rendering (Appendix A) |
| `internal/expr` | predicates: the guarded expression subset and match specifications (§9) |
| `internal/kernel` | compile and execute: normalization, analysis, the fixpoint loop, settlement, report, migration (§7–§14) |
| `internal/gen`, `internal/harness` | the seeded generator and theorem drivers (§15.7–§15.8) |
| `internal/vec` | the vector routines (§15.13) |
| `arch_test.go` | the two architectural rules as static checks (§15.12): no wall clock outside one component, evaluator behind its seam |

## License

Apache-2.0. The specification and corpus are licensed in their own repository.
