# The prompt

This implementation was produced by an AI agent (Claude, in Claude Code) given a read-only
copy of the specification repository at `spec/` — with `conformance/tools/` removed, so no
existing implementation was available even as authoring tooling — and the following prompt,
verbatim. The operator answered any substantive question only with: *"Follow the spec. If it
is ambiguous, record it in SPEC-ISSUES.md with the smallest decision and continue."*

---

Implement the specification in `spec/` from scratch, in Go.

1. `spec/` is read-only law. Your only sources are that directory and standard Go
   knowledge. Do not search the web, and do not consult any other implementation of
   anything.
2. Begin with `spec/AGENTS.md` and follow it exactly: its reading order, its implementation
   order, and its definition of done.
3. Go 1.22+, standard library only, one module at this workspace root.
4. Build your own certification harness per `spec/CERTIFICATION.md`. After completing each
   level, emit the certification result document (byte-canonical, per SPEC.md Appendix A.6)
   into `results/level-N.json`. `go run ./cmd/certify ../spec` must reproduce the full run
   end to end.
5. When the specification is ambiguous, silent, or defective, do not resolve it silently:
   record the section number, the problem, and the smallest decision you took to proceed in
   `SPEC-ISSUES.md`, then continue.
6. Commit at each level boundary with the level's certification result in the commit
   message.

Done means Level 3: the manifest verifies, every vector passes by value equality after the
single stated normalization, and theorems T1–T5 hold over the shipped seeds. A partial level
is a scored fact — emit its result and keep going.

---

## The run

| | |
|---|---|
| Model | `claude-fable-5` (Claude Code) |
| Date | 2026-08-31 |
| Result | Level 3 — 134/134 vectors, theorems T1–T5 |
| Cost | **$54.24** (211.3k output tokens; 35.2M cache reads) |
| Duration | 1h 6m 57s wall · 48m 36s API |
| Code produced | 8,373 lines added, 57 removed |
| Spec issues filed | 7 |
| Operator help | none beyond the standing rule quoted above |

The issues the agent filed were absorbed into the specification through its governance
process; the published spec already reflects them. (One path note: the harness takes the
spec directory as an argument — `go run ./cmd/certify <path-to-spec>` — since the literal
`../spec` in the prompt assumed a layout the workspace did not have.)
