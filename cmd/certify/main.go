// Command certify runs the Wilanis conformance kit (spec/conformance) against
// this implementation and emits certification result documents per
// CERTIFICATION.md §3 and SPEC.md §15.11, rendered byte-canonically (A.6).
//
// Usage: certify [-outdir results] <spec-dir>
//
// It verifies the manifest freeze, runs every vector family and every theorem,
// and writes results/level-N.json for N in 0..3 — each the certification
// result of a run that attempts levels 0..N and marks the rest skipped.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rfontes1987/wilanis-go/internal/harness"
	"github.com/rfontes1987/wilanis-go/internal/wire"
)

func main() {
	outdir := "results"
	args := os.Args[1:]
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		switch {
		case args[0] == "-outdir" && len(args) > 1:
			outdir = args[1]
			args = args[2:]
		default:
			fmt.Fprintln(os.Stderr, "usage: certify [-outdir dir] <spec-dir>")
			os.Exit(2)
		}
	}
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: certify [-outdir dir] <spec-dir>")
		os.Exit(2)
	}
	specDir := args[0]
	if _, err := os.Stat(filepath.Join(specDir, "conformance")); err != nil {
		// tolerate being launched from a subdirectory or with a stale
		// relative path: the spec directory is findable from the module root
		for _, alt := range []string{"spec", filepath.Join("..", "spec")} {
			if _, err := os.Stat(filepath.Join(alt, "conformance")); err == nil {
				specDir = alt
				break
			}
		}
	}
	confDir := filepath.Join(specDir, "conformance")

	manifestVersion, manifestHash, err := harness.VerifyManifest(confDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "manifest verification failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("manifest %s verified (%s)\n", manifestVersion, manifestHash)

	vectors, err := harness.LoadVectors(confDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "loading vectors: %v\n", err)
		os.Exit(1)
	}
	seeds, err := harness.LoadSeeds(confDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "loading seeds: %v\n", err)
		os.Exit(1)
	}

	// Run everything once at full level; the per-level documents are the same
	// outcomes with above-level work marked skipped.
	outcomes := map[string]string{}
	for _, v := range vectors {
		outcome := harness.RunVector(v)
		outcomes[v.ID] = outcome
		if outcome != "pass" {
			fmt.Printf("  %-45s %s\n", v.ID, outcome)
		}
	}
	theoremResults := harness.RunTheorems(seeds)

	if err := os.MkdirAll(outdir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	for level := 0; level <= 3; level++ {
		doc := buildResult(vectors, outcomes, theoremResults, seeds, level, manifestVersion, manifestHash)
		path := filepath.Join(outdir, fmt.Sprintf("level-%d.json", level))
		if err := os.WriteFile(path, wire.RenderCanonical(doc), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
	}

	full := buildResult(vectors, outcomes, theoremResults, seeds, 3, manifestVersion, manifestHash)
	la := full["levelAchieved"]
	if la == nil {
		fmt.Println("levelAchieved: null")
	} else {
		fmt.Printf("levelAchieved: %v\n", la)
	}
}

// buildResult assembles the §15.11 certification result for a run attempting
// levels 0..attempt.
func buildResult(vectors []*harness.Vector, outcomes map[string]string, theorems map[string]harness.TheoremResult, seeds *harness.Seeds, attempt int, manifestVersion, manifestHash string) map[string]any {
	vecRows := make([]any, 0, len(vectors))
	ids := make([]string, 0, len(vectors))
	byID := map[string]*harness.Vector{}
	for _, v := range vectors {
		ids = append(ids, v.ID)
		byID[v.ID] = v
	}
	sort.Strings(ids)

	// pass tracking per level: requirement of level n = every vector of
	// level ≤ n passes; plus T1–T4 at n ≥ 2 and T5 at n ≥ 3.
	vecOK := map[int]bool{0: true, 1: true, 2: true, 3: true}
	for _, id := range ids {
		v := byID[id]
		outcome := outcomes[id]
		if v.Level > attempt {
			outcome = "skipped"
		}
		vecRows = append(vecRows, map[string]any{"id": id, "outcome": outcome})
		if outcome != "pass" {
			for n := v.Level; n <= 3; n++ {
				vecOK[n] = false
			}
		}
	}

	theoremRows := make([]any, 0, 5)
	tOK := map[int]bool{0: true, 1: true, 2: true, 3: true}
	for _, tid := range []string{"T1", "T2", "T3", "T4", "T5"} {
		minLevel := 2
		if tid == "T5" {
			minLevel = 3
		}
		res := theorems[tid]
		outcome := res.Outcome
		violations := res.Violations
		if minLevel > attempt {
			outcome = "skipped"
			violations = nil
		}
		row := map[string]any{
			"id":      tid,
			"seeds":   int64(len(seeds.Theorems[tid])),
			"outcome": outcome,
		}
		if len(violations) > 0 {
			vs := make([]any, len(violations))
			for i, s := range violations {
				vs[i] = s
			}
			row["violations"] = vs
		}
		theoremRows = append(theoremRows, row)
		if outcome != "pass" {
			for n := minLevel; n <= 3; n++ {
				tOK[n] = false
			}
		}
	}

	levels := map[string]any{}
	cumulative := true
	levelAchieved := any(nil)
	for n := 0; n <= 3; n++ {
		ok := vecOK[n] && tOK[n]
		cumulative = cumulative && ok
		levels[fmt.Sprintf("%d", n)] = cumulative
		if cumulative {
			levelAchieved = int64(n)
		}
	}

	return map[string]any{
		"implementation": map[string]any{
			"name":     "wilanis-go",
			"version":  "0.1.0",
			"language": "go",
		},
		"manifest": map[string]any{
			"version": manifestVersion,
			"hash":    manifestHash,
		},
		"vectors":       vecRows,
		"theorems":      theoremRows,
		"levels":        levels,
		"levelAchieved": levelAchieved,
	}
}
