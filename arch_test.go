// Package wilanis_test enforces SPEC.md §15.12: the two architectural laws
// that live in implementation architecture rather than observable values,
// checked statically over this module's own source.
package wilanis_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func goFiles(t *testing.T) []string {
	var files []string
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			name := info.Name()
			if name == "spec" || name == ".git" || name == "results" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func importsOf(t *testing.T, path string) []string {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	var out []string
	for _, imp := range f.Imports {
		out = append(out, strings.Trim(imp.Path.Value, `"`))
	}
	return out
}

// TestNoWallClockOutsideClock enforces §11.19: no clock API outside the one
// named component (internal/kernel/clock).
func TestNoWallClockOutsideClock(t *testing.T) {
	for _, path := range goFiles(t) {
		if strings.HasPrefix(filepath.ToSlash(path), "internal/kernel/clock/") {
			continue
		}
		for _, imp := range importsOf(t, path) {
			if imp == "time" {
				t.Errorf("%s imports %q outside the clock component (§11.19)", path, imp)
			}
		}
	}
}

// TestEvaluatorSeam enforces §9.6: the expression evaluator sits behind a
// seam — internal/expr is imported by exactly one kernel file (the predicate
// seam) and by nothing else in the kernel.
func TestEvaluatorSeam(t *testing.T) {
	for _, path := range goFiles(t) {
		slash := filepath.ToSlash(path)
		if strings.HasPrefix(slash, "internal/expr/") {
			continue
		}
		for _, imp := range importsOf(t, path) {
			if imp == "github.com/rfontes1987/wilanis-go/internal/expr" && slash != "internal/kernel/predicates.go" {
				t.Errorf("%s imports the expression evaluator outside the seam (§9.6)", path)
			}
		}
	}
}
