package harness

// Family runners not yet implemented report "error" so a partial level is a
// scored fact (§15.10). Each is replaced as its level lands.

func runCompile(v *Vector) string { return runCompileShaped(v.Doc) }

// runExpression handles both compile-shaped and execution-shaped expression
// vectors (§15.4).
func runExpression(v *Vector) string {
	if expect, ok := v.Doc["expect"].(map[string]any); ok {
		if _, isReport := expect["report"]; isReport {
			return runExecutionShaped(v.Doc, "execOptions")
		}
	}
	return runCompileShaped(v.Doc)
}
func runExecution(v *Vector) string { return runExecutionShaped(v.Doc, "options") }
func runMigration(v *Vector) string { return runMigrationShaped(v.Doc) }

// TheoremResult is one theorem's outcome for the certification result.
type TheoremResult struct {
	Outcome    string // pass | fail | vacuous | skipped
	Violations []int64
}
