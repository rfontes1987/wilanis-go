package harness

import (
	"fmt"
	"os"
	"testing"

	"github.com/rfontes1987/wilanis-go/internal/wire"
)

// TestDebugVector runs one vector without the panic guard, for debugging.
// Select with WILANIS_DEBUG_VECTOR.
func TestDebugVector(t *testing.T) {
	id := os.Getenv("WILANIS_DEBUG_VECTOR")
	if id == "" {
		t.Skip("set WILANIS_DEBUG_VECTOR")
	}
	vs, err := LoadVectors("../../spec/conformance")
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range vs {
		if v.ID != id {
			continue
		}
		var out string
		switch v.Family {
		case "compile":
			out = runCompileShaped(v.Doc)
		case "expression":
			out = runExpression(v)
		case "execution":
			out = runExecutionShaped(v.Doc, "options")
		case "migration":
			out = runMigration(v)
		default:
			out = runIdentity(v)
		}
		fmt.Println("outcome:", out)
		if out != "pass" && os.Getenv("WILANIS_DEBUG_DUMP") != "" {
			dumpMismatch(v)
		}
	}
}

// dumpMismatch prints got-vs-want for execution vectors.
func dumpMismatch(v *Vector) {
	if v.Family != "execution" && v.Family != "expression" {
		return
	}
	optKey := "options"
	if v.Family == "expression" {
		optKey = "execOptions"
	}
	got, err := executeForDebug(v.Doc, optKey)
	if err != nil {
		fmt.Println("exec error:", err)
		return
	}
	expect, _ := v.Doc["expect"].(map[string]any)
	fmt.Println("GOT: ", string(wire.RenderCanonical(zeroElapsed(any(got)))))
	fmt.Println("WANT:", string(wire.RenderCanonical(zeroElapsed(expect["report"]))))
}
