package kernel

import "sort"

// Diagnostic is a compile diagnostic (§10.3).
type Diagnostic struct {
	Code     string
	Message  string
	Severity string // "error" or "lint" — always the code's default (§10.4)
	Node     string
	Edge     string
	Address  string
	Pointer  string
}

// severityOf derives the default severity from the code prefix (§10.4).
func severityOf(code string) string {
	if len(code) > 0 && code[0] == 'L' {
		return "lint"
	}
	return "error"
}

type diags struct{ list []Diagnostic }

func (d *diags) add(code, message, node, edge, address, pointer string) {
	d.list = append(d.list, Diagnostic{
		Code: code, Message: message, Severity: severityOf(code),
		Node: node, Edge: edge, Address: address, Pointer: pointer,
	})
}

// hasBlocking reports whether any diagnostic has blocking severity.
func (d *diags) hasBlocking() bool {
	for _, x := range d.list {
		if x.Severity == "error" {
			return true
		}
	}
	return false
}

// sorted returns the diagnostics in the §10.3 deterministic order:
// (code, address, pointer), comparing UTF-8 bytes.
func (d *diags) sorted() []Diagnostic {
	out := make([]Diagnostic, len(d.list))
	copy(out, d.list)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Code != out[j].Code {
			return out[i].Code < out[j].Code
		}
		if out[i].Address != out[j].Address {
			return out[i].Address < out[j].Address
		}
		return out[i].Pointer < out[j].Pointer
	})
	return out
}

// DiagnosticsValue renders diagnostics as the wire value of
// diagnostics.schema.json.
func DiagnosticsValue(list []Diagnostic) map[string]any {
	rows := make([]any, 0, len(list))
	for _, d := range list {
		row := map[string]any{
			"code":     d.Code,
			"message":  d.Message,
			"severity": d.Severity,
		}
		if d.Node != "" {
			row["node"] = d.Node
		}
		if d.Edge != "" {
			row["edge"] = d.Edge
		}
		if d.Address != "" {
			row["address"] = d.Address
		}
		if d.Pointer != "" {
			row["pointer"] = d.Pointer
		}
		rows = append(rows, row)
	}
	return map[string]any{"diagnostics": rows}
}
