package kernel

// Structural typing (§8.5): shape compatibility and shape navigation for the
// E_SHAPE_MISMATCH check.

// consumerInputShape returns the declared shape of a consumer input, or nil
// when unconstrained / unknown.
func consumerInputShape(a *analysis, n *nodeView, input string) map[string]any {
	switch n.species {
	case "routine":
		if n.contract != nil {
			if decl := n.contract.Input(input); decl != nil {
				return decl.Shape
			}
		}
	case "map":
		if input == over(n) {
			return nil // the over list's element typing is not statically declared
		}
		if n.contract != nil {
			if decl := n.contract.Input(input); decl != nil {
				return decl.Shape
			}
		} else if n.childArt != nil {
			if decl, ok := n.childArt.declaredInputs()[input]; ok {
				if s, ok := decl["shape"].(map[string]any); ok {
					return s
				}
			}
		}
	case "invoke":
		if n.childArt != nil {
			if decl, ok := n.childArt.declaredInputs()[input]; ok {
				if s, ok := decl["shape"].(map[string]any); ok {
					return s
				}
			}
		}
	}
	return nil
}

// sourceShape returns the declared shape at a binding's source, or nil when
// unknown.
func (a *analysis) sourceShape(b *bindingView) map[string]any {
	if b.isInput {
		if decl, ok := a.declaredInputs[b.inputName]; ok {
			if s, ok := decl["shape"].(map[string]any); ok {
				return s
			}
		}
		return nil
	}
	producer, ok := a.nodes[b.producer]
	if !ok || !producer.refKnown {
		return nil
	}
	switch producer.species {
	case "routine":
		var portShape map[string]any
		path := b.path
		if producer.contract.LoneDefaultPort() {
			portShape = producer.contract.Outputs[0].Shape
		} else {
			if len(path) == 0 {
				return nil
			}
			port, _ := path[0].(string)
			decl := producer.contract.Output(port)
			if decl == nil {
				return nil
			}
			portShape = decl.Shape
			path = path[1:]
		}
		return navigateShape(portShape, path)
	}
	return nil
}

// navigateShape walks a declared shape along a path; nil means unknown.
func navigateShape(shape map[string]any, path []any) map[string]any {
	cur := shape
	for _, seg := range path {
		if cur == nil {
			return nil
		}
		kind, _ := cur["kind"].(string)
		switch s := seg.(type) {
		case string:
			switch kind {
			case "record":
				fields, _ := cur["fields"].(map[string]any)
				fd, _ := fields[s].(map[string]any)
				if fd == nil {
					return nil
				}
				next, _ := fd["shape"].(map[string]any)
				cur = next
			case "map":
				next, _ := cur["of"].(map[string]any)
				cur = next
			default:
				return nil
			}
		case int64:
			if kind != "sequence" {
				return nil
			}
			next, _ := cur["of"].(map[string]any)
			cur = next
		}
	}
	return cur
}

// shapeCompatible implements the §8.5 rule: S is compatible with declared T
// iff T is any, S is any, or they have the same kind and their declared
// components are pairwise compatible (absent component = any; integer is
// compatible with number, not the converse).
func shapeCompatible(s, t map[string]any) bool {
	if t == nil || s == nil {
		return true
	}
	sk, _ := s["kind"].(string)
	tk, _ := t["kind"].(string)
	if tk == "any" || sk == "any" {
		return true
	}
	if sk == "integer" && tk == "number" {
		return true
	}
	if sk != tk {
		return false
	}
	switch sk {
	case "sequence", "map":
		so, _ := s["of"].(map[string]any)
		to, _ := t["of"].(map[string]any)
		return shapeCompatible(so, to)
	case "record":
		sf, _ := s["fields"].(map[string]any)
		tf, _ := t["fields"].(map[string]any)
		for name, tfd := range tf {
			sfd, ok := sf[name]
			if !ok {
				continue // absent component is any
			}
			sShape, _ := sfd.(map[string]any)["shape"].(map[string]any)
			tShape, _ := tfd.(map[string]any)["shape"].(map[string]any)
			if !shapeCompatible(sShape, tShape) {
				return false
			}
		}
		return true
	}
	return true
}
