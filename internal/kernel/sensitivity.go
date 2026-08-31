package kernel

// Sensitivity propagation (§10.6): every value position has a class from the
// ordered lattice public < internal < pii, defaulting to internal. Each node
// output's class is the least fixpoint over data edges.

// propagateSensitivity computes port classes and runs the two coherence
// checks.
func (a *analysis) propagateSensitivity(d *diags) {
	// initialize port classes
	for _, id := range a.nodeOrder {
		n := a.nodes[id]
		a.portClass[id] = map[string]int{}
		_ = n
	}
	// iterate to fixpoint (finite lattice, monotone)
	for iter := 0; iter < len(a.nodeOrder)*3+8; iter++ {
		changed := false
		for _, id := range a.nodeOrder {
			n := a.nodes[id]
			in := a.inClass(n)
			ports := a.portClass[id]
			set := func(port string, rank int) {
				if ports[port] < rank {
					ports[port] = rank
					changed = true
				}
			}
			switch n.species {
			case "routine":
				if n.contract != nil {
					for _, out := range n.contract.Outputs {
						if out.Sensitivity != "" {
							// a declared output sensitivity always wins for its port
							set(out.Port, classRank(out.Sensitivity))
						} else {
							set(out.Port, max(classInternal, in))
						}
					}
				} else {
					set("", max(classInternal, in))
				}
			case "decision", "map":
				// kernel-defined outputs take the propagation default
				set("", max(classInternal, in))
			case "invoke":
				if n.childArt != nil {
					for name, rank := range n.childArt.exportClasses {
						set(name, max(rank, max(classInternal, in)))
					}
				} else {
					set("", max(classInternal, in))
				}
			}
		}
		if !changed {
			break
		}
	}

	// fan-out routine-body children commit facts too: their class follows the
	// routine-node rule over the body contract's declared output classes
	for _, id := range a.nodeOrder {
		n := a.nodes[id]
		if n.species != "map" || n.contract == nil {
			continue
		}
		in := a.inClass(n)
		rank := 0
		if len(n.contract.Outputs) == 0 {
			rank = max(classInternal, in)
		}
		for _, out := range n.contract.Outputs {
			r := max(classInternal, in)
			if out.Sensitivity != "" {
				r = classRank(out.Sensitivity)
			}
			if r > rank {
				rank = r
			}
		}
		a.fanChildClass[id] = rank
	}

	// node fact class: the maximum over its ports' classes
	anyPii := false
	for _, rank := range a.fanChildClass {
		if rank == classPii {
			anyPii = true // children commit facts: they are node outputs for the pii test
		}
	}
	for _, id := range a.nodeOrder {
		m := 0
		for _, rank := range a.portClass[id] {
			if rank > m {
				m = rank
			}
		}
		a.nodeClass[id] = m
		if m == classPii {
			anyPii = true
		}
	}
	// export classes
	maxExport := 0
	for _, ex := range a.exports {
		if !ex.ok {
			continue
		}
		rank := classInternal
		if ex.ep.IsInput {
			rank = a.inputClass(ex.ep.Input)
		} else if n, ok := a.nodes[ex.ep.Node]; ok {
			rank = a.classAtPort(n, ex.ep.Path)
		}
		a.exportClasses[ex.name] = rank
		if rank > maxExport {
			maxExport = rank
		}
		if rank == classPii {
			anyPii = true
		}
	}

	// whole-composition pii presence (§10.6): a graph carries pii facts if any
	// node of it, or of any composed child, does.
	a.hasPii = anyPii
	for _, id := range a.nodeOrder {
		n := a.nodes[id]
		if n.childArt != nil && n.childArt.hasPii {
			a.hasPii = true
		}
	}

	// subject designation
	subjects := 0
	for iname, decl := range a.declaredInputs {
		if s, _ := decl["subject"].(bool); s {
			subjects++
			a.subjectInput = iname
		}
	}
	if subjects != 1 {
		a.subjectInput = ""
	}
	if a.hasPii && subjects != 1 {
		d.add("E_SENS_NO_SUBJECT", "graph carries pii facts but designates no single subject input", "", "", "graph", "")
	}

	// distribution coherence
	if dist, _ := a.spec["distribution"].(string); dist == "client" {
		leak := maxExport > classPublic
		for _, id := range a.nodeOrder {
			if a.nodeClass[id] > classPublic {
				leak = true
			}
		}
		for _, decl := range a.declaredInputs {
			if classRank(str(decl["sensitivity"])) > classPublic {
				leak = true
			}
		}
		if leak {
			d.add("E_SENS_LEAK", "client-distributable graph exposes a non-public value", "", "", "graph", "")
		}
	}
}

// inClass is the maximum class reaching a node's inputs over data edges.
func (a *analysis) inClass(n *nodeView) int {
	m := 0
	for _, iname := range n.inputOrder {
		for _, b := range n.inputs[iname].bindings {
			var rank int
			if b.isInput {
				rank = a.inputClass(b.inputName)
			} else if p, ok := a.nodes[b.producer]; ok {
				rank = a.classAtPort(p, b.path)
			}
			if rank > m {
				m = rank
			}
		}
	}
	return m
}

func (a *analysis) inputClass(name string) int {
	if decl, ok := a.declaredInputs[name]; ok {
		if s, ok := decl["sensitivity"].(string); ok {
			return classRank(s)
		}
	}
	return classInternal
}

// classAtPort resolves a producer path to the producing port's class.
func (a *analysis) classAtPort(n *nodeView, path []any) int {
	ports := a.portClass[n.id]
	switch n.species {
	case "routine":
		if n.contract != nil && !n.contract.LoneDefaultPort() && len(path) > 0 {
			if port, ok := path[0].(string); ok {
				if r, ok := ports[port]; ok {
					return r
				}
			}
			return classInternal
		}
		if n.contract != nil && n.contract.LoneDefaultPort() {
			return ports["value"]
		}
		return ports[""]
	case "decision", "map":
		return ports[""]
	case "invoke":
		if len(path) > 0 {
			if port, ok := path[0].(string); ok {
				if r, ok := ports[port]; ok {
					return r
				}
			}
		}
		return classInternal
	}
	return classInternal
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
