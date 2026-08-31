package kernel

// The registry binds versioned references to routine contracts and
// implementations, and graph references to graph contracts (§8.8). It is a
// parameter of compile and execute, never ambient.

// InputDecl is one contract input (§8.5). Declared-versus-defaulted survives
// as presence flags (D-46b).
type InputDecl struct {
	Name           string
	Shape          map[string]any // nil when undeclared (= any)
	Optional       bool
	Sensitivity    string // "" when undeclared (= internal)
	ConfigEligible bool
	Secret         bool
}

// OutputDecl is one contract output port.
type OutputDecl struct {
	Port        string
	Shape       map[string]any
	Sensitivity string // "" when undeclared
}

// Contract is a routine's IO contract (§8.5).
type Contract struct {
	Inputs    []InputDecl
	Outputs   []OutputDecl
	Effect    string // "pure" | "effectful"; absent means effectful
	CostClass string // absent means "default"
}

// Effectful reports the contract's effect class (§8.6: default effectful).
func (c *Contract) Effectful() bool { return c.Effect != "pure" }

// EffectiveCostClass applies the §8.5 default.
func (c *Contract) EffectiveCostClass() string {
	if c.CostClass == "" {
		return "default"
	}
	return c.CostClass
}

// Input returns the declared input by name.
func (c *Contract) Input(name string) *InputDecl {
	for i := range c.Inputs {
		if c.Inputs[i].Name == name {
			return &c.Inputs[i]
		}
	}
	return nil
}

// Output returns the declared output by port.
func (c *Contract) Output(port string) *OutputDecl {
	for i := range c.Outputs {
		if c.Outputs[i].Port == port {
			return &c.Outputs[i]
		}
	}
	return nil
}

// LoneDefaultPort reports whether the contract declares exactly the lone
// default port `value` (§8.4).
func (c *Contract) LoneDefaultPort() bool {
	return len(c.Outputs) == 1 && c.Outputs[0].Port == "value"
}

// Failure is a typed, checked routine failure (§8.9). It travels verbatim
// into reports and absorbed facts, so presence of `retryable` is preserved.
type Failure struct {
	Code         string
	Message      string
	Retryable    bool
	HasRetryable bool
	Detail       any
	HasDetail    bool
}

// Value renders the failure as a value.
func (f *Failure) Value() map[string]any {
	m := map[string]any{"code": f.Code, "message": f.Message}
	if f.HasRetryable || f.Retryable {
		m["retryable"] = f.Retryable
	}
	if f.HasDetail {
		m["detail"] = f.Detail
	}
	return m
}

// Impl is a routine implementation: pure data in (the envelope), one emission
// out — a map from port name to value — or a typed failure (§8.1, §8.9). A
// panic is an unexpected crash (§11.8).
type Impl func(env map[string]any) (map[string]any, *Failure)

// GraphBinding binds a graph reference to a child graph contract (§8.8).
type GraphBinding struct {
	Spec map[string]any // authoring form

	compiled *Artifact
	failed   bool
	resolved bool
}

// Registry is the binding set.
type Registry struct {
	Identity string
	Routines map[string]*Contract
	Impls    map[string]Impl
	Graphs   map[string]*GraphBinding
}

// ResolveGraph compiles (once) and returns the bound child artifact, or nil
// when the reference is unbound or the child spec fails its own compilation —
// the referencing node reports E_REF_UNKNOWN either way (§8.8).
func (r *Registry) ResolveGraph(ref string) *Artifact {
	gb, ok := r.Graphs[ref]
	if !ok {
		return nil
	}
	if !gb.resolved {
		gb.resolved = true
		art, _ := Compile(gb.Spec, r, nil)
		if art == nil {
			gb.failed = true
		} else {
			gb.compiled = art
		}
	}
	return gb.compiled
}

// ParseRegistry builds a Registry from a contract document value
// (contract.schema.json).
func ParseRegistry(doc map[string]any) *Registry {
	r := &Registry{
		Identity: str(doc["identity"]),
		Routines: map[string]*Contract{},
		Impls:    map[string]Impl{},
		Graphs:   map[string]*GraphBinding{},
	}
	if routines, ok := doc["routines"].(map[string]any); ok {
		for ref, cv := range routines {
			cm, ok := cv.(map[string]any)
			if !ok {
				continue
			}
			r.Routines[ref] = parseContract(cm)
		}
	}
	if graphs, ok := doc["graphs"].(map[string]any); ok {
		for ref, gv := range graphs {
			gm, ok := gv.(map[string]any)
			if !ok {
				continue
			}
			spec, _ := gm["spec"].(map[string]any)
			r.Graphs[ref] = &GraphBinding{Spec: spec}
		}
	}
	return r
}

func parseContract(cm map[string]any) *Contract {
	c := &Contract{}
	if ins, ok := cm["inputs"].([]any); ok {
		for _, iv := range ins {
			im, ok := iv.(map[string]any)
			if !ok {
				continue
			}
			d := InputDecl{Name: str(im["name"])}
			if s, ok := im["shape"].(map[string]any); ok {
				d.Shape = s
			}
			d.Optional, _ = im["optional"].(bool)
			d.Sensitivity = str(im["sensitivity"])
			d.ConfigEligible, _ = im["configEligible"].(bool)
			d.Secret, _ = im["secret"].(bool)
			c.Inputs = append(c.Inputs, d)
		}
	}
	if outs, ok := cm["outputs"].([]any); ok {
		for _, ov := range outs {
			om, ok := ov.(map[string]any)
			if !ok {
				continue
			}
			d := OutputDecl{Port: str(om["port"])}
			if s, ok := om["shape"].(map[string]any); ok {
				d.Shape = s
			}
			d.Sensitivity = str(om["sensitivity"])
			c.Outputs = append(c.Outputs, d)
		}
	}
	c.Effect = str(cm["effect"])
	c.CostClass = str(cm["costClass"])
	return c
}

func str(v any) string {
	s, _ := v.(string)
	return s
}
