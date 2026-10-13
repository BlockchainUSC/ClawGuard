package capability

// Registry maps concrete tool names, as they appear in an inbound tools[]
// array, onto capability categories.
type Registry struct {
	byName map[string]ToolCategory
}

// NewRegistry copies m, so later mutation of the caller's map cannot widen
// permissions after construction.
func NewRegistry(m map[string]ToolCategory) *Registry {
	cp := make(map[string]ToolCategory, len(m))
	for name, cat := range m {
		cp[name] = cat
	}
	return &Registry{byName: cp}
}

// CategoryOf resolves a tool name. An unknown name returns false, and callers
// must treat that as denied.
func (r *Registry) CategoryOf(name string) (ToolCategory, bool) {
	if r == nil {
		return "", false
	}
	cat, ok := r.byName[name]
	return cat, ok
}

// Permitted is the single decision point for "may this session call this tool".
//
// Default-deny: an unknown tool name, a nil registry, and a profile with tools
// stripped all return false. A registry that defaulted to allow would silently
// undo every other control in this package, which is why the unknown-name case
// has a dedicated test.
func (r *Registry) Permitted(p Profile, toolName string) bool {
	cat, ok := r.CategoryOf(toolName)
	if !ok {
		return false
	}
	return p.Allows(cat)
}

// FilterTools returns the subset of toolNames permitted under p, preserving
// input order. This is the splice applied to the upstream tools[] array in
// Phase 5; at TierQuarantined and above it returns nil.
func (r *Registry) FilterTools(p Profile, toolNames []string) []string {
	if p.ToolsStripped() {
		return nil
	}
	var out []string
	for _, name := range toolNames {
		if r.Permitted(p, name) {
			out = append(out, name)
		}
	}
	return out
}
