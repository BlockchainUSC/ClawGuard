package capability

import "sort"

// ToolCategory groups concrete tools by the kind of access they grant. Profiles
// are expressed in categories so that adding a tool does not mean revisiting
// every tier.
type ToolCategory string

const (
	CatShell       ToolCategory = "shell"
	CatSQLExec     ToolCategory = "sql_exec"
	CatSQLReadOnly ToolCategory = "sql_readonly"
	CatWebSearch   ToolCategory = "web_search"
	CatFileIO      ToolCategory = "file_io"
	CatStaticAPI   ToolCategory = "static_api"
)

// ModelRoute selects which upstream model serves a request, and under which
// system prompt.
type ModelRoute string

const (
	RoutePrimaryFull      ModelRoute = "primary-full"
	RoutePrimaryStrict    ModelRoute = "primary-strict"
	RouteLightweightGuard ModelRoute = "lightweight-guard"
	RouteStaticRefusal    ModelRoute = "static-refusal"
)

// Profile is the set of privileges granted at a tier.
//
// Its fields are unexported and its tool set is reachable only through Allows.
// A caller that could mutate a returned Profile could widen permissions for
// every session in the process.
type Profile struct {
	tier          Tier
	name          string
	readOnly      bool
	toolsStripped bool
	allowed       map[ToolCategory]struct{}
	model         ModelRoute
}

func (p Profile) Tier() Tier          { return p.tier }
func (p Profile) Name() string        { return p.name }
func (p Profile) ReadOnly() bool      { return p.readOnly }
func (p Profile) ToolsStripped() bool { return p.toolsStripped }
func (p Profile) Model() ModelRoute   { return p.model }

// Allows reports whether this profile permits a tool category.
//
// The zero Profile allows nothing, so a Profile that was never initialised
// fails closed rather than granting everything.
func (p Profile) Allows(c ToolCategory) bool {
	if p.toolsStripped {
		return false
	}
	_, ok := p.allowed[c]
	return ok
}

// AllowedCategories returns a sorted copy of the permitted categories.
func (p Profile) AllowedCategories() []ToolCategory {
	if p.toolsStripped {
		return nil
	}
	out := make([]ToolCategory, 0, len(p.allowed))
	for c := range p.allowed {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func set(cats ...ToolCategory) map[ToolCategory]struct{} {
	m := make(map[ToolCategory]struct{}, len(cats))
	for _, c := range cats {
		m[c] = struct{}{}
	}
	return m
}

var profiles = map[Tier]Profile{
	TierFull: {
		tier:    TierFull,
		name:    "Full / Unrestricted",
		allowed: set(CatShell, CatSQLExec, CatSQLReadOnly, CatWebSearch, CatFileIO, CatStaticAPI),
		model:   RoutePrimaryFull,
	},
	TierConstrained: {
		tier:     TierConstrained,
		name:     "Constrained",
		readOnly: true,
		allowed:  set(CatSQLReadOnly, CatWebSearch, CatStaticAPI),
		model:    RoutePrimaryStrict,
	},
	TierQuarantined: {
		tier:          TierQuarantined,
		name:          "Quarantined",
		readOnly:      true,
		toolsStripped: true,
		model:         RouteLightweightGuard,
	},
	TierBlocked: {
		tier:          TierBlocked,
		name:          "Hard Block",
		readOnly:      true,
		toolsStripped: true,
		model:         RouteStaticRefusal,
	},
}

// ProfileFor returns the profile for a tier. An unrecognised tier yields the
// blocked profile.
func ProfileFor(t Tier) Profile {
	p, ok := profiles[t]
	if !ok {
		return profiles[TierBlocked]
	}
	return p
}
