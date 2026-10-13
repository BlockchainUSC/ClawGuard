package capability

import (
	"slices"
	"testing"
)

func testRegistry() *Registry {
	return NewRegistry(map[string]ToolCategory{
		"run_shell":   CatShell,
		"sql_write":   CatSQLExec,
		"sql_select":  CatSQLReadOnly,
		"web_search":  CatWebSearch,
		"read_file":   CatFileIO,
		"weather_api": CatStaticAPI,
	})
}

// The most important test in this package. A registry that defaulted to allow
// would silently undo every other control: an attacker-renamed or
// newly-introduced tool would pass unchecked at every tier.
func TestRegistry_UnknownToolIsDenied(t *testing.T) {
	r := testRegistry()
	full := ProfileFor(TierFull) // the most permissive profile there is

	for _, name := range []string{
		"", "unknown_tool", "run_shell ", "RUN_SHELL", "run_shell\n",
		"../run_shell", "exec", "sql_select;DROP",
	} {
		if r.Permitted(full, name) {
			t.Errorf("unknown tool %q was permitted at the full tier", name)
		}
	}
}

func TestRegistry_NilRegistryDeniesEverything(t *testing.T) {
	var r *Registry
	if r.Permitted(ProfileFor(TierFull), "run_shell") {
		t.Error("nil registry permitted a tool")
	}
	if _, ok := r.CategoryOf("run_shell"); ok {
		t.Error("nil registry resolved a category")
	}
}

func TestRegistry_PermittedFollowsProfile(t *testing.T) {
	r := testRegistry()

	cases := []struct {
		tier Tier
		tool string
		want bool
	}{
		{TierFull, "run_shell", true},
		{TierFull, "sql_write", true},
		{TierFull, "read_file", true},
		{TierConstrained, "sql_select", true},
		{TierConstrained, "web_search", true},
		{TierConstrained, "run_shell", false},
		{TierConstrained, "sql_write", false},
		{TierConstrained, "read_file", false},
		{TierQuarantined, "web_search", false},
		{TierQuarantined, "sql_select", false},
		{TierBlocked, "web_search", false},
	}
	for _, c := range cases {
		if got := r.Permitted(ProfileFor(c.tier), c.tool); got != c.want {
			t.Errorf("Permitted(%s, %s) = %v, want %v", c.tier, c.tool, got, c.want)
		}
	}
}

func TestRegistry_FilterTools(t *testing.T) {
	r := testRegistry()
	in := []string{"run_shell", "sql_select", "unknown_tool", "web_search", "sql_write"}

	if got := r.FilterTools(ProfileFor(TierFull), in); !slices.Equal(got,
		[]string{"run_shell", "sql_select", "web_search", "sql_write"}) {
		t.Errorf("full tier filter = %v", got)
	}

	if got := r.FilterTools(ProfileFor(TierConstrained), in); !slices.Equal(got,
		[]string{"sql_select", "web_search"}) {
		t.Errorf("constrained tier filter = %v", got)
	}

	// Below level 2 no tools are forwarded at all.
	for _, tier := range []Tier{TierQuarantined, TierBlocked} {
		if got := r.FilterTools(ProfileFor(tier), in); len(got) != 0 {
			t.Errorf("%s forwarded tools %v", tier, got)
		}
	}
}

// Mutating the caller's map after construction must not widen permissions.
func TestRegistry_CopiesItsInput(t *testing.T) {
	src := map[string]ToolCategory{"sql_select": CatSQLReadOnly}
	r := NewRegistry(src)

	src["run_shell"] = CatShell

	if r.Permitted(ProfileFor(TierFull), "run_shell") {
		t.Error("registry observed a mutation of the caller's map")
	}
}
