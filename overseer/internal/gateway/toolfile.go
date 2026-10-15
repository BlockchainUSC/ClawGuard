package gateway

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"openclaw/guard/overseer/internal/capability"
)

// ToolFile is the operator-editable registry: which capability category each
// tool name belongs to.
//
// A file rather than a compiled-in map so the tool set can change without a
// rebuild and can differ between deployments, and so it is reviewable in git.
type ToolFile struct {
	Tools map[string]string `json:"tools"`
}

// knownCategories is the closed set a file may reference.
var knownCategories = map[capability.ToolCategory]bool{
	capability.CatShell:       true,
	capability.CatSQLExec:     true,
	capability.CatSQLReadOnly: true,
	capability.CatWebSearch:   true,
	capability.CatFileIO:      true,
	capability.CatStaticAPI:   true,
}

// LoadToolRegistry reads and validates the registry file.
//
// Validation is strict and happens at startup, not on first request. A typo in
// a category name would otherwise leave that tool unclassified, and an
// unclassified tool is denied — so a one-character mistake silently removes a
// capability from every session, which looks like a model regression rather
// than a config error.
func LoadToolRegistry(path string) (*capability.Registry, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading tool registry: %w", err)
	}

	var f ToolFile
	dec := json.NewDecoder(stringsReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("parsing tool registry %s: %w", path, err)
	}
	if len(f.Tools) == 0 {
		return nil, fmt.Errorf("tool registry %s defines no tools", path)
	}

	mapped := make(map[string]capability.ToolCategory, len(f.Tools))
	var bad []string
	for name, cat := range f.Tools {
		c := capability.ToolCategory(cat)
		if !knownCategories[c] {
			bad = append(bad, fmt.Sprintf("%s=%q", name, cat))
			continue
		}
		mapped[name] = c
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		return nil, fmt.Errorf("tool registry %s has unknown categories: %v (known: %s)",
			path, bad, knownCategoryList())
	}

	return capability.NewRegistry(mapped), nil
}

func knownCategoryList() string {
	out := make([]string, 0, len(knownCategories))
	for c := range knownCategories {
		out = append(out, string(c))
	}
	sort.Strings(out)
	return fmt.Sprint(out)
}
