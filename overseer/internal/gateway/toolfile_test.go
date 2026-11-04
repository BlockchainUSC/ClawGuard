package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"openclaw/guard/overseer/internal/capability"
)

func writeRegistry(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tools.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing registry: %v", err)
	}
	return path
}

func TestLoadToolRegistry_Valid(t *testing.T) {
	path := writeRegistry(t, `{"tools":{
		"run_shell":"shell",
		"sql_select":"sql_readonly",
		"web_search":"web_search"
	}}`)

	reg, err := LoadToolRegistry(path)
	if err != nil {
		t.Fatalf("LoadToolRegistry: %v", err)
	}

	full := capability.ProfileFor(capability.TierFull)
	if !reg.Permitted(full, "run_shell") {
		t.Error("run_shell not permitted at the full tier")
	}
	constrained := capability.ProfileFor(capability.TierConstrained)
	if constrained.Allows(capability.CatShell) {
		t.Error("constrained tier allows shell")
	}
	// Default-deny still holds for anything the file did not mention.
	if reg.Permitted(full, "not_in_file") {
		t.Error("a tool absent from the registry was permitted")
	}
}

// Criterion 6: a bad registry fails at boot.
//
// An unknown category leaves its tool unclassified, and an unclassified tool is
// denied — so a one-character typo silently removes a capability from every
// session and presents as a model regression. It has to be loud, and it has to
// be at startup.
func TestLoadToolRegistry_RejectsBadFiles(t *testing.T) {
	cases := []struct {
		name, body, wantIn string
	}{
		{"unknown category", `{"tools":{"x":"shel"}}`, "unknown categories"},
		{"empty", `{"tools":{}}`, "defines no tools"},
		{"not json", `tools: shell`, "parsing"},
		{"unexpected field", `{"tools":{"x":"shell"},"oops":1}`, "parsing"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := LoadToolRegistry(writeRegistry(t, c.body))
			if err == nil {
				t.Fatalf("%s was accepted", c.name)
			}
			if !strings.Contains(err.Error(), c.wantIn) {
				t.Errorf("error %q does not mention %q", err, c.wantIn)
			}
		})
	}
}

func TestLoadToolRegistry_MissingFile(t *testing.T) {
	_, err := LoadToolRegistry(filepath.Join(t.TempDir(), "absent.json"))
	if err == nil {
		t.Fatal("a missing registry file was accepted")
	}
	if !strings.Contains(err.Error(), "reading tool registry") {
		t.Errorf("error %q does not say what it failed to read", err)
	}
}

// The error must name every bad entry, not just the first, so one boot fixes
// one file rather than one typo.
func TestLoadToolRegistry_ReportsEveryBadEntry(t *testing.T) {
	_, err := LoadToolRegistry(writeRegistry(t,
		`{"tools":{"a":"shel","b":"sql_readonly","c":"filio"}}`))
	if err == nil {
		t.Fatal("accepted")
	}
	for _, want := range []string{"a=", "c="} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q omits %s", err, want)
		}
	}
	if strings.Contains(err.Error(), "b=") {
		t.Errorf("error %q blames a valid entry", err)
	}
}
