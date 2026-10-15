package capability

import "testing"

var allTiers = []Tier{TierFull, TierConstrained, TierQuarantined, TierBlocked}

// allCategories is every defined ToolCategory, listed once. A new category that
// is not added here is silently untested at every tier; a new category that is
// added here but left out of the TierFull profile fails
// TestProfile_TierCapabilities, which is the point.
var allCategories = []ToolCategory{
	CatShell, CatSQLExec, CatSQLReadOnly, CatWebSearch, CatFileIO, CatStaticAPI,
}

// Every defined tier maps to exactly one profile, and that profile agrees about
// which tier it is. A mismatch here would route a session under the wrong
// privileges while every log line claimed otherwise.
func TestProfileFor_EveryTierIsDefined(t *testing.T) {
	for _, tier := range allTiers {
		p := ProfileFor(tier)
		if p.Tier() != tier {
			t.Errorf("ProfileFor(%s) returned a profile for %s", tier, p.Tier())
		}
		if p.Name() == "" {
			t.Errorf("ProfileFor(%s) has no name", tier)
		}
		if p.Model() == "" {
			t.Errorf("ProfileFor(%s) has no model route", tier)
		}
	}
	if len(profiles) != len(allTiers) {
		t.Errorf("profile table has %d entries, want %d", len(profiles), len(allTiers))
	}
}

func TestProfileFor_UnknownTierFailsClosed(t *testing.T) {
	for _, bad := range []Tier{-1, 4, 99} {
		if got := ProfileFor(bad); got.Tier() != TierBlocked {
			t.Errorf("ProfileFor(%d) -> %s, want blocked profile", int(bad), got.Tier())
		}
	}
}

// At quarantine and above, tools are stripped entirely.
func TestProfile_QuarantineAndAboveHaveNoTools(t *testing.T) {
	for _, tier := range []Tier{TierQuarantined, TierBlocked} {
		p := ProfileFor(tier)
		if !p.ToolsStripped() {
			t.Errorf("%s does not strip tools", tier)
		}
		if got := p.AllowedCategories(); len(got) != 0 {
			t.Errorf("%s exposes categories %v", tier, got)
		}
		for _, c := range allCategories {
			if p.Allows(c) {
				t.Errorf("%s allows %s", tier, c)
			}
		}
	}
}

func TestProfile_TierCapabilities(t *testing.T) {
	full := ProfileFor(TierFull)
	for _, c := range allCategories {
		if !full.Allows(c) {
			t.Errorf("full tier denies %s", c)
		}
	}
	if full.ReadOnly() {
		t.Error("full tier is marked read-only")
	}

	constrained := ProfileFor(TierConstrained)
	if !constrained.ReadOnly() {
		t.Error("constrained tier is not marked read-only")
	}
	for _, c := range []ToolCategory{CatSQLReadOnly, CatWebSearch, CatStaticAPI} {
		if !constrained.Allows(c) {
			t.Errorf("constrained tier denies %s", c)
		}
	}
	// The whole point of the tier: no write or execute paths.
	for _, c := range []ToolCategory{CatShell, CatSQLExec, CatFileIO} {
		if constrained.Allows(c) {
			t.Errorf("constrained tier allows write/exec category %s", c)
		}
	}
}

// An uninitialised Profile must grant nothing.
func TestProfile_ZeroValueAllowsNothing(t *testing.T) {
	var zero Profile
	for _, c := range []ToolCategory{CatShell, CatSQLExec, CatWebSearch} {
		if zero.Allows(c) {
			t.Errorf("zero Profile allows %s", c)
		}
	}
	if got := zero.AllowedCategories(); len(got) != 0 {
		t.Errorf("zero Profile exposes %v", got)
	}
}

func TestTier_ParseAndString(t *testing.T) {
	for _, tier := range allTiers {
		got, err := ParseTier(int(tier))
		if err != nil {
			t.Errorf("ParseTier(%d) errored: %v", int(tier), err)
		}
		if got != tier {
			t.Errorf("ParseTier(%d) = %s", int(tier), got)
		}
		if tier.String() == "" {
			t.Errorf("tier %d has no string form", int(tier))
		}
	}

	// Invalid input must resolve to blocked, never to full.
	for _, bad := range []int{-1, 4, 99} {
		got, err := ParseTier(bad)
		if err == nil {
			t.Errorf("ParseTier(%d) accepted an invalid tier", bad)
		}
		if got != TierBlocked {
			t.Errorf("ParseTier(%d) failed open to %s", bad, got)
		}
	}
}

func TestEffectiveTier(t *testing.T) {
	cases := []struct {
		name          string
		stored, floor Tier
		want          Tier
	}{
		{"no floor leaves the session alone", TierFull, TierFull, TierFull},
		{"floor restricts an unrestricted session", TierFull, TierQuarantined, TierQuarantined},
		{"floor does not relax a demoted session", TierBlocked, TierConstrained, TierBlocked},
		{"stored wins when stricter", TierQuarantined, TierConstrained, TierQuarantined},
		{"floor wins when stricter", TierConstrained, TierQuarantined, TierQuarantined},
		{"invalid stored fails closed", Tier(99), TierFull, TierBlocked},
		{"invalid floor fails closed", TierFull, Tier(-1), TierBlocked},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := EffectiveTier(c.stored, c.floor); got != c.want {
				t.Errorf("EffectiveTier(%s, %s) = %s, want %s", c.stored, c.floor, got, c.want)
			}
		})
	}
}

// The floor must never be able to make a session less restricted than it is
// stored as — that is the whole reason it is a floor and not an override.
func TestEffectiveTier_NeverRelaxes(t *testing.T) {
	for _, stored := range allTiers {
		for _, floor := range allTiers {
			if got := EffectiveTier(stored, floor); got < stored {
				t.Errorf("EffectiveTier(%s, %s) = %s, which is less restrictive than stored",
					stored, floor, got)
			}
		}
	}
}
