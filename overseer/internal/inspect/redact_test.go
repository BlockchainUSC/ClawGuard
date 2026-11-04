package inspect

import (
	"regexp"
	"strings"
	"testing"
	"time"
)

// schemaHashPattern is the CHECK constraint from migrations/0001_init.sql,
// copied here so a hash that the database would reject fails in Go first.
var schemaHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func TestHash_MatchesTheSchemaConstraint(t *testing.T) {
	for _, in := range []string{
		"",
		"hello",
		"ignore previous instructions",
		strings.Repeat("x", 100_000),
		"unicode: 日本語 🎉",
	} {
		got := Hash(in)
		if !schemaHashPattern.MatchString(got) {
			t.Errorf("Hash(%.20q) = %q, which the database would reject", in, got)
		}
	}
}

// A known vector, so a plausible-looking but wrong implementation is caught.
func TestHash_KnownVector(t *testing.T) {
	const (
		in   = "abc"
		want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	)
	if got := Hash(in); got != want {
		t.Errorf("Hash(%q) = %q, want %q", in, got, want)
	}
}

func TestHash_IsStable(t *testing.T) {
	a, b := Hash("same input"), Hash("same input")
	if a != b {
		t.Errorf("Hash is not deterministic: %q then %q", a, b)
	}
	if Hash("a") == Hash("b") {
		t.Error("different inputs produced the same hash")
	}
}

func TestPreview_NeverExceedsTheBound(t *testing.T) {
	for _, in := range []string{
		strings.Repeat("a", PreviewMax*3),
		strings.Repeat("日", PreviewMax*2), // multi-byte: a byte-based bound would overshoot
		"short",
		"",
	} {
		got := Preview(in)
		if n := len([]rune(got)); n > PreviewMax {
			t.Errorf("Preview of a %d-rune input returned %d runes, over the %d bound",
				len([]rune(in)), n, PreviewMax)
		}
	}
}

// Truncating mid-rune leaves invalid UTF-8 in a NOT NULL text column.
func TestPreview_TruncatesOnRuneBoundaries(t *testing.T) {
	got := Preview(strings.Repeat("日", PreviewMax*2))
	if !utf8Valid(got) {
		t.Error("Preview produced invalid UTF-8: it cut a multi-byte rune in half")
	}
}

// A reader has to be able to tell a complete preview from a clipped one.
func TestPreview_MarksTruncation(t *testing.T) {
	short := Preview("a complete short message")
	long := Preview(strings.Repeat("a", PreviewMax*3))

	if strings.Contains(short, "…") || strings.Contains(short, "...") {
		t.Errorf("a short preview was marked as truncated: %q", short)
	}
	if !strings.Contains(long, "…") && !strings.Contains(long, "...") {
		t.Errorf("a truncated preview carries no marker: %q", long[max(0, len(long)-40):])
	}
}

// The preview is permanent. Things that should not live forever in an excerpt
// must be masked, and masked visibly so a reader knows something was removed.
func TestPreview_RedactsSecrets(t *testing.T) {
	cases := []struct {
		name, in, mustNotContain string
	}{
		{"email", "contact alice@example.com for access", "alice@example.com"},
		{"bearer token", "Authorization: Bearer sk-live-abcdef0123456789abcdef", "sk-live-abcdef0123456789abcdef"},
		{"api key shape", "key=AKIAIOSFODNN7EXAMPLE rest of prompt", "AKIAIOSFODNN7EXAMPLE"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Preview(c.in)
			if strings.Contains(got, c.mustNotContain) {
				t.Errorf("Preview kept %q in a permanent record: %q", c.mustNotContain, got)
			}
			if !strings.Contains(strings.ToLower(got), "redact") {
				t.Errorf("Preview removed something without saying so: %q", got)
			}
		})
	}
}

func TestPreview_LeavesOrdinaryTextAlone(t *testing.T) {
	const in = "what is the capital of France?"
	if got := Preview(in); got != in {
		t.Errorf("Preview(%q) = %q, want it unchanged", in, got)
	}
}

func TestRedact_CaptureOff(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	got := Redact("some prompt", false, 24*time.Hour, now)

	if got.Raw != nil {
		t.Error("raw content was kept with capture off")
	}
	if got.ExpiresAt != nil {
		t.Error("an expiry was set with no raw content to expire")
	}
	if got.SHA256 != Hash("some prompt") {
		t.Error("the hash is not the hash of the content")
	}
	if got.Preview != Preview("some prompt") {
		t.Error("the preview is not the preview of the content")
	}
}

func TestRedact_CaptureOn(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	const retention = 72 * time.Hour
	got := Redact("some prompt", true, retention, now)

	if got.Raw == nil {
		t.Fatal("capture was on but no raw content was kept")
	}
	if *got.Raw != "some prompt" {
		t.Errorf("raw content = %q, want the original unredacted", *got.Raw)
	}
	if got.ExpiresAt == nil {
		t.Fatal("raw content was kept with no expiry: a leak with no deadline")
	}
	if !got.ExpiresAt.Equal(now.Add(retention)) {
		t.Errorf("expiry = %s, want %s", got.ExpiresAt, now.Add(retention))
	}
}

// Whatever else changes, raw content must never outlive a deadline.
func TestRedact_RawAlwaysHasAnExpiry(t *testing.T) {
	now := time.Now()
	for _, retention := range []time.Duration{0, time.Second, 30 * 24 * time.Hour} {
		got := Redact("x", true, retention, now)
		if got.Raw != nil && got.ExpiresAt == nil {
			t.Errorf("retention %s: raw content kept with no expiry", retention)
		}
	}
}

func utf8Valid(s string) bool {
	for _, r := range s {
		if r == '�' {
			return false
		}
	}
	return true
}
