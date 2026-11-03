package inspect

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"time"
)

// PreviewMax bounds content_preview. The database enforces the same number, so
// exceeding it is an insert error rather than a truncation — the bound exists
// so the PII containment this table is built around is enforced rather than
// merely intended.
const PreviewMax = 512

// ErrNotImplemented marks the gaps still to be written.
var ErrNotImplemented = errors.New("inspect: not implemented yet")

// Redacted is the durable record of a piece of content.
//
// The hash and preview are permanent; Raw is optional and expires. That split
// is the whole retention design: an audit trail that keeps every offending
// prompt forever becomes the system of record for exactly the material it
// exists to catch.
type Redacted struct {
	SHA256  string
	Preview string

	// Raw is nil unless capture is enabled. Populated while building an
	// evaluation corpus, off in ordinary operation.
	Raw *string

	// ExpiresAt is set whenever Raw is, so a retention sweep has something to
	// find. Raw without an expiry is a leak with no deadline.
	ExpiresAt *time.Time
}

// Hash returns the SHA-256 of content as lowercase hexadecimal.
//
// TODO(jonah): yours.
//
// The database constrains this column to `^[0-9a-f]{64}$`, so the encoding is
// not cosmetic — uppercase hex is rejected at insert time, and a content hash
// with two possible spellings stops being useful for grouping or deduplication.
//
//	crypto/sha256 gives you the digest; encoding/hex gives you the string.
//	Both default to the form you want. The empty string has a valid hash, and
//	should return it rather than "".
//
// redact_test.go is the specification.
func Hash(content string) string {

	data := []byte(content)
	hash := sha256.Sum256(data)
	hashString := hex.EncodeToString(hash[:])

	return hashString
}

// redactionRules mask things that must not survive in a permanent record.
//
// Order matters: the list is applied in sequence, so a more specific pattern
// has to come before a broader one that would eat part of its match. A
// sixteen-digit card number redacted by a ten-digit rule first leaves six
// digits exposed, which is worse than not matching at all.
//
// Every rule errs toward over-matching. A preview exists to recognise a pattern
// later, not to reconstruct the input, so a redacted innocent string costs
// legibility while a missed secret costs containment.
//
// Deliberately absent: a generic "long high-entropy blob" rule. Unrecognisable
// density is the entropy inspector's job, and duplicating it here would mean
// two places to tune and two places to be wrong.
var redactionRules = []struct {
	Name        string
	Pattern     *regexp.Regexp
	Replacement string
}{
	{
		Name:        "email",
		Pattern:     regexp.MustCompile(`(?i)\b[\w.+-]+@[\w-]+\.[\w.-]+\b`),
		Replacement: "[redacted:email]",
	},
	{
		// The token charset is wider than \w: real bearer tokens contain dots,
		// dashes and slashes, and stopping at the first one leaves most of the
		// secret in the record.
		Name:        "bearer-token",
		Pattern:     regexp.MustCompile(`(?i)\bbearer\s+[\w\-._~+/=]+`),
		Replacement: "[redacted:token]",
	},
	{
		// Recognisable key shapes: AWS access keys, sk-/pk- prefixed keys,
		// GitHub tokens.
		Name: "api-key",
		Pattern: regexp.MustCompile(
			`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|\b(?:sk|pk|rk)-[\w\-]{12,}\b|\bgh[pousr]_[A-Za-z0-9]{20,}\b`),
		Replacement: "[redacted:key]",
	},
	{
		// A secret named by its assignment, whatever its shape.
		Name: "secret-assignment",
		Pattern: regexp.MustCompile(
			`(?i)\b(?:api[_-]?key|secret|token|password|passwd|pwd|key)\b\s*[:=]\s*\S+`),
		Replacement: "[redacted:secret]",
	},
	{
		Name:        "ssn",
		Pattern:     regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
		Replacement: "[redacted:ssn]",
	},
	{
		// Card-shaped runs, with or without separators. Before the generic
		// digit rule so a card is never half-redacted.
		Name:        "card-number",
		Pattern:     regexp.MustCompile(`\b(?:\d[ -]?){12,18}\d\b`),
		Replacement: "[redacted:card]",
	},
	{
		// Phone and account numbers.
		Name:        "long-digits",
		Pattern:     regexp.MustCompile(`\b\d{9,}\b`),
		Replacement: "[redacted:digits]",
	},
}

// Preview returns a bounded, redacted rendering of content, safe to keep
// indefinitely.
//
// Redaction runs before truncation on purpose. Truncating first could cut a
// token in half and leave its first thirty characters sitting in the preview,
// which is a partial secret rather than no secret.
//
// A short preview is returned unchanged: the absence of a truncation marker
// already says "this is all of it", and annotating it would mean the preview no
// longer matches what was actually sent.
func Preview(content string) string {
	for _, rule := range redactionRules {
		// ReplaceAllString is already a no-op when nothing matches, so there is
		// nothing to test for first.
		content = rule.Pattern.ReplaceAllString(content, rule.Replacement)
	}

	runes := []rune(content)
	if len(runes) <= PreviewMax {
		return content
	}

	// PreviewMax-1 so the ellipsis fits inside the budget rather than pushing
	// the result one rune over it. The database enforces the same bound, so an
	// off-by-one here is an insert error, not a cosmetic one.
	return string(runes[:PreviewMax-1]) + "…"
}

// Redact assembles the durable record for one piece of content.
//
// now is a parameter rather than a clock read, matching the discipline in
// capability: anything time-dependent stays deterministic under test.
//
// TODO(jonah): yours, once Hash and Preview are working.
//
//	capture false -> Raw and ExpiresAt both nil.
//	capture true  -> Raw points at content, ExpiresAt is now.Add(retention).
//
// Raw must never be set without an expiry.
func Redact(content string, capture bool, retention time.Duration, now time.Time) Redacted {

	if capture {
		raw := content
		expiresAt := now.Add(retention)
		return Redacted{
			SHA256:    Hash(content),
			Preview:   Preview(content),
			Raw:       &raw,
			ExpiresAt: &expiresAt,
		}
	} else {
		return Redacted{
			SHA256:  Hash(content),
			Preview: Preview(content),
		}
	}
}
