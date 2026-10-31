package inspect

import (
	"errors"
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
	return ""
}

// Preview returns a bounded, redacted rendering of content, safe to keep
// indefinitely.
//
// TODO(jonah): yours.
//
// Two jobs:
//
//  1. Bound it. The result must never exceed PreviewMax runes. Truncate on a
//     rune boundary, not a byte one, or a multi-byte character gets cut in half
//     and the column holds invalid UTF-8. Mark a truncated preview so a reader
//     can tell "this is all of it" from "there was more".
//
//  2. Redact it. Mask things that should not survive in a permanent record even
//     in excerpt: email addresses, bearer tokens and API-key-shaped strings.
//     Replace rather than delete — "[redacted]" tells a future reader something
//     was there, which silence does not.
//
// Err on the side of masking. A preview is for recognising a pattern later, not
// for reconstructing the input; over-redacting costs legibility, under-redacting
// costs the containment the whole table is designed around.
func Preview(content string) string {
	return ""
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
	return Redacted{}
}
