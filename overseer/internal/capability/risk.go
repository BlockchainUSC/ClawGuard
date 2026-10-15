package capability

import (
	"math"
	"time"
)

// MaxRiskScore bounds the cumulative score so that a stream of large-weight
// signals cannot overflow or make decay take geological time.
const MaxRiskScore = 10_000

// Source identifies which inspection layer produced a signal. Values match the
// violation_source CHECK constraint in migrations/0001_init.sql.
type Source string

const (
	SourceFastRegex     Source = "FAST_REGEX"
	SourceEntropy       Source = "ENTROPY"
	SourceTokenSpike    Source = "TOKEN_SPIKE"
	SourceLlamaGuard    Source = "LLAMA_GUARD_3"
	SourceToolValidator Source = "TOOL_VALIDATOR"
)

// Confidence separates noisy heuristics from confirmed verdicts.
//
// Entropy and token-spike checks fire on base64 payloads, but also on minified
// JavaScript, UUIDs and ordinary pasted code. Because demotion is a ratchet
// that never recovers, letting those signals quarantine a session on their own
// would mean one pasted code block permanently degrading a legitimate user.
// Low-confidence signals therefore accumulate risk but cannot, alone, push a
// session past TierConstrained.
type Confidence int

const (
	ConfidenceLow Confidence = iota
	ConfidenceHigh
)

// Signal is one piece of evidence produced by an inspection layer.
type Signal struct {
	Source     Source
	Code       string // Llama Guard taxonomy code, e.g. "S13". Optional.
	Weight     int    // Risk contribution. Negative weights are clamped to zero.
	Confidence Confidence
}

// Thresholds are the cumulative risk scores at which each tier takes effect.
type Thresholds struct {
	Constrained int
	Quarantined int
	Blocked     int
}

// DefaultThresholds are placeholders. They are arbitrary until Phase 4 produces
// real signal volume to calibrate against.
var DefaultThresholds = Thresholds{Constrained: 30, Quarantined: 60, Blocked: 100}

// TierFor maps a risk score onto the tier it justifies.
func (t Thresholds) TierFor(score int) Tier {
	switch {
	case score >= t.Blocked:
		return TierBlocked
	case score >= t.Quarantined:
		return TierQuarantined
	case score >= t.Constrained:
		return TierConstrained
	default:
		return TierFull
	}
}

// Decay applies exponential decay to a risk score with the given half-life.
//
// Decay is computed on read from the elapsed time since the last update, which
// avoids a background job: a session's score is correct whenever it is next
// looked at. now is a parameter rather than a clock read so that decay is
// deterministic under test.
//
// A non-positive elapsed time (clock skew, or a replayed event) leaves the
// score unchanged rather than increasing it.
func Decay(score int, last, now time.Time, halfLife time.Duration) int {
	if score <= 0 {
		return 0
	}
	if halfLife <= 0 {
		return ClampScore(score)
	}
	elapsed := now.Sub(last)
	if elapsed <= 0 {
		return ClampScore(score)
	}
	factor := math.Pow(0.5, elapsed.Seconds()/halfLife.Seconds())
	return ClampScore(int(math.Round(float64(score) * factor)))
}

// ClampScore holds a risk score inside [0, MaxRiskScore].
//
// Exported because the bound is a storage invariant as well as an arithmetic
// one: the risk_score CHECK constraint in migrations/0001_init.sql rejects
// anything outside the same range, so a caller that recomputes a score before
// writing it must clamp it the same way this package does.
func ClampScore(v int) int {
	if v < 0 {
		return 0
	}
	if v > MaxRiskScore {
		return MaxRiskScore
	}
	return v
}
