package capability

import (
	"fmt"
	"time"
)

// Policy is the tunable part of the capability engine.
type Policy struct {
	Thresholds Thresholds
	HalfLife   time.Duration
}

// DefaultPolicy returns placeholder tuning. See DefaultThresholds.
func DefaultPolicy() Policy {
	return Policy{Thresholds: DefaultThresholds, HalfLife: 30 * time.Minute}
}

// Decision is the result of one evaluation. It carries its own reasoning so the
// audit log can record why a session was demoted, not merely that it was.
type Decision struct {
	From       Tier
	To         Tier
	RiskBefore int
	RiskAfter  int
	Reasons    []string
}

// Demoted reports whether this decision cost the session capability.
func (d Decision) Demoted() bool { return d.To > d.From }

// Decide evaluates a session against new signals and returns its resulting
// tier. It is pure: identical inputs, including now, always produce an
// identical Decision.
//
// Invariants, each covered by a test in engine_test.go:
//
//  1. Ratchet — To is never less than From.
//  2. TierBlocked is absorbing.
//  3. Signals that are all low-confidence cannot demote past TierConstrained.
//  4. Risk decays before thresholds are applied, and never goes negative.
//  5. An invalid incoming tier is treated as blocked, not as full.
func (p Policy) Decide(cur Tier, score int, last time.Time, sigs []Signal, now time.Time) Decision {
	if !cur.Valid() {
		// Corrupt stored state must not be read as "unrestricted".
		cur = TierBlocked
	}

	d := Decision{From: cur, RiskBefore: score}

	if cur == TierBlocked {
		d.To = TierBlocked
		d.RiskAfter = clampScore(score)
		d.Reasons = []string{"tier 3 is absorbing; no further evaluation"}
		return d
	}

	decayed := Decay(score, last, now, p.HalfLife)
	if decayed != score {
		d.Reasons = append(d.Reasons, fmt.Sprintf("risk decayed %d -> %d", score, decayed))
	}

	delta := 0
	allLow := len(sigs) > 0
	for _, s := range sigs {
		w := s.Weight
		if w < 0 {
			// A signal is evidence of risk; it must never reduce it.
			w = 0
		}
		delta += w
		if s.Confidence != ConfidenceLow {
			allLow = false
		}
		d.Reasons = append(d.Reasons, fmt.Sprintf("%s%s +%d", s.Source, codeSuffix(s.Code), w))
	}

	d.RiskAfter = clampScore(decayed + delta)

	candidate := p.Thresholds.TierFor(d.RiskAfter)
	if allLow && candidate > TierConstrained {
		candidate = TierConstrained
		d.Reasons = append(d.Reasons, "capped at constrained: all signals were low-confidence")
	}

	d.To = stricter(cur, candidate)
	if candidate < cur {
		d.Reasons = append(d.Reasons,
			fmt.Sprintf("ratchet held tier at %s (score alone justified %s)", cur, candidate))
	}
	return d
}

func codeSuffix(code string) string {
	if code == "" {
		return ""
	}
	return "(" + code + ")"
}
