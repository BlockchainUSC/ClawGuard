package capability

import (
	"math/rand/v2"
	"reflect"
	"testing"
	"time"
)

var testNow = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

func randomSignals(rng *rand.Rand) []Signal {
	sources := []Source{SourceFastRegex, SourceEntropy, SourceTokenSpike, SourceLlamaGuard, SourceToolValidator}
	n := rng.IntN(4)
	sigs := make([]Signal, 0, n)
	for i := 0; i < n; i++ {
		sigs = append(sigs, Signal{
			Source:     sources[rng.IntN(len(sources))],
			Weight:     rng.IntN(120) - 20,      // deliberately includes negatives
			Confidence: Confidence(rng.IntN(3)), // includes ConfidenceUnspecified
		})
	}
	return sigs
}

// Invariant 1: the ratchet. No sequence of inputs ever returns capability.
func TestDecide_RatchetNeverPromotes(t *testing.T) {
	p := DefaultPolicy()
	rng := rand.New(rand.NewPCG(1, 2))

	for i := 0; i < 5000; i++ {
		cur := Tier(rng.IntN(4))
		score := rng.IntN(200)
		elapsed := time.Duration(rng.IntN(100000)) * time.Second
		sigs := randomSignals(rng)

		d := p.Decide(cur, score, testNow.Add(-elapsed), sigs, testNow)

		if d.To < d.From {
			t.Fatalf("ratchet violated: from=%s to=%s score=%d elapsed=%s signals=%+v",
				d.From, d.To, score, elapsed, sigs)
		}
		if d.RiskAfter < 0 {
			t.Fatalf("negative risk %d from score=%d signals=%+v", d.RiskAfter, score, sigs)
		}
		if d.RiskAfter > MaxRiskScore {
			t.Fatalf("risk %d exceeds cap %d", d.RiskAfter, MaxRiskScore)
		}
	}
}

// Invariant 2: TierBlocked is absorbing.
func TestDecide_BlockedIsAbsorbing(t *testing.T) {
	p := DefaultPolicy()
	rng := rand.New(rand.NewPCG(3, 4))

	for i := 0; i < 1000; i++ {
		d := p.Decide(TierBlocked, rng.IntN(200), testNow.Add(-time.Duration(rng.IntN(1e6))*time.Second),
			randomSignals(rng), testNow)
		if d.To != TierBlocked {
			t.Fatalf("blocked session escaped to %s", d.To)
		}
	}

	// Decay cannot release a blocked session either, however long it waits.
	d := p.Decide(TierBlocked, 500, testNow.Add(-365*24*time.Hour), nil, testNow)
	if d.To != TierBlocked {
		t.Fatalf("blocked session escaped after a year of decay: %s", d.To)
	}
}

// Invariant 3: low-confidence signals alone cannot quarantine.
func TestDecide_LowConfidenceCannotExceedConstrained(t *testing.T) {
	p := DefaultPolicy()

	// A single enormous low-confidence signal: far past the Blocked threshold.
	huge := []Signal{{Source: SourceEntropy, Weight: 5000, Confidence: ConfidenceLow}}
	d := p.Decide(TierFull, 0, testNow, huge, testNow)
	if d.To != TierConstrained {
		t.Fatalf("low-confidence signal demoted to %s, want %s", d.To, TierConstrained)
	}

	// Many low-confidence signals, still capped.
	var many []Signal
	for i := 0; i < 50; i++ {
		many = append(many, Signal{Source: SourceTokenSpike, Weight: 40, Confidence: ConfidenceLow})
	}
	if got := p.Decide(TierFull, 0, testNow, many, testNow).To; got != TierConstrained {
		t.Fatalf("50 low-confidence signals demoted to %s, want %s", got, TierConstrained)
	}

	// One high-confidence signal in the mix lifts the cap.
	mixed := append([]Signal{{Source: SourceLlamaGuard, Code: "S13", Weight: 100, Confidence: ConfidenceHigh}}, many...)
	if got := p.Decide(TierFull, 0, testNow, mixed, testNow).To; got != TierBlocked {
		t.Fatalf("high-confidence signal was capped: got %s, want %s", got, TierBlocked)
	}
}

// Invariant 4: decay is monotonic, bounded, and never negative.
func TestDecay_MonotonicAndBounded(t *testing.T) {
	const half = 30 * time.Minute
	prev := Decay(100, testNow, testNow, half)
	if prev != 100 {
		t.Fatalf("zero elapsed changed score: %d", prev)
	}

	for mins := 1; mins <= 600; mins++ {
		got := Decay(100, testNow, testNow.Add(time.Duration(mins)*time.Minute), half)
		if got > prev {
			t.Fatalf("decay increased at %d min: %d > %d", mins, got, prev)
		}
		if got < 0 {
			t.Fatalf("decay went negative at %d min: %d", mins, got)
		}
		prev = got
	}
	if prev != 0 {
		t.Fatalf("score %d had not decayed to zero after 10 hours at a 30m half-life", prev)
	}
}

func TestDecay_EdgeCases(t *testing.T) {
	t.Run("clock skew does not increase risk", func(t *testing.T) {
		if got := Decay(50, testNow, testNow.Add(-time.Hour), 30*time.Minute); got != 50 {
			t.Fatalf("got %d, want 50", got)
		}
	})
	t.Run("non-positive half-life disables decay", func(t *testing.T) {
		if got := Decay(50, testNow, testNow.Add(time.Hour), 0); got != 50 {
			t.Fatalf("got %d, want 50", got)
		}
	})
	t.Run("one half-life halves the score", func(t *testing.T) {
		if got := Decay(100, testNow, testNow.Add(30*time.Minute), 30*time.Minute); got != 50 {
			t.Fatalf("got %d, want 50", got)
		}
	})
}

// Invariant 4 (cont.): Decide is pure — same inputs, same output.
func TestDecide_IsDeterministic(t *testing.T) {
	p := DefaultPolicy()
	sigs := []Signal{
		{Source: SourceLlamaGuard, Code: "S2", Weight: 35, Confidence: ConfidenceHigh},
		{Source: SourceEntropy, Weight: 5, Confidence: ConfidenceLow},
	}
	last := testNow.Add(-17 * time.Minute)

	a := p.Decide(TierFull, 20, last, sigs, testNow)
	b := p.Decide(TierFull, 20, last, sigs, testNow)
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("Decide is not deterministic:\n a = %+v\n b = %+v", a, b)
	}
}

// Invariant 5: corrupt stored state fails closed, not open.
func TestDecide_InvalidTierFailsClosed(t *testing.T) {
	p := DefaultPolicy()
	for _, bad := range []Tier{-1, 4, 99} {
		d := p.Decide(bad, 0, testNow, nil, testNow)
		if d.To != TierBlocked {
			t.Fatalf("invalid tier %d resolved to %s, want %s", int(bad), d.To, TierBlocked)
		}
	}
}

func TestDecide_NegativeWeightsCannotReduceRisk(t *testing.T) {
	p := DefaultPolicy()
	d := p.Decide(TierFull, 50, testNow, []Signal{
		{Source: SourceFastRegex, Weight: -1000, Confidence: ConfidenceHigh},
	}, testNow)
	if d.RiskAfter != 50 {
		t.Fatalf("negative weight changed risk 50 -> %d", d.RiskAfter)
	}
}

func TestDecide_ThresholdBoundaries(t *testing.T) {
	p := DefaultPolicy()
	cases := []struct {
		score int
		want  Tier
	}{
		{0, TierFull}, {29, TierFull},
		{30, TierConstrained}, {59, TierConstrained},
		{60, TierQuarantined}, {99, TierQuarantined},
		{100, TierBlocked}, {5000, TierBlocked},
	}
	for _, c := range cases {
		sig := []Signal{{Source: SourceLlamaGuard, Weight: c.score, Confidence: ConfidenceHigh}}
		if got := p.Decide(TierFull, 0, testNow, sig, testNow).To; got != c.want {
			t.Errorf("score %d -> %s, want %s", c.score, got, c.want)
		}
	}
}

func TestDecision_RecordsReasoning(t *testing.T) {
	p := DefaultPolicy()
	d := p.Decide(TierFull, 0, testNow, []Signal{
		{Source: SourceLlamaGuard, Code: "S13", Weight: 70, Confidence: ConfidenceHigh},
	}, testNow)

	if !d.Demoted() {
		t.Fatal("expected demotion")
	}
	if len(d.Reasons) == 0 {
		t.Fatal("demotion recorded no reasoning; the audit log would say what but never why")
	}
}

// A Signal whose Confidence was never set must NOT be treated as a noisy
// heuristic. The low-confidence cap is a concession to false positives from
// entropy and token-spike checks; a caller that forgot the field has made no
// such claim, and guessing "low" on their behalf silently under-enforces.
func TestDecide_UnsetConfidenceDoesNotEarnTheLowConfidenceCap(t *testing.T) {
	p := DefaultPolicy()

	forgotten := []Signal{{Source: SourceLlamaGuard, Code: "S13", Weight: 500}}
	explicit := []Signal{{Source: SourceLlamaGuard, Code: "S13", Weight: 500, Confidence: ConfidenceHigh}}

	got := p.Decide(TierFull, 0, testNow, forgotten, testNow)
	want := p.Decide(TierFull, 0, testNow, explicit, testNow)

	if got.To != want.To {
		t.Errorf("omitting Confidence gave tier %s, explicit high gave %s: "+
			"a forgotten field silently reduced enforcement", got.To, want.To)
	}
	if got.To != TierBlocked {
		t.Errorf("tier = %s, want %s", got.To, TierBlocked)
	}

	// And an explicit low-confidence signal must still be capped.
	low := []Signal{{Source: SourceEntropy, Weight: 500, Confidence: ConfidenceLow}}
	if capped := p.Decide(TierFull, 0, testNow, low, testNow); capped.To != TierConstrained {
		t.Errorf("explicit low-confidence gave %s, want %s", capped.To, TierConstrained)
	}
}
