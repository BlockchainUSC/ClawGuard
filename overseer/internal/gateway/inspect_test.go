package gateway

import (
	"context"
	"errors"
	"testing"
	"time"

	"openclaw/guard/overseer/internal/capability"
)

func sig(src capability.Source, w int, c capability.Confidence) capability.Signal {
	return capability.Signal{Source: src, Weight: w, Confidence: c}
}

// Criterion 8: inspectors run concurrently, not in series.
//
// This matters because the fast leg is sub-millisecond and the slow one is a
// network round trip. Run in series, the budget is the sum; run together, it is
// the slowest. Breaking the fan-out would still produce correct verdicts, just
// slower — which is exactly the kind of regression nothing notices.
func TestRunInspectors_RunsConcurrently(t *testing.T) {
	const delay = 80 * time.Millisecond
	a := StubInspector{InspectorName: "a", Delay: delay}
	b := StubInspector{InspectorName: "b", Delay: delay}

	started := time.Now()
	out := RunInspectors(context.Background(), time.Second, capability.TierQuarantined,
		Subject{}, a, b)
	elapsed := time.Since(started)

	if out.Floor != capability.TierFull {
		t.Errorf("floor = %s, want %s: nothing failed", out.Floor, capability.TierFull)
	}
	// Serial would be ~160ms. Generous margin, still far below the sum.
	if elapsed > delay+50*time.Millisecond {
		t.Errorf("took %s for two %s inspectors: they ran in series", elapsed, delay)
	}
}

// Criterion 9: a slow inspector cannot hold the response past the budget.
func TestRunInspectors_HonoursTheBudget(t *testing.T) {
	const budget = 60 * time.Millisecond
	slow := StubInspector{InspectorName: "slow", Delay: 5 * time.Second}

	started := time.Now()
	out := RunInspectors(context.Background(), budget, capability.TierQuarantined, Subject{}, slow)
	elapsed := time.Since(started)

	if elapsed > budget+60*time.Millisecond {
		t.Errorf("took %s with a %s budget", elapsed, budget)
	}
	if out.Floor != capability.TierQuarantined {
		t.Errorf("floor = %s, want %s: a timeout must restrict", out.Floor, capability.TierQuarantined)
	}
	if len(out.Results) != 1 || !out.Results[0].TimedOut {
		t.Errorf("results = %+v, want one recorded timeout", out.Results)
	}
}

// Criterion 10, part one: an inspector that cannot answer produces a floor.
//
// This is the fail-closed path. Without it, an attacker takes the guard offline
// by loading the inference service until it stops responding, and every request
// sails through unrestricted.
func TestRunInspectors_ErrorProducesFloor(t *testing.T) {
	broken := StubInspector{InspectorName: "broken", Err: errors.New("connection refused")}
	fine := StubInspector{InspectorName: "fine",
		Signals: []capability.Signal{sig(capability.SourceFastRegex, 10, capability.ConfidenceHigh)}}

	out := RunInspectors(context.Background(), time.Second, capability.TierQuarantined,
		Subject{}, broken, fine)

	if out.Floor != capability.TierQuarantined {
		t.Errorf("floor = %s, want %s", out.Floor, capability.TierQuarantined)
	}
	// The working inspector's findings still count.
	if len(out.Signals) != 1 {
		t.Errorf("signals = %d, want 1: a healthy inspector's result was discarded", len(out.Signals))
	}
}

func TestRunInspectors_CleanRunHasNoFloor(t *testing.T) {
	out := RunInspectors(context.Background(), time.Second, capability.TierQuarantined, Subject{},
		StubInspector{InspectorName: "a"},
		StubInspector{InspectorName: "b",
			Signals: []capability.Signal{sig(capability.SourceEntropy, 5, capability.ConfidenceLow)}})

	if out.Floor != capability.TierFull {
		t.Errorf("floor = %s, want %s", out.Floor, capability.TierFull)
	}
	if len(out.Signals) != 1 {
		t.Errorf("signals = %d, want 1", len(out.Signals))
	}
}

// Phase 3 ships with no inspectors at all; that must not restrict anything.
func TestRunInspectors_NoInspectorsIsNotAFailure(t *testing.T) {
	out := RunInspectors(context.Background(), time.Second, capability.TierQuarantined, Subject{})
	if out.Floor != capability.TierFull {
		t.Errorf("floor = %s, want %s", out.Floor, capability.TierFull)
	}
	if len(out.Signals) != 0 || len(out.Results) != 0 {
		t.Errorf("got signals=%d results=%d, want none", len(out.Signals), len(out.Results))
	}
}

// The floor is the strictest any inspector demanded, never the last one.
func TestRunInspectors_FloorIsStrictest(t *testing.T) {
	out := RunInspectors(context.Background(), time.Second, capability.TierBlocked, Subject{},
		StubInspector{InspectorName: "ok"},
		StubInspector{InspectorName: "broken", Err: errors.New("down")})

	if out.Floor != capability.TierBlocked {
		t.Errorf("floor = %s, want %s", out.Floor, capability.TierBlocked)
	}
}

// A cancelled parent context must not be reported as a clean inspection.
func TestRunInspectors_CancelledParentFailsClosed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	out := RunInspectors(ctx, time.Second, capability.TierQuarantined, Subject{},
		StubInspector{InspectorName: "a", Delay: 50 * time.Millisecond})

	if out.Floor != capability.TierQuarantined {
		t.Errorf("floor = %s, want %s: a cancelled request inspected nothing", out.Floor, capability.TierQuarantined)
	}
}
