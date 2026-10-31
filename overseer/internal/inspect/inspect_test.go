package inspect

import (
	"context"
	"errors"
	"testing"
	"time"

	"openclaw/guard/overseer/internal/capability"
)

// enf registers inspectors as enforcing, which is what most of these tests
// mean. Mode-specific behaviour is covered by its own tests below.
func enf(is ...Inspector) []Registered {
	out := make([]Registered, 0, len(is))
	for _, i := range is {
		out = append(out, Enforcing(i))
	}
	return out
}

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
		Subject{}, enf(a, b)...)
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
	out := RunInspectors(context.Background(), budget, capability.TierQuarantined, Subject{}, enf(slow)...)
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
		Subject{}, enf(broken, fine)...)

	if out.Floor != capability.TierQuarantined {
		t.Errorf("floor = %s, want %s", out.Floor, capability.TierQuarantined)
	}
	// The working inspector's findings still count.
	if len(out.Signals) != 1 {
		t.Errorf("signals = %d, want 1: a healthy inspector's result was discarded", len(out.Signals))
	}
}

func TestRunInspectors_CleanRunHasNoFloor(t *testing.T) {
	out := RunInspectors(context.Background(), time.Second, capability.TierQuarantined, Subject{}, enf(
		StubInspector{InspectorName: "a"},
		StubInspector{InspectorName: "b",
			Signals: []capability.Signal{sig(capability.SourceEntropy, 5, capability.ConfidenceLow)}})...)

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
	out := RunInspectors(context.Background(), time.Second, capability.TierBlocked, Subject{}, enf(
		StubInspector{InspectorName: "ok"},
		StubInspector{InspectorName: "broken", Err: errors.New("down")})...)

	if out.Floor != capability.TierBlocked {
		t.Errorf("floor = %s, want %s", out.Floor, capability.TierBlocked)
	}
}

// A cancelled parent context must not be reported as a clean inspection.
func TestRunInspectors_CancelledParentFailsClosed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	out := RunInspectors(ctx, time.Second, capability.TierQuarantined, Subject{}, enf(StubInspector{InspectorName: "a", Delay: 50 * time.Millisecond})...)

	if out.Floor != capability.TierQuarantined {
		t.Errorf("floor = %s, want %s: a cancelled request inspected nothing", out.Floor, capability.TierQuarantined)
	}
}

// ---------------------------------------------------------------------------
// Mode: the mechanism that lets a new detector be compared before it is trusted.
// ---------------------------------------------------------------------------

// A shadowed inspector's findings are recorded but must not reach the decision.
// Without this, "run the new detector alongside the old one" is impossible and
// every new detector is a leap of faith.
func TestRunInspectors_ShadowSignalsDoNotCount(t *testing.T) {
	loud := StubInspector{InspectorName: "candidate",
		Signals: []capability.Signal{sig(capability.SourceLlamaGuard, 500, capability.ConfidenceHigh)}}

	out := RunInspectors(context.Background(), time.Second, capability.TierQuarantined,
		Subject{}, Shadowing(loud))

	if len(out.Signals) != 0 {
		t.Errorf("counted signals = %d, want 0: a shadowed inspector influenced the decision", len(out.Signals))
	}
	if len(out.Results) != 1 {
		t.Fatalf("results = %d, want 1: the shadowed finding was not recorded", len(out.Results))
	}
	if out.Results[0].Counted() {
		t.Error("a shadowed result reports itself as counted")
	}
	if len(out.Results[0].Signals) != 1 {
		t.Error("the shadowed inspector's findings were discarded instead of recorded")
	}
}

// A shadowed inspector that is broken must not restrict anyone. Otherwise
// adding a candidate detector can take the service down, and nobody will risk
// adding one.
func TestRunInspectors_ShadowFailureDoesNotFloor(t *testing.T) {
	out := RunInspectors(context.Background(), time.Second, capability.TierBlocked, Subject{},
		Shadowing(StubInspector{InspectorName: "candidate", Err: errors.New("sidecar down")}))

	if out.Floor != capability.TierFull {
		t.Errorf("floor = %s, want %s: a shadowed failure restricted the request", out.Floor, capability.TierFull)
	}
	if len(out.Results) != 1 || out.Results[0].Err == nil {
		t.Error("the shadowed failure was not recorded")
	}
}

// A shadowed inspector timing out must not floor either.
func TestRunInspectors_ShadowTimeoutDoesNotFloor(t *testing.T) {
	out := RunInspectors(context.Background(), 40*time.Millisecond, capability.TierBlocked, Subject{},
		Shadowing(StubInspector{InspectorName: "slow-candidate", Delay: 5 * time.Second}))

	if out.Floor != capability.TierFull {
		t.Errorf("floor = %s, want %s: a shadowed timeout restricted the request", out.Floor, capability.TierFull)
	}
}

// Enforcing and shadowed inspectors in one run: only the enforcing one counts,
// both are recorded. This is the shape of an actual A/B comparison.
func TestRunInspectors_MixedModes(t *testing.T) {
	incumbent := StubInspector{InspectorName: "incumbent",
		Signals: []capability.Signal{sig(capability.SourceFastRegex, 10, capability.ConfidenceHigh)}}
	candidate := StubInspector{InspectorName: "candidate",
		Signals: []capability.Signal{sig(capability.SourceLlamaGuard, 90, capability.ConfidenceHigh)}}

	out := RunInspectors(context.Background(), time.Second, capability.TierQuarantined, Subject{},
		Enforcing(incumbent), Shadowing(candidate))

	if len(out.Signals) != 1 || out.Signals[0].Weight != 10 {
		t.Errorf("counted signals = %+v, want only the incumbent's", out.Signals)
	}
	if len(out.Results) != 2 {
		t.Fatalf("results = %d, want both recorded", len(out.Results))
	}
	var counted, shadowed int
	for _, r := range out.Results {
		if r.Counted() {
			counted++
		} else {
			shadowed++
		}
	}
	if counted != 1 || shadowed != 1 {
		t.Errorf("counted=%d shadowed=%d, want 1 and 1", counted, shadowed)
	}
}

// ModeOff means the inspector is not run at all — no goroutine, no result row.
func TestRunInspectors_OffIsNotRun(t *testing.T) {
	out := RunInspectors(context.Background(), time.Second, capability.TierQuarantined, Subject{},
		Registered{Inspector: StubInspector{InspectorName: "disabled", Err: errors.New("would fail")},
			Mode: ModeOff})

	if len(out.Results) != 0 {
		t.Errorf("results = %+v, want none: a disabled inspector ran", out.Results)
	}
	if out.Floor != capability.TierFull {
		t.Errorf("floor = %s: a disabled inspector restricted the request", out.Floor)
	}
}

// The zero Mode enforces. A forgotten field must not silently disable a
// detector someone believed was protecting them — the same reasoning that made
// ConfidenceUnspecified fail closed rather than reading as low confidence.
func TestRunInspectors_ZeroModeEnforces(t *testing.T) {
	out := RunInspectors(context.Background(), time.Second, capability.TierQuarantined, Subject{},
		Registered{Inspector: StubInspector{InspectorName: "forgotten", Err: errors.New("down")}})

	if out.Floor != capability.TierQuarantined {
		t.Errorf("floor = %s, want %s: an inspector with an unset Mode did not enforce",
			out.Floor, capability.TierQuarantined)
	}
}

// A nil inspector must be skipped rather than panic the request path.
func TestRunInspectors_NilInspectorIsSkipped(t *testing.T) {
	out := RunInspectors(context.Background(), time.Second, capability.TierQuarantined, Subject{},
		Registered{Inspector: nil, Mode: ModeEnforce},
		Enforcing(StubInspector{InspectorName: "real"}))

	if len(out.Results) != 1 || out.Results[0].Inspector != "real" {
		t.Errorf("results = %+v, want only the real inspector", out.Results)
	}
}
