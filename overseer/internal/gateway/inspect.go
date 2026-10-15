package gateway

import (
	"context"
	"time"

	"github.com/google/uuid"

	"openclaw/guard/overseer/internal/capability"
	"openclaw/guard/overseer/internal/session"
)

// Subject is the thing being inspected: one direction of one turn.
type Subject struct {
	SessionID uuid.UUID
	RequestID uuid.UUID
	Direction session.Direction

	// Content is the text to judge. Inbound this is the user's prompt;
	// outbound it is the assistant's reply.
	Content string

	// ToolCalls is populated outbound only.
	ToolCalls []ToolCall
}

// Verdict is what one inspector concluded.
//
// No signals means "nothing found", which is a real answer. An inspector that
// could not reach an answer returns an error instead — the distinction is the
// whole point, because the two must produce different behaviour.
type Verdict struct {
	Signals []capability.Signal
}

// Inspector examines a Subject and reports what it found.
//
// Implementations must not know about tiers, floors, or sessions. They answer
// "what did I detect in this content", and the gateway decides what that means.
// Keeping that line clean is what lets an in-process regex check, a network
// classifier and a future injection detector share one interface.
//
// Inspect must respect ctx. The runner enforces a deadline, but an inspector
// that ignores cancellation holds a goroutine after the request has been
// answered.
type Inspector interface {
	Name() string
	Inspect(ctx context.Context, s Subject) (Verdict, error)
}

// Result records what one inspector did, for logging and metrics.
type Result struct {
	Inspector string
	Signals   []capability.Signal
	Err       error
	Duration  time.Duration
	TimedOut  bool
}

// Outcome is the joined result of every inspector.
type Outcome struct {
	// Signals is everything detected, to be fed to capability.Policy.Decide.
	Signals []capability.Signal

	// Floor is a request-scoped restriction applied because an inspector could
	// not answer. It is NEVER persisted: "the guard is unavailable" is not
	// evidence about the user, and writing it down would make an outage follow
	// people across sessions.
	Floor capability.Tier

	Results []Result
}

// RunInspectors runs every inspector concurrently under one shared deadline and
// joins the results.
//
// Concurrency is the point: the heuristics are sub-millisecond and the semantic
// gate is a network round trip, so running them in series would make the fast
// one free and the slow one the whole budget. One deadline covers the set, not
// each member.
//
// Any inspector that errors or does not finish in time contributes
// unavailableFloor. This is the fail-closed path: a semantic gate that times
// out must restrict the request, or an attacker can disable the guard by
// loading the inference service until it stops answering.
func RunInspectors(
	ctx context.Context,
	budget time.Duration,
	unavailableFloor capability.Tier,
	subject Subject,
	inspectors ...Inspector,
) Outcome {
	out := Outcome{Floor: capability.TierFull}
	if len(inspectors) == 0 {
		return out
	}

	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	results := make(chan Result, len(inspectors))
	for _, in := range inspectors {
		go func(in Inspector) {
			started := time.Now()
			v, err := in.Inspect(ctx, subject)
			results <- Result{
				Inspector: in.Name(),
				Signals:   v.Signals,
				Err:       err,
				Duration:  time.Since(started),
			}
		}(in)
	}

	// Read results until every inspector has reported or the budget expires.
	// Selecting on ctx.Done rather than waiting on a WaitGroup means an
	// inspector that ignores cancellation delays its own goroutine, not the
	// response.
	seen := map[string]bool{}
	for range inspectors {
		select {
		case r := <-results:
			seen[r.Inspector] = true
			out.Results = append(out.Results, r)
			if r.Err != nil {
				out.Floor = capability.Stricter(out.Floor, unavailableFloor)
				continue
			}
			out.Signals = append(out.Signals, r.Signals...)
		case <-ctx.Done():
			for _, in := range inspectors {
				if !seen[in.Name()] {
					out.Results = append(out.Results, Result{
						Inspector: in.Name(),
						Err:       ctx.Err(),
						Duration:  budget,
						TimedOut:  true,
					})
					out.Floor = capability.Stricter(out.Floor, unavailableFloor)
				}
			}
			return out
		}
	}
	return out
}

// StubInspector is a configurable Inspector for tests and for running the
// gateway without a live semantic gate.
//
// It exists in the production tree on purpose: a guardrail whose test suite
// needs a GPU does not get run, and phase 3 has to prove the fan-out works
// before any real inspector exists.
type StubInspector struct {
	InspectorName string
	Signals       []capability.Signal
	Err           error
	Delay         time.Duration
}

func (s StubInspector) Name() string { return s.InspectorName }

func (s StubInspector) Inspect(ctx context.Context, _ Subject) (Verdict, error) {
	if s.Delay > 0 {
		select {
		case <-time.After(s.Delay):
		case <-ctx.Done():
			return Verdict{}, ctx.Err()
		}
	}
	if s.Err != nil {
		return Verdict{}, s.Err
	}
	return Verdict{Signals: s.Signals}, nil
}
