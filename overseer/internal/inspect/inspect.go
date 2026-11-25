// Package inspect defines what it means to examine one direction of a turn,
// and runs the examiners.
//
// It is a package of its own rather than part of gateway so that inspector
// implementations can live beside the interface they satisfy. With the seam in
// gateway, every inspector would import gateway while gateway imported them.
package inspect

import (
	"context"
	"strconv"
	"time"

	"github.com/google/uuid"

	"openclaw/guard/overseer/internal/capability"
	"openclaw/guard/overseer/internal/session"
)

// ToolCall is a provider-neutral view of a call the model asked for.
//
// Deliberately not gateway's wire type. An inspector judges "the model wants to
// run `delete_everything` with these arguments" — a question that does not
// depend on whether the provider spells it tools[].function.name or something
// else. Keeping the wire format on one side of this boundary is also what stops
// a second provider from rippling into every inspector.
type ToolCall struct {
	Name      string
	Arguments string
}

// Turn is one message in a conversation.
type Turn struct {
	Role string // "user", "assistant", "system"
	Text string
}

// Subject is the thing being inspected: one direction of one turn.
type Subject struct {
	SessionID uuid.UUID
	RequestID uuid.UUID
	Direction session.Direction

	// Content is the text to judge. Inbound this is the user's prompt;
	// outbound it is the assistant's reply.
	Content string

	// Conversation is the exchange so far, oldest first, excluding Content.
	//
	// Roles are kept because context changes the verdict: a classifier reading
	// only the user's words cannot see an attack split across turns, and an
	// instruction that looks innocent alone can be the second half of one that
	// was not. Deriving everything from the request rather than from stored
	// state is what keeps inspectors free of their own persistence — nothing to
	// cache, nothing to expire, nothing to get stale.
	//
	// Empty is a valid answer and means "first turn", not "no history".
	Conversation []Turn

	// ToolCalls is populated outbound only.
	ToolCalls []ToolCall
}

// PriorUserText returns the user's earlier turns, oldest first.
//
// Derived rather than carried as its own field, so there is one source of
// truth. Two fields that must agree are two fields that can disagree.
//
// Only user turns: "is this message unusually large" is a question about how
// long this person's messages normally are, and the model's replies measure
// something else.
func (s Subject) PriorUserText() []string {
	var out []string
	for _, t := range s.Conversation {
		if t.Role == "user" {
			out = append(out, t.Text)
		}
	}
	return out
}

// directionOutbound mirrors session.Outbound without importing it for a
// constant; inspect already depends on session for the Direction type.
const directionOutbound = session.Outbound

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
	// Name identifies this inspector, and MUST be one of the
	// capability.Source constants.
	//
	// It is not a label. Findings and failures are filed under it in
	// guardrail_violations.violation_source, which carries a foreign key to the
	// violation_sources table, so a free-form name is rejected at write time
	// and the evidence for that request is lost. Adding an inspector means
	// adding its Source constant and a row in that table, in a migration.
	Name() string
	Inspect(ctx context.Context, s Subject) (Verdict, error)
}

// Mode controls how much authority one inspector has over the decision.
//
// Mode is deployment configuration, not a property of the inspector, so the
// same implementation can be enforcing in one environment and shadowed in
// another without touching its code. That is what lets a new detector run
// beside an incumbent on identical traffic and be compared before it is
// trusted.
//
// ModeEnforce is the zero value deliberately. A forgotten Mode therefore
// counts, which is the restrictive direction — the same reasoning that made
// ConfidenceUnspecified fail closed. Silently not enforcing a detector someone
// believed was live is the worse failure.
type Mode int

const (
	// ModeEnforce: signals count toward the decision, and an error floors the
	// request.
	ModeEnforce Mode = iota
	// ModeShadow: the inspector runs and its findings are recorded, but they do
	// not influence the tier and its failures do not floor anything. Adding a
	// shadowed detector cannot degrade service.
	ModeShadow
	// ModeOff: not run at all.
	ModeOff
)

func (m Mode) String() string {
	switch m {
	case ModeEnforce:
		return "enforce"
	case ModeShadow:
		return "shadow"
	case ModeOff:
		return "off"
	default:
		return "mode(" + strconv.Itoa(int(m)) + ")"
	}
}

// Registered pairs an inspector with the authority it has been given.
type Registered struct {
	Inspector Inspector
	Mode      Mode
}

// Enforcing is a convenience for the common case.
func Enforcing(i Inspector) Registered { return Registered{Inspector: i, Mode: ModeEnforce} }

// Shadowing runs an inspector for comparison only.
func Shadowing(i Inspector) Registered { return Registered{Inspector: i, Mode: ModeShadow} }

// Result records what one inspector did, for logging and metrics.
type Result struct {
	Inspector string
	Mode      Mode
	Signals   []capability.Signal
	Err       error
	Duration  time.Duration
	TimedOut  bool
}

// Counted reports whether this result influenced the decision. Shadow results
// are recorded in the audit trail with Counted false, which is what makes a
// later comparison possible.
func (r Result) Counted() bool { return r.Mode == ModeEnforce }

// Outcome is the joined result of every inspector.
type Outcome struct {
	// Signals is what the ENFORCING inspectors detected, to be fed to
	// capability.Policy.Decide. Shadow findings are deliberately absent: they
	// appear in Results so they can be recorded and compared, and nowhere else.
	Signals []capability.Signal

	// Floor is a request-scoped restriction applied because an inspector could
	// not answer. It is NEVER persisted: "the guard is unavailable" is not
	// evidence about the user, and writing it down would make an outage follow
	// people across sessions.
	Floor capability.Tier

	Results []Result
}

// RunInspectors runs every registered inspector concurrently under one shared
// deadline and joins the results.
//
// Concurrency is the point: the heuristics are sub-millisecond and the semantic
// gate is a network round trip, so running them in series would make the fast
// one free and the slow one the whole budget. One deadline covers the set, not
// each member.
//
// Authority follows Mode. An enforcing inspector that errors or does not finish
// in time contributes unavailableFloor — the fail-closed path, without which an
// attacker disables the guard by loading the inference service until it stops
// answering. A shadowed inspector contributes nothing either way: its findings
// are recorded for comparison and its failures are not the request's problem,
// which is what makes adding one safe.
func RunInspectors(
	ctx context.Context,
	budget time.Duration,
	unavailableFloor capability.Tier,
	subject Subject,
	registered ...Registered,
) Outcome {
	out := Outcome{Floor: capability.TierFull}

	active := make([]Registered, 0, len(registered))
	for _, r := range registered {
		if r.Mode != ModeOff && r.Inspector != nil {
			active = append(active, r)
		}
	}
	if len(active) == 0 {
		return out
	}

	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	results := make(chan Result, len(active))
	for _, r := range active {
		go func(r Registered) {
			started := time.Now()
			v, err := r.Inspector.Inspect(ctx, subject)
			results <- Result{
				Inspector: r.Inspector.Name(),
				Mode:      r.Mode,
				Signals:   v.Signals,
				Err:       err,
				Duration:  time.Since(started),
			}
		}(r)
	}

	// Read results until every active inspector has reported or the budget
	// expires. Selecting on ctx.Done rather than waiting on a WaitGroup means an
	// inspector that ignores cancellation delays its own goroutine, not the
	// response.
	seen := map[string]bool{}
	for range active {
		select {
		case r := <-results:
			seen[r.Inspector] = true
			out.Results = append(out.Results, r)
			if r.Err != nil {
				if r.Counted() {
					out.Floor = capability.Stricter(out.Floor, unavailableFloor)
				}
				continue
			}
			if r.Counted() {
				out.Signals = append(out.Signals, r.Signals...)
			}
		case <-ctx.Done():
			for _, r := range active {
				if seen[r.Inspector.Name()] {
					continue
				}
				out.Results = append(out.Results, Result{
					Inspector: r.Inspector.Name(),
					Mode:      r.Mode,
					Err:       ctx.Err(),
					Duration:  budget,
					TimedOut:  true,
				})
				if r.Mode == ModeEnforce {
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
