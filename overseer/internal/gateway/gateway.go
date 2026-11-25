package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"openclaw/guard/overseer/internal/auth"
	"openclaw/guard/overseer/internal/capability"
	"openclaw/guard/overseer/internal/inspect"
	"openclaw/guard/overseer/internal/session"
)

// HeaderRequestID is echoed on every response, including errors, so any
// behaviour a user reports can be found in the logs.
const HeaderRequestID = "X-Request-Id"

// HeaderSessionID carries the session a client wishes to continue.
//
// A client-supplied id is safe here only because of two guarantees established
// in phase 2: session.LoadOrCreate rejects a session belonging to another user,
// and a brand-new session inherits carried-forward risk. Rotating the header
// therefore buys an attacker nothing. Without both, this header would be the
// bypass.
const HeaderSessionID = "X-Session-Id"

// Deps are the gateway's collaborators.
type Deps struct {
	Auth     auth.Authenticator
	Sessions session.Store
	Registry *capability.Registry
	Policy   capability.Policy
	Upstream *Upstream
	Log      *slog.Logger

	// Inspectors run on every inbound request, each with the authority its
	// Mode grants. Empty until phase 4 supplies implementations.
	Inspectors []inspect.Registered

	// InspectBudget covers the whole inspection phase, not each inspector.
	InspectBudget time.Duration

	// UnavailableFloor is applied when an inspector cannot answer. It restricts
	// the request in hand and is never persisted.
	UnavailableFloor capability.Tier

	// EnforceDecisions controls whether a signal-driven demotion is persisted.
	//
	// False — the default — computes and logs the decision without calling
	// session.Apply. The thresholds are placeholders until an evaluation corpus
	// can say what the false-positive rate is, and a false positive restricts a
	// real person, so detection ships before enforcement does.
	//
	// The zero value being "do not enforce" is the one place in this codebase
	// where the permissive default is correct: enforcing with uncalibrated
	// thresholds harms users, while not enforcing only delays protection that
	// does not work yet.
	EnforceDecisions bool

	// CaptureRawContent stores the inspected text verbatim and records clean
	// verdicts as well as findings. Both are needed to build an evaluation
	// corpus; neither is wanted permanently.
	CaptureRawContent bool

	// RawContentRetention stamps an expiry on captured text. Raw content is
	// never written without one.
	RawContentRetention time.Duration
}

type Gateway struct{ d Deps }

func New(d Deps) (*Gateway, error) {
	switch {
	case d.Auth == nil:
		return nil, errors.New("gateway: Auth is required")
	case d.Sessions == nil:
		return nil, errors.New("gateway: Sessions is required")
	case d.Upstream == nil:
		return nil, errors.New("gateway: Upstream is required")
	case d.Registry == nil:
		return nil, errors.New("gateway: Registry is required")
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.InspectBudget <= 0 {
		d.InspectBudget = 2 * time.Second
	}
	if d.Policy.Thresholds == (capability.Thresholds{}) {
		// A zero Policy puts every threshold at zero, so TierFor returns
		// TierBlocked for any score at all and every request is refused. That
		// fails closed, but as a total outage with no explanation.
		d.Policy = capability.DefaultPolicy()
	}
	if !d.UnavailableFloor.Valid() {
		// Fail closed: an unset floor must not mean "no restriction".
		d.UnavailableFloor = capability.TierQuarantined
	}
	return &Gateway{d: d}, nil
}

func (g *Gateway) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/chat/completions", g.handleChat)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	return mux
}

func (g *Gateway) handleChat(w http.ResponseWriter, r *http.Request) {
	requestID := uuid.New()
	w.Header().Set(HeaderRequestID, requestID.String())
	log := g.d.Log.With("request_id", requestID)

	user, err := g.d.Auth.WhoIs(r)
	if err != nil {
		// Deliberately uniform: "no credentials" and "bad credentials" produce
		// the same response, so the endpoint is not an oracle for which tokens
		// exist. The distinction is in the log, where only an operator sees it.
		log.Info("rejected", "reason", "authentication", "err", err)
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	log = log.With("user", user.ID, "identity_verified", user.Verified)

	var req ChatRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBytes)).Decode(&req); err != nil {
		log.Info("rejected", "reason", "malformed body", "err", err)
		writeError(w, http.StatusBadRequest, "request body is not a valid chat completion: "+err.Error())
		return
	}

	// Streaming is refused rather than quietly buffered. Buffering and
	// re-emitting chunks would cost the whole benefit of streaming while
	// keeping its complexity, and would tell the client something untrue about
	// what happened. See README.md, Decisions.
	if req.Stream {
		log.Info("rejected", "reason", "streaming not supported")
		writeError(w, http.StatusBadRequest,
			"streaming is not supported: retry without \"stream\": true")
		return
	}

	sessionID := requestedSessionID(r)
	sess, err := g.d.Sessions.LoadOrCreate(r.Context(), sessionID, user)
	if err != nil {
		if errors.Is(err, session.ErrSessionNotOwned) {
			// Same response as a session that does not exist, so the endpoint
			// cannot be used to discover which session ids are real.
			log.Warn("rejected", "reason", "session not owned", "session_id", sessionID)
			writeError(w, http.StatusForbidden, "session is not available")
			return
		}
		log.Error("session load failed", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.Header().Set(HeaderSessionID, sess.ID.String())
	log = log.With("session_id", sess.ID, "stored_tier", sess.Tier.String(), "risk", sess.RiskScore)

	outcome := inspect.RunInspectors(r.Context(), g.d.InspectBudget, g.d.UnavailableFloor,
		inspect.Subject{
			SessionID:    sess.ID,
			RequestID:    requestID,
			Direction:    session.Inbound,
			Content:      req.LastUserText(),
			Conversation: req.ConversationBefore(),
		},
		g.d.Inspectors...)

	// What the evidence says this session should be.
	//
	// cur is the STORED tier, never the effective one. The floor is scoped to
	// this request, and feeding it back into a decision that later gets
	// persisted would turn an inference outage into permanent evidence about
	// the user — the failure that carrying risk rather than tier was meant to
	// end.
	//
	// last is RiskUpdatedAt, not UpdatedAt. UpdatedAt moves on any write to the
	// row, so decay measured from it is measured over the wrong interval.
	decision := g.d.Policy.Decide(
		sess.Tier,
		sess.RiskScore,
		sess.RiskUpdatedAt,
		outcome.Signals,
		time.Now(),
	)

	// With enforcement off the decision is computed and logged and changes
	// nothing — not the stored tier, not this request. The thresholds are
	// placeholders until an evaluation corpus can say what the false-positive
	// rate is, and acting on them would restrict real people on the strength of
	// numbers nobody has validated.
	tier := sess.Tier
	if g.d.EnforceDecisions {
		tier = decision.To
	}

	// The floor applies either way. "The guard is unreachable" is a known bad
	// state rather than an uncalibrated guess.
	effective := capability.EffectiveTier(tier, outcome.Floor)
	profile := capability.ProfileFor(effective)

	log = log.With(
		"effective_tier", effective.String(),
		"floor", outcome.Floor.String(),
		"signals", len(outcome.Signals),
		"tools_offered", len(req.Tools),
	)
	// Logged separately rather than folded into the request line: while
	// enforcement is off this is the entire output of the inspection phase, and
	// "would this have demoted someone, and did it actually" is the question
	// the thresholds will be calibrated against.
	log.Info("decision computed",
		"decision_tier", decision.To.String(),
		"risk_after", decision.RiskAfter,
		"signal_delta", decision.SignalDelta,
		"enforced", g.d.EnforceDecisions,
		"reasons", decision.Reasons,
	)

	// Recorded before the tier-3 early return below, or a blocked request —
	// the most interesting kind — would leave no trace at all.
	//
	// A failure here does not fail the request. Nothing was enforced, so there
	// is no safety reason to refuse the user because an audit write did not
	// land. It is logged at error level instead, because silently losing
	// evidence is how a corpus turns out to have holes months later.
	redacted := redactFor(req.LastUserText(), g.d.CaptureRawContent, g.d.RawContentRetention)
	if vs := violationsFrom(outcome, redacted, decision, sess.Tier,
		g.d.EnforceDecisions, g.d.CaptureRawContent); len(vs) > 0 {
		if err := g.d.Sessions.Record(r.Context(), sess.ID, requestID, vs); err != nil {
			log.Error("recording evidence failed", "violations", len(vs), "err", err)
		} else {
			log.Info("evidence recorded", "violations", len(vs), "captured", g.d.CaptureRawContent)
		}
	}

	for _, res := range outcome.Results {
		if res.Err != nil {
			log.Warn("inspector unavailable",
				"inspector", res.Inspector, "timed_out", res.TimedOut, "err", res.Err)
		}
	}

	if effective == capability.TierBlocked {
		// The upstream model is never contacted at tier 3.
		log.Info("blocked", "tier", effective.String())
		writeJSON(w, http.StatusOK, StaticRefusal(req.Model, requestID))
		return
	}

	// Phase 3 enforces nothing: no tool stripping, no model routing, no
	// demotion. The profile is computed and logged so the seam is exercised and
	// observable before anything depends on it.
	_ = profile

	upstreamCtx, cancel := context.WithTimeout(r.Context(), g.d.Upstream.Client.Timeout)
	defer cancel()

	resp, err := g.d.Upstream.Forward(upstreamCtx, req)
	if err != nil {
		log.Error("upstream failed", "err", err)
		writeError(w, http.StatusBadGateway, "upstream request failed")
		return
	}

	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set(HeaderRequestID, requestID.String())
	w.WriteHeader(resp.Status)
	_, _ = w.Write(resp.Body)

	log.Info("forwarded", "upstream_status", resp.Status, "bytes", len(resp.Body))
}

// maxRequestBytes bounds the body a client can make the gateway buffer. Without
// it, a single request can exhaust memory — and the gateway buffers by design,
// since it has to inspect what it forwards.
const maxRequestBytes = 8 << 20 // 8 MiB

// requestedSessionID honours a well-formed X-Session-Id and mints one
// otherwise. A malformed value is replaced rather than rejected: it is not a
// security control (ownership is checked downstream), so failing the request
// would only punish a buggy client.
func requestedSessionID(r *http.Request) uuid.UUID {
	if raw := r.Header.Get(HeaderSessionID); raw != "" {
		if id, err := uuid.Parse(raw); err == nil {
			return id
		}
	}
	return session.NewID()
}

type errorBody struct {
	Error struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error"`
}

// writeError returns an OpenAI-shaped error so client SDKs can parse it.
func writeError(w http.ResponseWriter, status int, msg string) {
	var b errorBody
	b.Error.Message = msg
	b.Error.Type = "openclaw_guard_error"
	writeJSON(w, status, b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
