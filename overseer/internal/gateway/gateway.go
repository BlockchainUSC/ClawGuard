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
			SessionID: sess.ID,
			RequestID: requestID,
			Direction: session.Inbound,
			Content:   req.LastUserText(),
		},
		g.d.Inspectors...)

	// The floor restricts this request only. It is never handed to
	// session.Apply, because "the guard is unavailable" is not evidence about
	// the user and must not follow them to their next session.
	effective := capability.EffectiveTier(sess.Tier, outcome.Floor)
	profile := capability.ProfileFor(effective)

	log = log.With(
		"effective_tier", effective.String(),
		"floor", outcome.Floor.String(),
		"signals", len(outcome.Signals),
		"tools_offered", len(req.Tools),
	)
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
