package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/jackc/pgx/v5/pgxpool"

	"openclaw/guard/overseer/internal/auth"
	"openclaw/guard/overseer/internal/capability"
	"openclaw/guard/overseer/internal/dbtest"
	"openclaw/guard/overseer/internal/inspect"
	"openclaw/guard/overseer/internal/session"
)

type fakeAuth struct {
	user auth.User
	err  error
}

func (f fakeAuth) WhoIs(*http.Request) (auth.User, error) { return f.user, f.err }

// recorder stands in for the provider and remembers what it was sent.
type recorder struct {
	mu       sync.Mutex
	calls    int
	lastBody []byte
	lastAuth string
	status   int
	respBody string
	header   http.Header
}

func (rec *recorder) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rec.mu.Lock()
		rec.calls++
		rec.lastBody, _ = io.ReadAll(r.Body)
		rec.lastAuth = r.Header.Get("Authorization")
		status, body, hdr := rec.status, rec.respBody, rec.header
		rec.mu.Unlock()

		for k, vs := range hdr {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
		if body == "" {
			body = `{"id":"chatcmpl-1","object":"chat.completion","choices":[]}`
		}
		_, _ = w.Write([]byte(body))
	}
}

func (rec *recorder) seen() (int, []byte, string) {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return rec.calls, rec.lastBody, rec.lastAuth
}

type harness struct {
	gw    *Gateway
	rec   *recorder
	store session.Store
	pool  *pgxpool.Pool
	user  auth.User
	logs  *syncBuffer
}

// syncBuffer collects log output for assertions. The handler logs from the
// request goroutine, so reads need the lock.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func newHarness(t *testing.T, inspectors ...inspect.Registered) *harness {
	t.Helper()
	pool, _ := dbtest.Pool(t)

	rec := &recorder{header: http.Header{}}
	upstream := httptest.NewServer(rec.handler())
	t.Cleanup(upstream.Close)

	logs := &syncBuffer{}
	user := auth.User{ID: "alice", Verified: true}
	store := session.NewPostgresStore(pool)

	gw, err := New(Deps{
		Auth:     fakeAuth{user: user},
		Sessions: store,
		Registry: capability.NewRegistry(map[string]capability.ToolCategory{
			"web_search": capability.CatWebSearch,
		}),
		Policy: capability.DefaultPolicy(),
		Upstream: &Upstream{
			BaseURL: upstream.URL,
			APIKey:  "sk-gateway-secret",
			Client:  &http.Client{Timeout: 10 * time.Second},
		},
		Log:              slog.New(slog.NewJSONHandler(logs, nil)),
		Inspectors:       inspectors,
		InspectBudget:    500 * time.Millisecond,
		UnavailableFloor: capability.TierQuarantined,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return &harness{gw: gw, rec: rec, store: store, pool: pool, user: user, logs: logs}
}

func (h *harness) post(t *testing.T, body string, hdr http.Header) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer client-token-should-not-leak")
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	w := httptest.NewRecorder()
	h.gw.Handler().ServeHTTP(w, req)
	return w
}

const simpleBody = `{"model":"llama3","messages":[{"role":"user","content":"hi"}],"temperature":0.3}`

// Criteria 1 and 11: a request reaches upstream semantically unchanged, and the
// response carries a request id.
func TestGateway_ForwardsTransparently(t *testing.T) {
	h := newHarness(t)
	w := h.post(t, simpleBody, nil)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get(HeaderRequestID); got == "" {
		t.Error("no request id on the response")
	} else if _, err := uuid.Parse(got); err != nil {
		t.Errorf("request id %q is not a uuid", got)
	}
	if got := w.Header().Get(HeaderSessionID); got == "" {
		t.Error("no session id on the response")
	}

	calls, body, _ := h.rec.seen()
	if calls != 1 {
		t.Fatalf("upstream called %d times", calls)
	}
	var sent, original map[string]any
	if err := json.Unmarshal(body, &sent); err != nil {
		t.Fatalf("upstream received invalid JSON: %v", err)
	}
	_ = json.Unmarshal([]byte(simpleBody), &original)
	for k, v := range original {
		if got, ok := sent[k]; !ok {
			t.Errorf("field %q was dropped on the way upstream", k)
		} else if !jsonEqual(got, v) {
			t.Errorf("field %q changed: %v -> %v", k, v, got)
		}
	}
}

// Criterion 2: the client's own credential must never reach the provider.
func TestGateway_SendsItsOwnKeyUpstream(t *testing.T) {
	h := newHarness(t)
	h.post(t, simpleBody, nil)

	_, _, authHeader := h.rec.seen()
	if authHeader != "Bearer sk-gateway-secret" {
		t.Errorf("upstream Authorization = %q, want the gateway's key", authHeader)
	}
	if strings.Contains(authHeader, "client-token") {
		t.Error("the client's token was forwarded upstream")
	}
}

// Criterion 3: upstream status and body reach the client; hop-by-hop headers
// do not.
func TestGateway_PassesUpstreamErrorsThrough(t *testing.T) {
	h := newHarness(t)
	h.rec.status = http.StatusTooManyRequests
	h.rec.respBody = `{"error":{"message":"slow down"}}`
	h.rec.header.Set("Connection", "close")
	h.rec.header.Set("X-Ratelimit-Remaining", "0")

	w := h.post(t, simpleBody, nil)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("status = %d, want the upstream's 429", w.Code)
	}
	if !strings.Contains(w.Body.String(), "slow down") {
		t.Errorf("upstream error body was replaced: %s", w.Body.String())
	}
	if w.Header().Get("X-Ratelimit-Remaining") != "0" {
		t.Error("a useful upstream header was dropped")
	}
	if w.Header().Get("Connection") != "" {
		t.Error("a hop-by-hop header was forwarded")
	}
}

// Criterion 4.
func TestGateway_RejectsStreaming(t *testing.T) {
	h := newHarness(t)
	w := h.post(t, `{"model":"m","messages":[],"stream":true}`, nil)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "streaming") {
		t.Errorf("error does not explain the problem: %s", w.Body.String())
	}
	if calls, _, _ := h.rec.seen(); calls != 0 {
		t.Error("a streaming request reached upstream")
	}
}

// Criterion 5.
func TestGateway_RejectsUnauthenticated(t *testing.T) {
	h := newHarness(t)
	h.gw.d.Auth = fakeAuth{err: errors.New("no token")}

	w := h.post(t, simpleBody, nil)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
	if calls, _, _ := h.rec.seen(); calls != 0 {
		t.Error("an unauthenticated request reached upstream")
	}
	if w.Header().Get(HeaderRequestID) == "" {
		t.Error("a rejected request has no id to trace")
	}
}

func TestGateway_RejectsMalformedBody(t *testing.T) {
	h := newHarness(t)
	w := h.post(t, `{"model": `, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	if calls, _, _ := h.rec.seen(); calls != 0 {
		t.Error("a malformed request reached upstream")
	}
}

// The session persists across requests when the client echoes the header back.
func TestGateway_ReusesTheSessionAcrossRequests(t *testing.T) {
	h := newHarness(t)

	first := h.post(t, simpleBody, nil)
	id := first.Header().Get(HeaderSessionID)
	if id == "" {
		t.Fatal("no session id issued")
	}

	hdr := http.Header{}
	hdr.Set(HeaderSessionID, id)
	second := h.post(t, simpleBody, hdr)

	if got := second.Header().Get(HeaderSessionID); got != id {
		t.Errorf("session id = %q on the second request, want %q", got, id)
	}
}

// Criterion 10, part two: an unavailable inspector restricts the request but
// must not be written to the session. Otherwise an outage follows the user.
func TestGateway_InspectorFailureIsNotPersisted(t *testing.T) {
	h := newHarness(t, inspect.Enforcing(inspect.StubInspector{InspectorName: "down", Err: errors.New("unreachable")}))

	w := h.post(t, simpleBody, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: a quarantine floor must not fail the request in phase 3", w.Code)
	}
	id := uuid.MustParse(w.Header().Get(HeaderSessionID))

	reloaded, err := h.store.LoadOrCreate(t.Context(), id, h.user)
	if err != nil {
		t.Fatalf("reloading session: %v", err)
	}
	if reloaded.Tier != capability.TierFull {
		t.Errorf("stored tier = %s, want %s: an availability failure was persisted",
			reloaded.Tier, capability.TierFull)
	}
	if reloaded.RiskScore != 0 {
		t.Errorf("stored risk = %d, want 0", reloaded.RiskScore)
	}
}

// A blocked session never reaches the provider.
func TestGateway_BlockedSessionNeverContactsUpstream(t *testing.T) {
	h := newHarness(t, inspect.Enforcing(inspect.StubInspector{InspectorName: "down", Err: errors.New("unreachable")}))
	h.gw.d.UnavailableFloor = capability.TierBlocked

	w := h.post(t, simpleBody, nil)

	if calls, _, _ := h.rec.seen(); calls != 0 {
		t.Error("a blocked request was forwarded upstream")
	}
	if w.Code != http.StatusOK {
		t.Errorf("status = %d: a refusal is an answer, not an error", w.Code)
	}
	var parsed ChatResponse
	if err := json.Unmarshal(w.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("refusal body is not a chat completion: %v", err)
	}
	if len(parsed.Choices) != 1 || parsed.Choices[0].Message.Text() != RefusalText {
		t.Errorf("unexpected refusal body: %s", w.Body.String())
	}
}

func jsonEqual(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

// ---------------------------------------------------------------------------
// Wiring the inspectors into the request path.
// ---------------------------------------------------------------------------

// capturing records the Subject it was handed, so a test can assert what the
// gateway actually passed down.
type capturing struct {
	mu   sync.Mutex
	seen []inspect.Subject
}

func (c *capturing) Name() string { return "capturing" }

func (c *capturing) Inspect(_ context.Context, s inspect.Subject) (inspect.Verdict, error) {
	c.mu.Lock()
	c.seen = append(c.seen, s)
	c.mu.Unlock()
	return inspect.Verdict{}, nil
}

func (c *capturing) last() (inspect.Subject, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.seen) == 0 {
		return inspect.Subject{}, false
	}
	return c.seen[len(c.seen)-1], true
}

// The token-spike check needs a baseline, and the baseline is the conversation
// already in the request. If the gateway does not pass the earlier turns, that
// detector is inert no matter what anyone sends.
func TestGateway_PassesConversationHistoryToInspectors(t *testing.T) {
	cap := &capturing{}
	h := newHarness(t, inspect.Enforcing(cap))

	body := `{"model":"m","messages":[
		{"role":"user","content":"first question"},
		{"role":"assistant","content":"an answer"},
		{"role":"user","content":"second question"},
		{"role":"assistant","content":"another answer"},
		{"role":"user","content":"the latest one"}]}`

	if w := h.post(t, body, nil); w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}

	got, ok := cap.last()
	if !ok {
		t.Fatal("the inspector was never called")
	}
	if got.Content != "the latest one" {
		t.Errorf("Content = %q, want the most recent user turn", got.Content)
	}
	// The whole exchange reaches the inspector, roles intact: a classifier
	// reading only the user's words cannot see an attack split across turns.
	if len(got.Conversation) != 4 {
		t.Fatalf("Conversation = %v, want the four turns before the latest", got.Conversation)
	}
	if got.Conversation[0].Role != "user" || got.Conversation[0].Text != "first question" {
		t.Errorf("Conversation[0] = %+v, want the oldest user turn", got.Conversation[0])
	}
	if got.Conversation[1].Role != "assistant" {
		t.Errorf("Conversation[1] = %+v, want the assistant reply kept", got.Conversation[1])
	}

	// The spike baseline is derived from it rather than carried separately.
	prior := got.PriorUserText()
	if len(prior) != 2 || prior[0] != "first question" || prior[1] != "second question" {
		t.Errorf("PriorUserText() = %v, want the two earlier user turns", prior)
	}
	if got.SessionID == uuid.Nil || got.RequestID == uuid.Nil {
		t.Error("the Subject carries no session or request id")
	}
	if got.Direction != session.Inbound {
		t.Errorf("Direction = %q, want INBOUND", got.Direction)
	}
}

// Decay must be measured from risk_updated_at, not updated_at.
//
// This session has blocked-level risk earned ten hours ago, on a row written to
// a moment ago. Decayed from the risk baseline it is spent and the request
// proceeds; decayed from the last write it is untouched and the user is blocked
// on risk that should have expired.
func TestGateway_DecaysRiskFromTheRiskBaseline(t *testing.T) {
	h := newHarness(t)
	h.gw.d.EnforceDecisions = true

	id := session.NewID()
	if _, err := h.pool.Exec(t.Context(), `
		INSERT INTO session_states
			(session_id, user_id, current_tier, risk_score, created_at, updated_at, risk_updated_at)
		VALUES ($1, $2, 0, 120, now() - interval '10 hours', now(), now() - interval '10 hours')`,
		id, h.user.ID); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	hdr := http.Header{}
	hdr.Set(HeaderSessionID, id.String())
	w := h.post(t, simpleBody, hdr)

	if calls, _, _ := h.rec.seen(); calls == 0 {
		t.Error("the request was blocked on risk that should have decayed: " +
			"decay is being measured from updated_at rather than risk_updated_at")
	}
	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}
}

// With enforcement off, a detection must change nothing: not the stored tier,
// and not this request either. The thresholds are placeholders, and acting on
// them would restrict real people on numbers nobody has validated.
func TestGateway_DetectionDoesNotEnforceWhenDisabled(t *testing.T) {
	loud := inspect.StubInspector{
		InspectorName: "loud",
		Signals: []capability.Signal{{
			Source: capability.SourceFastRegex, Weight: 500,
			Confidence: capability.ConfidenceHigh, Code: "test",
		}},
	}
	h := newHarness(t, inspect.Enforcing(loud))
	h.gw.d.EnforceDecisions = false

	w := h.post(t, simpleBody, nil)

	if calls, _, _ := h.rec.seen(); calls != 1 {
		t.Errorf("upstream calls = %d, want 1: a detection blocked a request with enforcement off", calls)
	}
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}

	id := uuid.MustParse(w.Header().Get(HeaderSessionID))
	reloaded, err := h.store.LoadOrCreate(t.Context(), id, h.user)
	if err != nil {
		t.Fatalf("reloading: %v", err)
	}
	if reloaded.Tier != capability.TierFull {
		t.Errorf("stored tier = %s, want %s: a detection was persisted with enforcement off",
			reloaded.Tier, capability.TierFull)
	}
}

// The floor is not a detection. "The guard is unreachable" is a known bad
// state, so it restricts the request whatever EnforceDecisions says.
func TestGateway_FloorAppliesEvenWithEnforcementDisabled(t *testing.T) {
	down := inspect.StubInspector{InspectorName: "down", Err: errors.New("unreachable")}
	h := newHarness(t, inspect.Enforcing(down))
	h.gw.d.EnforceDecisions = false
	h.gw.d.UnavailableFloor = capability.TierBlocked

	w := h.post(t, simpleBody, nil)

	if calls, _, _ := h.rec.seen(); calls != 0 {
		t.Error("the floor did not restrict the request")
	}
	if w.Code != http.StatusOK {
		t.Errorf("status = %d: a refusal is an answer, not an error", w.Code)
	}
}

// decisionTierFromLogs pulls the tier out of the "decision computed" record.
func decisionTierFromLogs(t *testing.T, raw string) string {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		if rec["msg"] == "decision computed" {
			tier, _ := rec["decision_tier"].(string)
			return tier
		}
	}
	t.Fatalf("no \"decision computed\" record in the logs:\n%s", raw)
	return ""
}

// The floor must never reach Policy.Decide.
//
// An unreachable inspector restricts the request in hand, but it is not
// evidence about the user. Feeding it in as `cur` would make the decision
// inherit it — and once enforcement is on, that decision is persisted and the
// outage becomes a permanent fact about someone who did nothing. That is the
// failure carrying risk rather than tier was meant to end.
//
// It is invisible in the response, because the floor produces the same
// restriction either way. The decision itself is the only place the difference
// shows, so this reads it from the log.
func TestGateway_FloorDoesNotContaminateTheDecision(t *testing.T) {
	down := inspect.StubInspector{InspectorName: "down", Err: errors.New("unreachable")}
	h := newHarness(t, inspect.Enforcing(down))
	h.gw.d.EnforceDecisions = true
	h.gw.d.UnavailableFloor = capability.TierQuarantined

	if w := h.post(t, simpleBody, nil); w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}

	if got := decisionTierFromLogs(t, h.logs.String()); got != capability.TierFull.String() {
		t.Errorf("decision tier = %q, want %q: the availability floor was fed into Decide "+
			"and would be persisted as evidence about the user",
			got, capability.TierFull.String())
	}
}

// The converse: a real detection does reach the decision.
func TestGateway_SignalsReachTheDecision(t *testing.T) {
	loud := inspect.StubInspector{
		InspectorName: "loud",
		Signals: []capability.Signal{{
			Source: capability.SourceFastRegex, Weight: 500,
			Confidence: capability.ConfidenceHigh, Code: "test",
		}},
	}
	h := newHarness(t, inspect.Enforcing(loud))

	if w := h.post(t, simpleBody, nil); w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}

	if got := decisionTierFromLogs(t, h.logs.String()); got != capability.TierBlocked.String() {
		t.Errorf("decision tier = %q, want %q: a weight-500 high-confidence signal "+
			"did not reach Decide", got, capability.TierBlocked.String())
	}
}

// ---------------------------------------------------------------------------
// Recording evidence.
// ---------------------------------------------------------------------------

type violationRow struct {
	Source   string
	Raw      *string
	Expiry   *time.Time
	Metadata map[string]any
}

func (h *harness) violations(t *testing.T, sessionID uuid.UUID) []violationRow {
	t.Helper()
	rows, err := h.pool.Query(t.Context(), `
		SELECT violation_source, raw_content, raw_content_expires_at, metadata
		  FROM guardrail_violations WHERE session_id = $1 ORDER BY id`, sessionID)
	if err != nil {
		t.Fatalf("querying violations: %v", err)
	}
	defer rows.Close()

	var out []violationRow
	for rows.Next() {
		var v violationRow
		var meta []byte
		if err := rows.Scan(&v.Source, &v.Raw, &v.Expiry, &meta); err != nil {
			t.Fatalf("scanning: %v", err)
		}
		if len(meta) > 0 {
			_ = json.Unmarshal(meta, &v.Metadata)
		}
		out = append(out, v)
	}
	return out
}

func loudInspector(name string, src capability.Source, weight int) inspect.StubInspector {
	return inspect.StubInspector{
		InspectorName: name,
		Signals: []capability.Signal{{
			Source: src, Weight: weight,
			Confidence: capability.ConfidenceHigh, Code: "test-rule",
		}},
	}
}

// A detection is recorded even though enforcement is off. That record is the
// entire output of this phase.
func TestGateway_RecordsDetections(t *testing.T) {
	h := newHarness(t, inspect.Enforcing(loudInspector(string(capability.SourceFastRegex), capability.SourceFastRegex, 40)))

	w := h.post(t, simpleBody, nil)
	id := uuid.MustParse(w.Header().Get(HeaderSessionID))

	rows := h.violations(t, id)
	if len(rows) != 1 {
		t.Fatalf("violation rows = %d, want 1", len(rows))
	}
	if rows[0].Source != string(capability.SourceFastRegex) {
		t.Errorf("source = %q", rows[0].Source)
	}
	if rows[0].Metadata["confidence"] != "high" {
		t.Errorf("confidence = %v, want the string form", rows[0].Metadata["confidence"])
	}
	if rows[0].Metadata["enforced"] != false {
		t.Errorf("enforced = %v, want false", rows[0].Metadata["enforced"])
	}
	// The counterfactual: the applied columns are NULL, so without this the
	// record cannot say what would have happened.
	if rows[0].Metadata["proposed_to"] == nil {
		t.Error("the record does not say what the decision would have been")
	}
}

// Shadow findings must be recorded and distinguishable, or comparing a
// candidate detector against the incumbent is impossible.
func TestGateway_RecordsShadowFindingsSeparately(t *testing.T) {
	h := newHarness(t,
		inspect.Enforcing(loudInspector(string(capability.SourceFastRegex), capability.SourceFastRegex, 40)),
		inspect.Shadowing(loudInspector(string(capability.SourceLlamaGuard), capability.SourceLlamaGuard, 90)),
	)

	w := h.post(t, simpleBody, nil)
	id := uuid.MustParse(w.Header().Get(HeaderSessionID))

	rows := h.violations(t, id)
	if len(rows) != 2 {
		t.Fatalf("violation rows = %d, want 2", len(rows))
	}
	modes := map[string]string{}
	for _, r := range rows {
		modes[r.Source], _ = r.Metadata["mode"].(string)
	}
	if modes[string(capability.SourceFastRegex)] != "enforce" {
		t.Errorf("live inspector recorded as %q", modes[string(capability.SourceFastRegex)])
	}
	if modes[string(capability.SourceLlamaGuard)] != "shadow" {
		t.Errorf("shadowed inspector recorded as %q: the two cannot be told apart",
			modes[string(capability.SourceLlamaGuard)])
	}
}

// An unreachable inspector is recorded, so a later reader can tell "no verdict
// because the gate was down" from "no verdict because it was clean". Without
// that distinction a corpus row is unusable.
func TestGateway_RecordsInspectorFailures(t *testing.T) {
	down := inspect.StubInspector{InspectorName: string(capability.SourceLlamaGuard), Err: errors.New("connection refused")}
	h := newHarness(t, inspect.Enforcing(down))

	w := h.post(t, simpleBody, nil)
	id := uuid.MustParse(w.Header().Get(HeaderSessionID))

	rows := h.violations(t, id)
	if len(rows) != 1 {
		t.Fatalf("violation rows = %d, want 1", len(rows))
	}
	if rows[0].Metadata["error"] == nil {
		t.Error("the failure was recorded without saying what went wrong")
	}
}

// With capture off, a clean request writes nothing. Three rows per request
// forever is a permanent cost for a bounded exercise.
func TestGateway_CleanRequestWritesNothingWithoutCapture(t *testing.T) {
	h := newHarness(t, inspect.Enforcing(inspect.StubInspector{InspectorName: string(capability.SourceEntropy)}))
	h.gw.d.CaptureRawContent = false

	w := h.post(t, simpleBody, nil)
	id := uuid.MustParse(w.Header().Get(HeaderSessionID))

	if rows := h.violations(t, id); len(rows) != 0 {
		t.Errorf("%d rows written for a clean request with capture off", len(rows))
	}
}

// With capture on, clean verdicts ARE recorded — a false-positive rate cannot
// be computed from positives alone.
func TestGateway_CaptureRecordsCleanVerdictsAndRawContent(t *testing.T) {
	h := newHarness(t, inspect.Enforcing(inspect.StubInspector{InspectorName: string(capability.SourceEntropy)}))
	h.gw.d.CaptureRawContent = true
	h.gw.d.RawContentRetention = 48 * time.Hour

	w := h.post(t, simpleBody, nil)
	id := uuid.MustParse(w.Header().Get(HeaderSessionID))

	rows := h.violations(t, id)
	if len(rows) != 1 {
		t.Fatalf("violation rows = %d, want 1 clean verdict", len(rows))
	}
	if rows[0].Metadata["clean"] != true {
		t.Errorf("metadata does not mark the verdict clean: %v", rows[0].Metadata)
	}
	if rows[0].Raw == nil {
		t.Error("capture is on but no raw content was stored")
	}
	if rows[0].Expiry == nil {
		t.Error("raw content stored with no expiry")
	}
}

// A blocked request is the most interesting kind. Recording has to happen
// before the tier-3 early return or it leaves no trace at all.
func TestGateway_BlockedRequestStillRecords(t *testing.T) {
	down := inspect.StubInspector{InspectorName: string(capability.SourceLlamaGuard), Err: errors.New("unreachable")}
	h := newHarness(t, inspect.Enforcing(down))
	h.gw.d.UnavailableFloor = capability.TierBlocked

	w := h.post(t, simpleBody, nil)
	if calls, _, _ := h.rec.seen(); calls != 0 {
		t.Fatal("a blocked request reached upstream")
	}
	id := uuid.MustParse(w.Header().Get(HeaderSessionID))

	if rows := h.violations(t, id); len(rows) == 0 {
		t.Error("a blocked request left no evidence behind")
	}
}

// All of a turn's rows share one request_id, which is what makes "what did each
// detector say about this prompt" answerable.
func TestGateway_EvidenceSharesOneRequestID(t *testing.T) {
	h := newHarness(t,
		inspect.Enforcing(loudInspector(string(capability.SourceFastRegex), capability.SourceFastRegex, 10)),
		inspect.Enforcing(loudInspector(string(capability.SourceEntropy), capability.SourceEntropy, 10)),
	)

	w := h.post(t, simpleBody, nil)
	id := uuid.MustParse(w.Header().Get(HeaderSessionID))

	var distinct int
	if err := h.pool.QueryRow(t.Context(),
		`SELECT count(DISTINCT request_id) FROM guardrail_violations WHERE session_id = $1`,
		id).Scan(&distinct); err != nil {
		t.Fatalf("counting: %v", err)
	}
	if distinct != 1 {
		t.Errorf("distinct request_ids = %d, want 1", distinct)
	}
	if got := w.Header().Get(HeaderRequestID); got == "" {
		t.Error("the response carries no request id to correlate with")
	}
}
