package gateway

import (
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

	"openclaw/guard/overseer/internal/auth"
	"openclaw/guard/overseer/internal/capability"
	"openclaw/guard/overseer/internal/dbtest"
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
	user  auth.User
}

func newHarness(t *testing.T, inspectors ...Inspector) *harness {
	t.Helper()
	pool, _ := dbtest.Pool(t)

	rec := &recorder{header: http.Header{}}
	upstream := httptest.NewServer(rec.handler())
	t.Cleanup(upstream.Close)

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
		Log:              slog.New(slog.NewTextHandler(io.Discard, nil)),
		Inspectors:       inspectors,
		InspectBudget:    500 * time.Millisecond,
		UnavailableFloor: capability.TierQuarantined,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return &harness{gw: gw, rec: rec, store: store, user: user}
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
	h := newHarness(t, StubInspector{InspectorName: "down", Err: errors.New("unreachable")})

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
	h := newHarness(t, StubInspector{InspectorName: "down", Err: errors.New("unreachable")})
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
