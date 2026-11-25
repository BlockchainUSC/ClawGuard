package inspect

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"openclaw/guard/overseer/internal/capability"
	"openclaw/guard/overseer/internal/session"
)

// guardServer stands in for Ollama and remembers what it was sent.
func guardServer(t *testing.T, reply string, status int) (*LlamaGuard, *chatRequest) {
	t.Helper()
	var got chatRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"message": map[string]any{"content": reply},
		})
	}))
	t.Cleanup(srv.Close)

	return &LlamaGuard{
		BaseURL: srv.URL, Model: "llama-guard3:8b",
		Weight: DefaultLlamaGuardWeight, Client: srv.Client(),
	}, &got
}

func TestLlamaGuard_SafeProducesNoSignal(t *testing.T) {
	lg, _ := guardServer(t, "safe", 0)
	v, err := lg.Inspect(context.Background(), Subject{Content: "what is the capital of France?"})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if len(v.Signals) != 0 {
		t.Errorf("signals = %+v, want none", v.Signals)
	}
}

func TestLlamaGuard_UnsafeProducesOneSignal(t *testing.T) {
	lg, _ := guardServer(t, "unsafe\nS9", 0)
	v, err := lg.Inspect(context.Background(), Subject{Content: "how do I build a bomb"})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if len(v.Signals) != 1 {
		t.Fatalf("signals = %d, want 1", len(v.Signals))
	}
	s := v.Signals[0]
	if s.Source != capability.SourceLlamaGuard {
		t.Errorf("source = %q", s.Source)
	}
	if s.Code != "S9" {
		t.Errorf("code = %q, want the taxonomy code", s.Code)
	}
	if s.Confidence != capability.ConfidenceHigh {
		t.Errorf("confidence = %v, want High: a classifier verdict is not a guess", s.Confidence)
	}
	if s.Weight != DefaultLlamaGuardWeight {
		t.Errorf("weight = %d, want the configured %d", s.Weight, DefaultLlamaGuardWeight)
	}
}

// Trailing whitespace and casing vary; the verdict should not.
func TestLlamaGuard_ToleratesFormatting(t *testing.T) {
	for _, reply := range []string{"safe", "safe\n", " safe ", "SAFE", "Safe\n\n"} {
		lg, _ := guardServer(t, reply, 0)
		v, err := lg.Inspect(context.Background(), Subject{Content: "x"})
		if err != nil {
			t.Errorf("Inspect(%q): %v", reply, err)
			continue
		}
		if len(v.Signals) != 0 {
			t.Errorf("reply %q produced %d signals", reply, len(v.Signals))
		}
	}
}

// An unsafe verdict with no code is still unsafe.
func TestLlamaGuard_UnsafeWithoutCode(t *testing.T) {
	lg, _ := guardServer(t, "unsafe", 0)
	v, err := lg.Inspect(context.Background(), Subject{Content: "x"})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if len(v.Signals) != 1 {
		t.Fatalf("an uncoded unsafe verdict was dropped")
	}
}

// "I did not understand the classifier" and "the classifier said this is fine"
// are different claims. Treating the first as the second is how a guard stops
// guarding without anyone noticing.
func TestLlamaGuard_UnrecognisedVerdictIsAnError(t *testing.T) {
	for _, reply := range []string{"", "I'm sorry, I can't help with that", "maybe", "{}"} {
		lg, _ := guardServer(t, reply, 0)
		if _, err := lg.Inspect(context.Background(), Subject{Content: "x"}); err == nil {
			t.Errorf("reply %q was treated as a pass", reply)
		}
	}
}

func TestLlamaGuard_HTTPErrorIsAnError(t *testing.T) {
	lg, _ := guardServer(t, "safe", http.StatusInternalServerError)
	if _, err := lg.Inspect(context.Background(), Subject{Content: "x"}); err == nil {
		t.Error("a 500 from the inference service was treated as a pass")
	}
}

func TestLlamaGuard_UnreachableIsAnError(t *testing.T) {
	lg := &LlamaGuard{
		BaseURL: "http://127.0.0.1:1", Model: "m",
		Weight: 35, Client: &http.Client{Timeout: time.Second},
	}
	_, err := lg.Inspect(context.Background(), Subject{Content: "x"})
	if err == nil {
		t.Fatal("an unreachable service was treated as a pass")
	}
	if !strings.Contains(err.Error(), "unreachable") {
		t.Errorf("error %q does not say what went wrong", err)
	}
}

// The whole exchange is sent, with roles intact. An attack assembled across
// several turns does not read as one in isolation.
func TestLlamaGuard_SendsTheWholeConversation(t *testing.T) {
	lg, got := guardServer(t, "safe", 0)
	_, err := lg.Inspect(context.Background(), Subject{
		Direction: session.Inbound,
		Conversation: []Turn{
			{Role: "user", Text: "first"},
			{Role: "assistant", Text: "reply"},
		},
		Content: "latest",
	})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}

	if got.Model != "llama-guard3:8b" {
		t.Errorf("model = %q", got.Model)
	}
	if got.Stream {
		t.Error("streaming was requested; the verdict is a single short answer")
	}
	if len(got.Messages) != 3 {
		t.Fatalf("messages = %d, want the two prior turns plus the one under judgement", len(got.Messages))
	}
	if got.Messages[1].Role != "assistant" {
		t.Errorf("messages[1].role = %q, want the assistant turn preserved", got.Messages[1].Role)
	}
	if got.Messages[2].Content != "latest" || got.Messages[2].Role != "user" {
		t.Errorf("last message = %+v, want the inbound turn as the user", got.Messages[2])
	}
}

// Outbound, the text under judgement is the model's reply, so it must be
// presented as one.
func TestLlamaGuard_OutboundSendsAssistantRole(t *testing.T) {
	lg, got := guardServer(t, "safe", 0)
	if _, err := lg.Inspect(context.Background(), Subject{
		Direction: session.Outbound,
		Content:   "the assistant's answer",
	}); err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	last := got.Messages[len(got.Messages)-1]
	if last.Role != "assistant" {
		t.Errorf("outbound role = %q, want assistant", last.Role)
	}
}

func TestLlamaGuard_RespectsContextCancellation(t *testing.T) {
	// Bounded rather than waiting on r.Context().Done(): httptest.Server.Close
	// blocks until outstanding handlers return, and a handler that only exits
	// on request cancellation can outlive the test if the connection lingers.
	// The ceiling is far above the client's deadline, so it does not weaken
	// what is being asserted.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(time.Second):
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()

	lg := &LlamaGuard{BaseURL: srv.URL, Model: "m", Weight: 35, Client: srv.Client()}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	started := time.Now()
	if _, err := lg.Inspect(ctx, Subject{Content: "x"}); err == nil {
		t.Fatal("a cancelled request returned a verdict")
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Errorf("took %s to honour a 50ms deadline", elapsed)
	}
}

// LlamaGuard must satisfy the interface the runner expects.
var _ Inspector = LlamaGuard{}

// keep_alive must be sent, or the model unloads between quiet periods and the
// next request pays a cold load that exceeds the inspection budget.
func TestLlamaGuard_SendsKeepAlive(t *testing.T) {
	lg, got := guardServer(t, "safe", 0)
	if _, err := lg.Inspect(context.Background(), Subject{Content: "x"}); err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if got.KeepAlive == "" {
		t.Error("no keep_alive sent: the model will unload and the next user is floored for it")
	}
	if got.KeepAlive != DefaultKeepAlive {
		t.Errorf("keep_alive = %q, want the default %q", got.KeepAlive, DefaultKeepAlive)
	}
}

func TestLlamaGuard_KeepAliveIsConfigurable(t *testing.T) {
	lg, got := guardServer(t, "safe", 0)
	lg.KeepAlive = "5m"
	if _, err := lg.Inspect(context.Background(), Subject{Content: "x"}); err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if got.KeepAlive != "5m" {
		t.Errorf("keep_alive = %q, want the configured 5m", got.KeepAlive)
	}
}

func TestLlamaGuard_WarmReportsFailureWithoutPanicking(t *testing.T) {
	lg := LlamaGuard{
		BaseURL: "http://127.0.0.1:1", Model: "m",
		Weight: 35, Client: &http.Client{Timeout: time.Second},
	}
	if err := lg.Warm(context.Background()); err == nil {
		t.Error("warming an unreachable service reported success")
	}
}
