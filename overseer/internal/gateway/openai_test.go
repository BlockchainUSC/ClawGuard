package gateway

import (
	"encoding/json"

	"github.com/google/uuid"
	"reflect"
	"testing"
)

// Criterion 1: a request round-trips semantically unchanged.
//
// Byte equality is explicitly NOT the goal — the gateway re-serialises, so key
// order and whitespace may differ. What must survive is every value, including
// fields this version has never heard of.
var testUUID = uuid.MustParse("11111111-2222-3333-4444-555555555555")

func TestChatRequest_RoundTripsUnknownFields(t *testing.T) {
	const body = `{
		"model": "llama3",
		"messages": [{"role":"user","content":"hello"}],
		"tools": [{"type":"function","function":{"name":"web_search","parameters":{"type":"object"}}}],
		"temperature": 0.7,
		"top_p": 0.95,
		"seed": 42,
		"a_field_from_the_future": {"nested": [1, 2, 3]},
		"logit_bias": {"123": -100}
	}`

	var req ChatRequest
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		t.Fatalf("decode: %v", err)
	}

	out, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	var before, after map[string]any
	if err := json.Unmarshal([]byte(body), &before); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(out, &after); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Errorf("request did not survive a round trip\n before: %v\n after:  %v", before, after)
	}
}

// An absent tools field and an empty one mean different things to a provider,
// and phase 5 needs to be able to express both.
func TestChatRequest_DistinguishesAbsentAndEmptyTools(t *testing.T) {
	var absent ChatRequest
	if err := json.Unmarshal([]byte(`{"model":"m","messages":[]}`), &absent); err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(absent)
	var m map[string]any
	_ = json.Unmarshal(out, &m)
	if _, present := m["tools"]; present {
		t.Error("a request with no tools field grew one")
	}

	var empty ChatRequest
	if err := json.Unmarshal([]byte(`{"model":"m","messages":[],"tools":[]}`), &empty); err != nil {
		t.Fatal(err)
	}
	out, _ = json.Marshal(empty)
	_ = json.Unmarshal(out, &m)
	if _, present := m["tools"]; !present {
		t.Error("an explicitly empty tools array was dropped")
	}
}

func TestMessage_Text(t *testing.T) {
	cases := []struct {
		name, content, want string
	}{
		{"plain string", `"hello"`, "hello"},
		{"multi-part", `[{"type":"text","text":"a"},{"type":"text","text":"b"}]`, "a\nb"},
		{"image part skipped", `[{"type":"image_url"},{"type":"text","text":"caption"}]`, "caption"},
		{"unparseable yields empty", `12345`, ""},
		{"absent yields empty", ``, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := Message{Role: "user"}
			if c.content != "" {
				m.Content = json.RawMessage(c.content)
			}
			if got := m.Text(); got != c.want {
				t.Errorf("Text() = %q, want %q", got, c.want)
			}
		})
	}
}

func TestChatRequest_LastUserTextAndToolNames(t *testing.T) {
	var req ChatRequest
	body := `{"model":"m","messages":[
		{"role":"user","content":"first"},
		{"role":"assistant","content":"reply"},
		{"role":"user","content":"second"}],
		"tools":[{"type":"function","function":{"name":"a"}},
		         {"type":"function","function":{"name":"b"}}]}`
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		t.Fatal(err)
	}
	if got := req.LastUserText(); got != "second" {
		t.Errorf("LastUserText() = %q, want %q", got, "second")
	}
	if got := req.ToolNames(); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Errorf("ToolNames() = %v", got)
	}
}

// Criterion 12: the refusal must parse as a normal completion, or an SDK that
// expects one will treat a deliberate block as a gateway fault.
func TestStaticRefusal_ParsesAsAChatCompletion(t *testing.T) {
	body, err := json.Marshal(StaticRefusal("llama3", testUUID))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var parsed struct {
		ID      string `json:"id"`
		Object  string `json:"object"`
		Model   string `json:"model"`
		Choices []struct {
			Message struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("a client SDK could not parse the refusal: %v", err)
	}
	if parsed.Object != "chat.completion" {
		t.Errorf("object = %q", parsed.Object)
	}
	if len(parsed.Choices) != 1 {
		t.Fatalf("choices = %d, want 1", len(parsed.Choices))
	}
	if parsed.Choices[0].Message.Role != "assistant" {
		t.Errorf("role = %q", parsed.Choices[0].Message.Role)
	}
	if parsed.Choices[0].Message.Content != RefusalText {
		t.Errorf("content = %q", parsed.Choices[0].Message.Content)
	}
	if parsed.Choices[0].FinishReason != "stop" {
		t.Errorf("finish_reason = %q", parsed.Choices[0].FinishReason)
	}
}
